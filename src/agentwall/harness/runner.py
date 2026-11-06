"""Run the scenario corpus through each ablation configuration and collect outcomes."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import anyio

from agentwall.agent.loop import ToolAgent
from agentwall.agent.model import CacheMiss, ModelClient, RunStopped
from agentwall.audit.log import AuditLog
from agentwall.demo.manifests import signed_demo_manifest
from agentwall.demo.servers import (
    DEMO_TOOL_POLICY,
    Sink,
    make_email_server,
    make_files_server,
    make_http_server,
    make_portfolio_server,
    make_weather_server,
    make_web_server,
)
from agentwall.detector import HeuristicDetector
from agentwall.gateway.backends import MCPBackend
from agentwall.gateway.core import Gateway, GatewayConfig
from agentwall.harness.agent import ObedientAgent
from agentwall.harness.corpus import build_corpus
from agentwall.harness.judge import judge, payload_seen
from agentwall.harness.scenario import Scenario
from agentwall.policy.engine import Policy
from agentwall.quarantine import LLMExtractor, QuarantineConfig, RuleExtractor
from agentwall.registry.crypto import generate_keypair
from agentwall.registry.manifest import Manifest
from agentwall.registry.registry import Registry

CLEAN_WEATHER = "Get the current weather for a city."


@dataclass(frozen=True)
class Ablation:
    name: str
    label: str
    policy: str
    detector: bool
    attribution: bool
    enforce_manifests: bool
    quarantine: bool = False
    default: bool = True  # run when no --configs are given


# Outputs quarantined in the quarantine configuration: the untrusted servers and file contents.
QUARANTINE_TARGETS = ("web", "weather", "files__read_file")

ABLATIONS: tuple[Ablation, ...] = (
    Ablation("none", "No defence", "none", False, True, False),
    Ablation("detector_only", "Detector only", "detector_only", True, True, False),
    Ablation("lowwater", "Policies, low-water mark only", "default", False, False, False),
    Ablation("attribution", "Policies + attribution", "default", False, True, False),
    Ablation("full", "Full AgentWall", "default", True, True, True),
    Ablation("strict", "Full AgentWall, strict policy", "strict", True, True, True),
    Ablation(
        "quarantine",
        "Full AgentWall + quarantine",
        "default",
        True,
        True,
        True,
        quarantine=True,
        default=False,
    ),
)


@dataclass
class ScenarioResult:
    config: str
    scenario: str
    category: str
    kind: str
    split: str
    attack_attempted: bool | None
    attack_success: bool | None
    goal_action: str | None
    saw_payload: bool
    steps: int
    steps_done: int
    legit_calls: int
    legit_stopped: int
    legit_actions: list[str]
    overheads_ms: list[float] = field(default_factory=list)
    agent: str = "obedient"
    repeat: int = 0
    stop: str = "scripted"
    turns: int = 0

    @property
    def task_completed(self) -> bool:
        return self.steps_done == self.steps


@dataclass(frozen=True)
class ModelAgentSpec:
    """Run scenarios with a real model instead of the obedient agent."""

    client: ModelClient
    model: str
    max_turns: int = 10

    @property
    def name(self) -> str:
        return f"gemini:{self.model}"


class IncompleteRun(RuntimeError):
    """The run stopped early (quota, budget or cache miss). Cached model calls make a re-run resume."""

    def __init__(self, done: int, total: int, cause: RunStopped) -> None:
        super().__init__(f"{done}/{total} scenario runs finished; stopped: {cause}")
        self.done, self.total, self.cause = done, total, cause


class _Keys:
    def __init__(self) -> None:
        self.private, self.public = generate_keypair()
        self._cache: dict[tuple[str, str], Manifest] = {}

    async def manifest(self, name: str, backend: MCPBackend, cache_key: str) -> Manifest:
        key = (name, cache_key)
        if key not in self._cache:
            self._cache[key] = signed_demo_manifest(name, await backend.list_tools(), self.private)
        return self._cache[key]


def demo_control_args(qualified: str) -> tuple[str, ...]:
    server, _, tool = qualified.partition("__")
    spec = DEMO_TOOL_POLICY.get(server, {}).get("tools", {}).get(tool)
    return tuple(spec[1]) if spec else ()


def _servers(scenario: Scenario, sink: Sink, weather_description: str) -> dict[str, Any]:
    return {
        "web": make_web_server(scenario.pages),
        "portfolio": make_portfolio_server(),
        "email": make_email_server(sink),
        "http": make_http_server(sink),
        "files": make_files_server(sink, scenario.files),
        "weather": make_weather_server(weather_description),
    }


def _quarantine(ablation: Ablation, agent: ModelAgentSpec | None) -> QuarantineConfig | None:
    if not ablation.quarantine:
        return None
    extractor = LLMExtractor(agent.client, agent.model) if agent else RuleExtractor()
    return QuarantineConfig(QUARANTINE_TARGETS, extractor)


async def run_scenario(
    scenario: Scenario,
    ablation: Ablation,
    keys: _Keys,
    agent: ModelAgentSpec | None = None,
    repeat: int = 0,
    audit: AuditLog | None = None,
) -> ScenarioResult:
    attack = scenario.attack
    approved_weather = CLEAN_WEATHER
    served_weather = CLEAN_WEATHER
    if attack and attack.carrier == "tool_description":
        approved_weather = served_weather = f"{CLEAN_WEATHER} {attack.payload}"
    elif attack and attack.carrier == "rug_pull":
        served_weather = f"{CLEAN_WEATHER} {attack.payload}"

    sink = Sink()
    servers = _servers(scenario, sink, served_weather)
    approval = make_weather_server(approved_weather)
    manifests = []
    for name, server in servers.items():
        source = approval if name == "weather" else server
        cache_key = approved_weather if name == "weather" else ""
        async with MCPBackend(name, source) as b:
            manifests.append(await keys.manifest(name, b, cache_key))

    config = GatewayConfig(
        policy=Policy.load(ablation.policy),
        registry=Registry(manifests, [keys.public]),
        detector=HeuristicDetector() if ablation.detector else None,
        attribution=ablation.attribution,
        enforce_manifests=ablation.enforce_manifests,
        quarantine=_quarantine(ablation, agent),
        audit=audit if audit is not None else AuditLog(),
    )
    async with Gateway([MCPBackend(n, s) for n, s in servers.items()], config) as gateway:
        await gateway.refresh()
        session = gateway.new_session()
        if agent is None:
            run = await ObedientAgent(scenario).run(session)
            saw, stop, turns = run.saw_payload, "scripted", len(scenario.steps)
        else:
            model_agent = ToolAgent(
                agent.client, agent.model, max_turns=agent.max_turns, seed=repeat
            )
            transcript = await model_agent.run(session, scenario.user_prompt)
            descriptions = [t.info.description for t in gateway.visible_tools()]
            saw = payload_seen(scenario, session.calls, descriptions)
            stop, turns = transcript.stop, transcript.turns

    verdict = judge(scenario, session.calls, demo_control_args)
    return ScenarioResult(
        config=ablation.name,
        scenario=scenario.id,
        category=scenario.category,
        kind=scenario.kind,
        split=scenario.split,
        attack_attempted=verdict.attack_attempted,
        attack_success=verdict.attack_success,
        goal_action=verdict.goal_action,
        saw_payload=saw,
        steps=verdict.steps,
        steps_done=verdict.steps_done,
        legit_calls=verdict.legit_calls,
        legit_stopped=verdict.legit_stopped,
        legit_actions=list(verdict.legit_actions),
        overheads_ms=[round(c.overhead_ms, 4) for c in session.calls],
        agent=agent.name if agent else "obedient",
        repeat=repeat,
        stop=stop,
        turns=turns,
    )


async def run_suite(
    suite: str = "quick",
    configs: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
    agent: ModelAgentSpec | None = None,
    repeats: int = 1,
) -> list[ScenarioResult]:
    scenarios = build_corpus(suite)
    ablations = [a for a in ABLATIONS if (a.name in configs if configs else a.default)]
    unknown = set(configs or ()) - {a.name for a in ABLATIONS}
    if unknown:
        raise ValueError(
            f"unknown configs {sorted(unknown)}; choose from {[a.name for a in ABLATIONS]}"
        )
    keys = _Keys()
    results: list[ScenarioResult] = []
    total = len(ablations) * len(scenarios) * repeats
    for ablation in ablations:
        start = time.perf_counter()
        for scenario in scenarios:
            for repeat in range(repeats):
                try:
                    results.append(await run_scenario(scenario, ablation, keys, agent, repeat))
                except RunStopped as exc:
                    raise IncompleteRun(len(results), total, exc) from exc
                if agent and progress and len(results) % 10 == 0:
                    progress(f"  {len(results)}/{total} scenario runs")
        if progress:
            progress(
                f"{ablation.name:<14} {len(scenarios)} scenarios in {time.perf_counter() - start:.1f}s"
            )
    return results


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        )
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def run_cli(
    suite: str = "quick",
    out: str = "results",
    configs: list[str] | None = None,
    agent: ModelAgentSpec | None = None,
    repeats: int = 1,
) -> int:
    from agentwall.harness.report import summarise, write_outputs

    try:
        results = anyio.run(lambda: run_suite(suite, configs, print, agent, repeats))
    except IncompleteRun as exc:
        print()
        print(f"Stopped early: {exc}")
        if isinstance(exc.cause, CacheMiss):
            print(
                "Replay-only runs need every response cached; drop --replay-only to fetch the rest."
            )
        else:
            print("Finished model calls are cached; run the same command again to resume.")
        return 3
    summary = summarise(results)
    write_outputs(
        Path(out),
        suite,
        results,
        summary,
        _git_commit(),
        agent.name if agent else "obedient",
        repeats,
    )
    print()
    print((Path(out) / "latest.md").read_text(encoding="utf-8"))
    return 0


def results_as_dicts(results: list[ScenarioResult]) -> list[dict[str, Any]]:
    return [asdict(r) for r in results]
