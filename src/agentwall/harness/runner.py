"""Run the scenario corpus through each ablation configuration and collect outcomes."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import anyio

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
from agentwall.harness.judge import judge
from agentwall.harness.scenario import Scenario
from agentwall.policy.engine import Policy
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


ABLATIONS: tuple[Ablation, ...] = (
    Ablation("none", "No defence", "none", False, True, False),
    Ablation("detector_only", "Detector only", "detector_only", True, True, False),
    Ablation("lowwater", "Policies, low-water mark only", "default", False, False, False),
    Ablation("attribution", "Policies + attribution", "default", False, True, False),
    Ablation("full", "Full AgentWall", "default", True, True, True),
    Ablation("strict", "Full AgentWall, strict policy", "strict", True, True, True),
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

    @property
    def task_completed(self) -> bool:
        return self.steps_done == self.steps


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


async def run_scenario(scenario: Scenario, ablation: Ablation, keys: _Keys) -> ScenarioResult:
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
    )
    async with Gateway([MCPBackend(n, s) for n, s in servers.items()], config) as gateway:
        await gateway.refresh()
        session = gateway.new_session()
        run = await ObedientAgent(scenario).run(session)

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
        saw_payload=run.saw_payload,
        steps=verdict.steps,
        steps_done=verdict.steps_done,
        legit_calls=verdict.legit_calls,
        legit_stopped=verdict.legit_stopped,
        legit_actions=list(verdict.legit_actions),
        overheads_ms=[round(c.overhead_ms, 4) for c in session.calls],
    )


async def run_suite(
    suite: str = "quick",
    configs: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[ScenarioResult]:
    scenarios = build_corpus(suite)
    ablations = [a for a in ABLATIONS if not configs or a.name in configs]
    keys = _Keys()
    results: list[ScenarioResult] = []
    for ablation in ablations:
        start = time.perf_counter()
        for scenario in scenarios:
            results.append(await run_scenario(scenario, ablation, keys))
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


def run_cli(suite: str = "quick", out: str = "results", configs: list[str] | None = None) -> int:
    from agentwall.harness.report import summarise, write_outputs

    results = anyio.run(lambda: run_suite(suite, configs, progress=print))
    summary = summarise(results)
    write_outputs(Path(out), suite, results, summary, _git_commit())
    print()
    print((Path(out) / "latest.md").read_text(encoding="utf-8"))
    return 0


def results_as_dicts(results: list[ScenarioResult]) -> list[dict[str, Any]]:
    return [asdict(r) for r in results]
