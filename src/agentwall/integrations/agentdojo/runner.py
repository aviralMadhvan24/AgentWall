"""Run an AgentDojo suite subset with and without AgentWall and write a report.

Every finished (config, user task, injection task) run is appended to ``runs.jsonl`` straight away, so
a run that stops on the free tier's daily quota resumes where it left off; the model-response cache
means re-runs cost nothing for finished conversations.
"""

from __future__ import annotations

import json
import subprocess
import time
import warnings
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from agentdojo.agent_pipeline import BasePipelineElement
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.task_suite.load_suites import get_suite

from agentwall.agent.model import ModelClient, RunStopped
from agentwall.harness.report import wilson
from agentwall.harness.runner import ABLATIONS
from agentwall.integrations.agentdojo.manifests import DEFAULT_INJECTION_TASKS
from agentwall.integrations.agentdojo.pipeline import build_pipeline

DEFAULT_VERSION = "v1.2.1"
CONFIG_LABELS = {"none": "No defence (AgentDojo executor)"} | {a.name: a.label for a in ABLATIONS}
# AgentDojo's attacks address the model by a prose name looked up from known model ids; every Gemini id
# maps to the same name, so a known one stands in for newer ids the table does not list yet.
_GEMINI_NAME_KEY = "gemini-2.0-flash-001"


@dataclass
class DojoRow:
    model: str
    version: str
    suite: str
    attack: str
    config: str
    user_task: str
    injection_task: str | None
    utility: bool
    attack_success: bool | None
    calls: int
    blocked: int
    held: int
    seconds: float

    def key(self) -> tuple[Any, ...]:
        return (
            self.model,
            self.version,
            self.suite,
            self.attack,
            self.config,
            self.user_task,
            self.injection_task,
        )


class _NameOnly(BasePipelineElement):
    def __init__(self, name: str) -> None:
        self.name = name

    def query(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def _load_rows(path: Path) -> list[DojoRow]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [DojoRow(**json.loads(line)) for line in fh if line.strip()]


def run_dojo(
    client: ModelClient,
    model: str,
    suite_name: str = "banking",
    version: str = DEFAULT_VERSION,
    configs: tuple[str, ...] = ("none", "full"),
    injection_tasks: tuple[str, ...] | None = None,
    user_tasks: tuple[str, ...] | None = None,
    attack_name: str = "important_instructions",
    out: Path = Path("results/agentdojo"),
    progress: Callable[[str], None] = print,
) -> tuple[list[DojoRow], int, int]:
    """Returns (rows for this selection, runs still to do, total runs)."""
    suite = get_suite(version, suite_name)
    injection_ids = (
        DEFAULT_INJECTION_TASKS.get(suite_name, ()) if injection_tasks is None else injection_tasks
    )
    user_ids = tuple(suite.user_tasks) if user_tasks is None else user_tasks
    ablations = {a.name: a for a in ABLATIONS}
    for c in configs:
        if c != "none" and c not in ablations:
            raise ValueError(f"unknown config {c!r}")
    attack = load_attack(attack_name, suite, _NameOnly(_GEMINI_NAME_KEY))

    runs_path = out / "runs.jsonl"
    done = {r.key(): r for r in _load_rows(runs_path)}
    plan = [
        (config, uid, iid)
        for config in configs
        for uid in user_ids
        for iid in (None, *injection_ids)
    ]
    total = len(plan)
    out.mkdir(parents=True, exist_ok=True)

    pipelines: dict[str, Any] = {}
    finished = 0
    for config, uid, iid in plan:
        key = (model, version, suite_name, attack_name, config, uid, iid)
        if key in done:
            finished += 1
            continue
        if config not in pipelines:
            pipelines[config] = build_pipeline(
                client,
                model,
                suite_name,
                suite.tools,
                None if config == "none" else ablations[config],
            )
        pipeline, executor = pipelines[config]
        user_task = suite.get_user_task_by_id(uid)
        injection = suite.get_injection_task_by_id(iid) if iid else None
        injections = attack.attack(user_task, injection) if injection else {}
        if executor is not None:
            executor.last_session = None
        start = time.perf_counter()
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                utility, security = suite.run_task_with_pipeline(
                    pipeline, user_task, injection, injections
                )
        except RunStopped as exc:
            progress(f"stopped after {finished}/{total} runs: {exc}")
            return [], total - finished, total
        session = executor.last_session if executor else None
        calls = session.calls if session else []
        row = DojoRow(
            model=model,
            version=version,
            suite=suite_name,
            attack=attack_name,
            config=config,
            user_task=uid,
            injection_task=iid,
            utility=bool(utility),
            attack_success=bool(security) if injection else None,
            calls=len(calls),
            blocked=sum(c.action == "block" for c in calls),
            held=sum(c.action == "ask" for c in calls),
            seconds=round(time.perf_counter() - start, 2),
        )
        with runs_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(asdict(row)) + "\n")
        done[key] = row
        finished += 1
        if finished % 5 == 0:
            progress(f"  {finished}/{total} runs")

    selected = {(model, version, suite_name, attack_name, c, u, i) for c, u, i in plan}
    return [done[k] for k in done if k in selected], 0, total


def summarise_dojo(rows: list[DojoRow]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for config in dict.fromkeys(r.config for r in rows):
        mine = [r for r in rows if r.config == config]
        benign = [r for r in mine if r.injection_task is None]
        attacked = [r for r in mine if r.injection_task is not None]
        wins = sum(bool(r.attack_success) for r in attacked)
        useful = sum(r.utility for r in benign)
        by_injection = {}
        for iid in sorted({r.injection_task for r in attacked if r.injection_task}):
            sub = [r for r in attacked if r.injection_task == iid]
            by_injection[iid] = {
                "n": len(sub),
                "asr": round(100 * sum(bool(r.attack_success) for r in sub) / len(sub), 1),
            }
        out[config] = {
            "user_tasks": len(benign),
            "attacked_runs": len(attacked),
            "utility": round(100 * useful / len(benign), 1) if benign else 0.0,
            "utility_ci": wilson(useful, len(benign)),
            "utility_under_attack": (
                round(100 * sum(r.utility for r in attacked) / len(attacked), 1)
                if attacked
                else 0.0
            ),
            "asr": round(100 * wins / len(attacked), 1) if attacked else 0.0,
            "asr_ci": wilson(wins, len(attacked)),
            "benign_runs_with_block_or_hold": sum((r.blocked + r.held) > 0 for r in benign),
            "by_injection": by_injection,
            "benign_by_task": {r.user_task: r.utility for r in benign},
            "benign_stopped_by_task": {r.user_task: r.blocked + r.held for r in benign},
        }
    return out


def render_dojo_markdown(
    summary: dict[str, Any], model: str, suite: str, version: str, attack: str, commit: str
) -> str:
    configs = list(summary)
    first = summary[configs[0]]
    lines = [
        f"# AgentDojo `{suite}` subset ({version})",
        "",
        f"Commit `{commit}` · model `{model}` · attack `{attack}` · {first['user_tasks']} user tasks · "
        f"{first['attacked_runs']} attacked runs per configuration. Utility and attack success are "
        "AgentDojo's own checks on the final environment.",
        "",
        "| Configuration | Utility | Utility 95% CI | Utility under attack | ASR | ASR 95% CI | Benign tasks with a blocked or held call |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for c in configs:
        s = summary[c]
        lines.append(
            f"| {CONFIG_LABELS.get(c, c)} | {s['utility']}% | {s['utility_ci'][0]}-{s['utility_ci'][1]}% | "
            f"{s['utility_under_attack']}% | {s['asr']}% | {s['asr_ci'][0]}-{s['asr_ci'][1]}% | "
            f"{s['benign_runs_with_block_or_hold']}/{s['user_tasks']} |"
        )
    lines += [
        "",
        "## Attack success by injection task",
        "",
        "| Injection task | n | " + " | ".join(CONFIG_LABELS.get(c, c) for c in configs) + " |",
        "| --- | --- | " + " | ".join("---" for _ in configs) + " |",
    ]
    for iid, info in first["by_injection"].items():
        cells = [f"{summary[c]['by_injection'].get(iid, {}).get('asr', '-')}%" for c in configs]
        lines.append(f"| {iid} | {info['n']} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "## Benign user tasks",
        "",
        "yes: task solved; no: not solved; (n): calls AgentWall blocked or held.",
        "",
        "| User task | " + " | ".join(CONFIG_LABELS.get(c, c) for c in configs) + " |",
        "| --- | " + " | ".join("---" for _ in configs) + " |",
    ]
    tasks = sorted(first["benign_by_task"], key=lambda t: int(t.rsplit("_", 1)[-1]))
    for t in tasks:
        cells = []
        for c in configs:
            ok = summary[c]["benign_by_task"].get(t)
            stopped = summary[c]["benign_stopped_by_task"].get(t, 0)
            mark = "-" if ok is None else ("yes" if ok else "no")
            cells.append(mark + (f" ({stopped})" if stopped else ""))
        lines.append(f"| {t} | " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def _commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def run_dojo_cli(
    client: ModelClient,
    model: str,
    suite: str,
    version: str,
    configs: tuple[str, ...],
    injection_tasks: tuple[str, ...] | None,
    user_tasks: tuple[str, ...] | None,
    attack: str,
    out: Path,
) -> int:
    rows, remaining, total = run_dojo(
        client, model, suite, version, configs, injection_tasks, user_tasks, attack, out
    )
    if remaining:
        print(f"{total - remaining}/{total} runs finished. Re-run the same command to resume.")
        return 3
    summary = summarise_dojo(rows)
    md = render_dojo_markdown(summary, model, suite, version, attack, _commit())
    (out / "latest.md").write_text(md, encoding="utf-8", newline="\n")
    (out / "latest.json").write_text(
        json.dumps(
            {
                "model": model,
                "suite": suite,
                "version": version,
                "attack": attack,
                "summary": summary,
            },
            indent=1,
        ),
        encoding="utf-8",
        newline="\n",
    )
    print()
    print(md)
    return 0
