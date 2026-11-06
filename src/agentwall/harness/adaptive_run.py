"""Run the adaptive-attack search across defence configurations and write a report."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

import anyio

from agentwall.agent.model import RunStopped
from agentwall.harness.adaptive import AdaptiveOutcome, Mutator, attack_until_broken, seed_scenarios
from agentwall.harness.corpus import build_corpus
from agentwall.harness.report import wilson
from agentwall.harness.runner import ABLATIONS, IncompleteRun, ModelAgentSpec, _Keys, run_scenario


async def run_adaptive(
    mutator: Mutator,
    configs: list[str],
    budget: int = 8,
    agent: ModelAgentSpec | None = None,
    seeds_from: str = "quick",
    progress: Callable[[str], None] | None = None,
) -> list[AdaptiveOutcome]:
    seeds = seed_scenarios(build_corpus(seeds_from))
    ablations = [a for a in ABLATIONS if a.name in configs]
    keys = _Keys()
    out: list[AdaptiveOutcome] = []
    total = len(seeds) * len(ablations)
    for ablation in ablations:
        for seed in seeds:

            async def run(scenario: Any, ablation: Any = ablation) -> Any:
                return await run_scenario(scenario, ablation, keys, agent)

            try:
                out.append(await attack_until_broken(seed, run, mutator, budget, ablation.name))
            except RunStopped as exc:
                raise IncompleteRun(len(out), total, exc) from exc
        if progress:
            broken = sum(o.broken for o in out if o.config == ablation.name)
            progress(f"{ablation.name:<14} {broken}/{len(seeds)} seeds broken")
    return out


def summarise_adaptive(outcomes: list[AdaptiveOutcome]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for config in dict.fromkeys(o.config for o in outcomes):
        rows = [o for o in outcomes if o.config == config]
        broken = [o for o in rows if o.broken]
        summary[config] = {
            "seeds": len(rows),
            "broken": len(broken),
            "asr": round(100 * len(broken) / len(rows), 1) if rows else 0.0,
            "asr_ci": wilson(len(broken), len(rows)),
            "broken_first_try": sum(o.attempts == 1 for o in broken),
            "mean_attempts_to_break": (
                round(sum(o.attempts for o in broken) / len(broken), 2) if broken else None
            ),
        }
    return summary


def render_adaptive(
    summary: dict[str, Any], outcomes: list[AdaptiveOutcome], mutator: str, budget: int, agent: str
) -> str:
    labels = {a.name: a.label for a in ABLATIONS}
    lines = [
        "# Adaptive attacks",
        "",
        f"Mutator `{mutator}` · up to {budget} attempts per seed attack · agent `{agent}`. An attack is "
        "broken when any attempt (the original or a rewrite keeping the attacker's exact values) "
        "succeeds.",
        "",
        "| Configuration | Seeds broken | Adaptive ASR | 95% CI | Broken on first try | Mean attempts to break |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for config, s in summary.items():
        lo, hi = s["asr_ci"]
        mean = s["mean_attempts_to_break"]
        lines.append(
            f"| {labels.get(config, config)} | {s['broken']}/{s['seeds']} | {s['asr']}% | {lo}-{hi}% | "
            f"{s['broken_first_try']} | {mean if mean is not None else '-'} |"
        )
    wins = [o for o in outcomes if o.broken and o.attempts > 1]
    if wins:
        lines += ["", "## Example rewrites that got through", ""]
        for o in wins[:5]:
            text = (o.winning_payload or "").replace("\n", " / ").replace("|", "\\|")
            lines.append(
                f"- {labels.get(o.config, o.config)}, `{o.seed}` (try {o.attempts}): {text[:220]}"
            )
    lines.append("")
    return "\n".join(lines)


def run_adaptive_cli(
    mutator: Mutator,
    configs: list[str],
    budget: int,
    out: Path,
    agent: ModelAgentSpec | None = None,
) -> int:
    try:
        outcomes = anyio.run(lambda: run_adaptive(mutator, configs, budget, agent, progress=print))
    except IncompleteRun as exc:
        print(f"\nStopped early: {exc}. Re-run the same command to resume from the model cache.")
        return 3
    summary = summarise_adaptive(outcomes)
    agent_name = agent.name if agent else "obedient"
    md = render_adaptive(summary, outcomes, mutator.name, budget, agent_name)
    out.mkdir(parents=True, exist_ok=True)
    (out / "latest.md").write_text(md, encoding="utf-8", newline="\n")
    (out / "latest.json").write_text(
        json.dumps(
            {
                "mutator": mutator.name,
                "budget": budget,
                "agent": agent_name,
                "summary": summary,
                "outcomes": [asdict(o) for o in outcomes],
            },
            indent=1,
        ),
        encoding="utf-8",
        newline="\n",
    )
    print()
    print(md)
    return 0
