"""Summaries and report files for harness runs."""

from __future__ import annotations

import csv
import json
import statistics
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from agentwall.harness.runner import ABLATIONS, ScenarioResult, results_as_dicts


def _pct(n: int, d: int) -> float:
    return round(100.0 * n / d, 1) if d else 0.0


def _p(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    idx = min(len(values) - 1, max(0, round(q * (len(values) - 1))))
    return round(values[idx], 3)


def summarise(results: list[ScenarioResult]) -> dict[str, Any]:
    by_config: dict[str, list[ScenarioResult]] = defaultdict(list)
    for r in results:
        by_config[r.config].append(r)

    configs: dict[str, dict[str, Any]] = {}
    for name, rows in by_config.items():
        attacks = [r for r in rows if r.kind == "attack"]
        benign = [r for r in rows if r.kind == "benign"]
        benign_calls = sum(r.legit_calls for r in benign)
        benign_stopped = sum(r.legit_stopped for r in benign)
        overheads = [o for r in rows for o in r.overheads_ms]
        per_category: dict[str, dict[str, Any]] = {}
        for cat in sorted({r.category for r in rows}):
            cat_rows = [r for r in rows if r.category == cat]
            if cat_rows[0].kind == "attack":
                ok = sum(bool(r.attack_success) for r in cat_rows)
                per_category[cat] = {
                    "kind": "attack",
                    "n": len(cat_rows),
                    "asr": _pct(ok, len(cat_rows)),
                }
            else:
                done = sum(r.task_completed for r in cat_rows)
                per_category[cat] = {
                    "kind": "benign",
                    "n": len(cat_rows),
                    "utility": _pct(done, len(cat_rows)),
                }
        configs[name] = {
            "attacks": len(attacks),
            "asr": _pct(sum(bool(r.attack_success) for r in attacks), len(attacks)),
            "blocked": _pct(sum(r.goal_action == "block" for r in attacks), len(attacks)),
            "held": _pct(sum(r.goal_action == "ask" for r in attacks), len(attacks)),
            "never_reached": _pct(sum(r.goal_action is None for r in attacks), len(attacks)),
            "asr_test_split": _pct(
                sum(bool(r.attack_success) for r in attacks if r.split == "test"),
                sum(r.split == "test" for r in attacks),
            ),
            "benign": len(benign),
            "utility": _pct(sum(r.task_completed for r in benign), len(benign)),
            "utility_under_attack": _pct(sum(r.task_completed for r in attacks), len(attacks)),
            "fpr": _pct(benign_stopped, benign_calls),
            "overhead_p50_ms": _p(overheads, 0.5),
            "overhead_p95_ms": _p(overheads, 0.95),
            "overhead_mean_ms": round(statistics.fmean(overheads), 3) if overheads else 0.0,
            "per_category": per_category,
        }
    return configs


def render_markdown(suite: str, summary: dict[str, Any], commit: str) -> str:
    order = [a for a in ABLATIONS if a.name in summary]
    first = summary[order[0].name]
    lines = [
        f"# AgentWall benchmark ({suite} suite)",
        "",
        f"Commit `{commit}` · {first['attacks']} attack scenarios · {first['benign']} benign scenarios · "
        "worst-case obedient agent (it follows every injection it sees).",
        "",
        "| Configuration | ASR | ASR (held-out phrasings) | Blocked | Held for approval | Benign utility | Utility under attack | FPR | Overhead p50 / p95 (ms) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for a in order:
        s = summary[a.name]
        lines.append(
            f"| {a.label} | {s['asr']}% | {s['asr_test_split']}% | {s['blocked']}% | {s['held']}% | "
            f"{s['utility']}% | {s['utility_under_attack']}% | {s['fpr']}% | "
            f"{s['overhead_p50_ms']} / {s['overhead_p95_ms']} |"
        )
    lines += [
        "",
        "ASR: share of attacks whose goal call executed. Blocked / held: share of attacks stopped by a block or an ask "
        "(the rest never reached a tool, e.g. the poisoned tool was hidden). FPR: share of the user's own calls in benign "
        "scenarios that were blocked or held.",
        "",
        "## Attack success by category",
        "",
        "| Category | n | " + " | ".join(a.label for a in order) + " |",
        "| --- | --- | " + " | ".join("---" for _ in order) + " |",
    ]
    cats = first["per_category"]
    for cat, info in cats.items():
        if info["kind"] != "attack":
            continue
        cells = [f"{summary[a.name]['per_category'][cat]['asr']}%" for a in order]
        lines.append(f"| {cat} | {info['n']} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "## Benign task completion by category",
        "",
        "| Category | n | " + " | ".join(a.label for a in order) + " |",
        "| --- | --- | " + " | ".join("---" for _ in order) + " |",
    ]
    for cat, info in cats.items():
        if info["kind"] != "benign":
            continue
        cells = [f"{summary[a.name]['per_category'][cat]['utility']}%" for a in order]
        lines.append(f"| {cat} | {info['n']} | " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def write_outputs(
    out: Path, suite: str, results: list[ScenarioResult], summary: dict[str, Any], commit: str
) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "latest.md").write_text(render_markdown(suite, summary, commit), encoding="utf-8")
    (out / "latest.json").write_text(
        json.dumps(
            {
                "suite": suite,
                "commit": commit,
                "summary": summary,
                "results": results_as_dicts(results),
            },
            indent=1,
        ),
        encoding="utf-8",
    )
    history = out / "history.csv"
    new = not history.exists()
    with history.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if new:
            writer.writerow(
                ["time", "commit", "suite", "config", "asr", "utility", "fpr", "overhead_p95_ms"]
            )
        for name, s in summary.items():
            writer.writerow(
                [
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                    commit,
                    suite,
                    name,
                    s["asr"],
                    s["utility"],
                    s["fpr"],
                    s["overhead_p95_ms"],
                ]
            )
