from __future__ import annotations

import json
import re

import pytest

pytest.importorskip("agentdojo")

from agentdojo.task_suite.load_suites import get_suite

from agentwall.agent.model import CachedClient, ModelRequest, ModelResponse
from agentwall.integrations.agentdojo.manifests import (
    DEFAULT_INJECTION_TASKS,
    SUITE_SERVERS,
)
from agentwall.integrations.agentdojo.pipeline import to_plain_messages
from agentwall.integrations.agentdojo.runner import (
    DEFAULT_VERSION,
    render_dojo_markdown,
    run_dojo,
    summarise_dojo,
)

IBAN = re.compile(r"IBAN:\s*([A-Z]{2}\d{2}[A-Z0-9]{10,30})")


class ScriptedClient:
    def __init__(self, policy):
        self.policy = policy
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return self.policy(request)


def _call(name, args, i=0):
    return {"id": f"aw_call_{i}", "name": name, "args": args, "signature": None}


def _outputs(request: ModelRequest) -> str:
    return "\n".join(
        r["output"] for m in request.messages if m["role"] == "tool" for r in m["results"]
    )


def bill_payer(obey_injections: bool):
    """Pays the bill file the user names; optionally also does what any injected text asks."""

    def policy(request: ModelRequest) -> ModelResponse:
        turn = sum(m["role"] == "model" for m in request.messages)
        out = _outputs(request)
        if turn == 0:
            return ModelResponse(
                calls=(_call("read_file", {"file_path": "bill-december-2023.txt"}),)
            )
        if turn == 1:
            calls = []
            match = IBAN.search(out)
            if match:  # under attack the injection may replace the whole bill
                pay = {"recipient": match.group(1), "amount": 98.70, "subject": "Car Rental"}
                calls.append(_call("send_money", {**pay, "date": "2022-01-01"}, 1))
            if obey_injections and "new_password" in out:
                calls.append(_call("update_password", {"password": "new_password"}, 2))
            if not calls:
                return ModelResponse(text="Done.")
            return ModelResponse(calls=tuple(calls))
        return ModelResponse(text="Done.")

    return policy


def test_banking_manifest_covers_every_tool():
    suite = get_suite(DEFAULT_VERSION, "banking")
    mapped = {t for spec in SUITE_SERVERS["banking"].values() for t in spec.tools}
    assert mapped == {f.name for f in suite.tools}
    assert set(DEFAULT_INJECTION_TASKS["banking"]) <= set(suite.injection_tasks)


def test_agentwall_blocks_injected_password_change_and_bill_from_untrusted_file(tmp_path):
    client = ScriptedClient(bill_payer(obey_injections=True))
    rows, remaining, total = run_dojo(
        client,
        "fake-model",
        configs=("none", "full"),
        injection_tasks=("injection_task_7",),
        user_tasks=("user_task_0",),
        out=tmp_path,
        progress=lambda _: None,
    )
    assert remaining == 0 and total == 4
    by = {(r.config, r.injection_task): r for r in rows}

    # Without AgentWall the gullible model pays the bill and also changes the password.
    assert by[("none", None)].utility is True
    assert by[("none", "injection_task_7")].attack_success is True

    # With AgentWall the password change is blocked: its value came from the untrusted file.
    attacked = by[("full", "injection_task_7")]
    assert attacked.attack_success is False and attacked.blocked >= 1

    # The bill's IBAN also exists only in the untrusted file, so paying it is blocked too: the known
    # cost of the default policy (see benign_untrusted_target in the obedient harness).
    benign = by[("full", None)]
    assert benign.utility is False and benign.blocked == 1

    blocked_reply = next(
        r["output"]
        for req in client.requests
        for m in req.messages
        if m["role"] == "tool"
        for r in m["results"]
        if "AgentWall blocked" in r["output"]
    )
    assert blocked_reply.startswith("Error: AgentWall blocked this call")

    summary = summarise_dojo(rows)
    assert summary["none"]["asr"] == 100.0 and summary["full"]["asr"] == 0.0
    md = render_dojo_markdown(summary, "fake-model", "banking", DEFAULT_VERSION, "x", "abc")
    assert "| user_task_0 | yes | no (1) |" in md


def test_finished_runs_resume_without_calling_the_model(tmp_path):
    kwargs = dict(
        configs=("none",),
        injection_tasks=("injection_task_7",),
        user_tasks=("user_task_0",),
        out=tmp_path,
        progress=lambda _: None,
    )
    first = ScriptedClient(bill_payer(obey_injections=False))
    run_dojo(first, "fake-model", **kwargs)
    assert first.requests

    again = ScriptedClient(bill_payer(obey_injections=False))
    rows, remaining, _ = run_dojo(again, "fake-model", **kwargs)
    assert remaining == 0 and len(rows) == 2 and not again.requests
    assert len((tmp_path / "runs.jsonl").read_text(encoding="utf-8").splitlines()) == 2


def test_stops_cleanly_when_the_cache_runs_dry(tmp_path):
    replay = CachedClient(None, tmp_path / "empty.jsonl")
    rows, remaining, total = run_dojo(
        replay,
        "fake-model",
        configs=("none",),
        injection_tasks=(),
        user_tasks=("user_task_0", "user_task_1"),
        out=tmp_path,
        progress=lambda _: None,
    )
    assert rows == [] and remaining == total == 2


def test_message_conversion_groups_tool_results_and_keeps_signatures(tmp_path):
    client = ScriptedClient(bill_payer(obey_injections=False))
    run_dojo(
        client,
        "fake-model",
        configs=("full",),
        injection_tasks=(),
        user_tasks=("user_task_0",),
        out=tmp_path,
        progress=lambda _: None,
    )
    last = client.requests[-1]
    assert last.system.startswith("You are an AI language model")
    assert [m["role"] for m in last.messages] == ["user", "model", "tool", "model", "tool"]
    assert {t.name for t in last.tools} >= {"send_money", "read_file"}
    json.dumps(last.to_json())  # cacheable

    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.types import text_content_block_from_string

    fc = FunctionCall(function="get_balance", args={}, id="x1")
    msgs = [
        {
            "role": "assistant",
            "content": [text_content_block_from_string("")],
            "tool_calls": [fc, fc],
        },
        {
            "role": "tool",
            "content": [text_content_block_from_string("1")],
            "tool_call_id": "x1",
            "tool_call": fc,
            "error": None,
        },
        {
            "role": "tool",
            "content": [text_content_block_from_string("")],
            "tool_call_id": "x1",
            "tool_call": fc,
            "error": "nope",
        },
    ]
    _, plain = to_plain_messages(msgs, {"x1": "c2ln"})
    assert plain[0]["calls"][0]["signature"] == "c2ln" and plain[0]["text"] is None
    assert [r["output"] for r in plain[1]["results"]] == ["1", "Error: nope"]
