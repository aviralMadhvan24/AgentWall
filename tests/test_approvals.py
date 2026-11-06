from __future__ import annotations

import anyio

from agentwall.approvals import ApprovalStore, StoreApprover
from agentwall.cli import main
from agentwall.policy.engine import Policy
from test_gateway import _gateway

NEWS = {"https://news.example/markets": "Markets rallied today."}


async def _held_session(store: ApprovalStore, wait: float = 0.0):
    # Strict policy: once untrusted content is in context, every side effect is an "ask".
    gateway, sink = await _gateway(
        pages=NEWS, policy=Policy.load("strict"), approver=StoreApprover(store, wait, 0.01)
    )
    session = gateway.new_session()
    session.add_user_message("Read the news and email a summary to aviral@home.in and ca@tax.in")
    await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
    return gateway, session, sink


def _email(to: str, body: str = "Markets rallied.") -> dict:
    return {"to": to, "subject": "News", "body": body}


async def test_held_call_names_the_request_and_a_one_time_approval_lets_one_retry_through():
    store = ApprovalStore()
    _, session, sink = await _held_session(store)

    held = await session.call_tool("email__send_email", _email("aviral@home.in"))
    assert held.action == "ask" and not held.executed
    (req,) = store.pending()
    assert req.control == {"to": "aviral@home.in"}
    assert f"agentwall approvals approve {req.id}" in held.message_for_agent()

    store.decide(req.id, approve=True)
    retry = await session.call_tool("email__send_email", _email("aviral@home.in", "edited body"))
    assert retry.executed and sink.outbox[-1]["body"] == "edited body"

    again = await session.call_tool("email__send_email", _email("aviral@home.in"))
    assert not again.executed  # one-time approval was used up


async def test_remembered_decisions_answer_future_calls_but_only_for_the_same_target():
    store = ApprovalStore()
    _, session, sink = await _held_session(store)

    await session.call_tool("email__send_email", _email("aviral@home.in"))
    store.decide(store.pending()[0].id, approve=True, remember=True)
    for _ in range(2):
        ok = await session.call_tool("email__send_email", _email("aviral@home.in"))
        assert ok.executed and "earlier" in ok.approval_note

    other = await session.call_tool("email__send_email", _email("ca@tax.in"))
    assert not other.executed  # a different recipient is a different request
    store.decide(store.pending()[0].id, approve=False, remember=True)
    denied = await session.call_tool("email__send_email", _email("ca@tax.in"))
    assert not denied.executed and "denied" in denied.approval_note
    assert len(sink.outbox) == 2


async def test_repeat_calls_bump_one_pending_request():
    store = ApprovalStore()
    _, session, _ = await _held_session(store)
    for _ in range(3):
        await session.call_tool("email__send_email", _email("aviral@home.in"))
    (req,) = store.pending()
    assert req.calls_seen == 3


async def test_approver_can_wait_for_an_operator():
    store = ApprovalStore()
    _, session, sink = await _held_session(store, wait=5.0)
    result = {}

    async def agent():
        result["out"] = await session.call_tool("email__send_email", _email("aviral@home.in"))

    async def operator():
        while not store.pending():
            await anyio.sleep(0.01)
        store.decide(store.pending()[0].id, approve=True)

    async with anyio.create_task_group() as tg:
        tg.start_soon(agent)
        tg.start_soon(operator)
    assert result["out"].executed and len(sink.outbox) == 1
    # The one-time approval was consumed by the call that waited for it.
    assert not (await session.call_tool("email__send_email", _email("aviral@home.in"))).executed


async def test_waiting_times_out_closed():
    store = ApprovalStore()
    _, session, sink = await _held_session(store, wait=0.05)
    out = await session.call_tool("email__send_email", _email("aviral@home.in"))
    assert not out.executed and sink.outbox == []


def test_file_store_is_shared_and_cli_answers_requests(tmp_path, capsys):
    path = tmp_path / "approvals.json"

    async def hold():
        _, session, _ = await _held_session(ApprovalStore(path))
        await session.call_tool("email__send_email", _email("aviral@home.in"))

    anyio.run(hold)
    req = ApprovalStore(path).pending()[0]

    assert main(["approvals", "list", "--store", str(path)]) == 0
    assert req.id in capsys.readouterr().out
    assert main(["approvals", "approve", req.id, "--remember", "--store", str(path)]) == 0
    assert "approved (always)" in capsys.readouterr().out
    assert ApprovalStore(path).get(req.id).remember
    assert main(["approvals", "deny", "nope", "--store", str(path)]) == 1
    assert main(["approvals", "list", "--all", "--store", str(path)]) == 0
    assert "(remembered)" in capsys.readouterr().out
