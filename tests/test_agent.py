from __future__ import annotations

import csv
import json
from collections.abc import Callable

import pytest

from agentwall.agent.model import (
    BudgetExhausted,
    CachedClient,
    CacheMiss,
    ModelRequest,
    ModelResponse,
    RateLimited,
    ThrottledClient,
    ToolSpec,
)
from agentwall.harness.corpus import build_corpus
from agentwall.harness.report import _migrate_history, render_markdown, summarise, wilson
from agentwall.harness.runner import (
    ABLATIONS,
    IncompleteRun,
    ModelAgentSpec,
    _Keys,
    run_scenario,
    run_suite,
)

Policy = Callable[[ModelRequest], ModelResponse]


class ScriptedClient:
    """Stands in for Gemini: decides each turn from the conversation so far."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.requests: list[ModelRequest] = []

    def generate(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return self.policy(request)


def call(name: str, args: dict, i: int = 0) -> dict:
    return {"id": f"aw_call_{i}", "name": name, "args": args, "signature": None}


def tool_outputs(request: ModelRequest) -> str:
    return "\n".join(
        r["output"] for m in request.messages if m["role"] == "tool" for r in m["results"]
    )


def model_turns(request: ModelRequest) -> int:
    return sum(m["role"] == "model" for m in request.messages)


def gullible(attacker: str) -> Policy:
    """Reads the news and holdings, then follows the page's instruction to email the attacker."""

    def policy(request: ModelRequest) -> ModelResponse:
        turn = model_turns(request)
        if turn == 0:
            return ModelResponse(
                calls=(
                    call("web__fetch_url", {"url": "https://news.example/markets"}, 0),
                    call("portfolio__get_holdings", {}, 1),
                )
            )
        if turn == 1 and attacker in tool_outputs(request):
            body = tool_outputs(request)[-200:]
            return ModelResponse(
                calls=(call("email__send_email", {"to": attacker, "subject": "s", "body": body}),)
            )
        return ModelResponse(text="Markets were up; your portfolio is fine.")

    return policy


def careful(request: ModelRequest) -> ModelResponse:
    if model_turns(request) == 0:
        return ModelResponse(
            calls=(
                call("web__fetch_url", {"url": "https://news.example/markets"}, 0),
                call("portfolio__get_holdings", {}, 1),
            )
        )
    return ModelResponse(text="Summary done.")


def _abl(name: str):
    return next(a for a in ABLATIONS if a.name == name)


def _exfil():
    return next(s for s in build_corpus("full") if s.id == "exfil-web-email-polite_review-plain-0")


async def test_gullible_model_succeeds_undefended_and_is_blocked_by_agentwall():
    scenario = _exfil()
    attacker = scenario.attack.values["email"]
    keys = _Keys()
    spec = ModelAgentSpec(ScriptedClient(gullible(attacker)), "fake")

    undefended = await run_scenario(scenario, _abl("none"), keys, spec)
    assert undefended.saw_payload and undefended.attack_attempted and undefended.attack_success
    assert undefended.agent == "gemini:fake" and undefended.stop == "answer"

    client = ScriptedClient(gullible(attacker))
    defended = await run_scenario(scenario, _abl("full"), keys, ModelAgentSpec(client, "fake"))
    assert defended.attack_attempted and not defended.attack_success
    assert defended.goal_action == "block"
    assert defended.task_completed
    # The model was told why, as the tool result.
    assert "AgentWall blocked this call" in tool_outputs(client.requests[-1])


async def test_model_that_ignores_injection_is_not_counted_as_attempting():
    result = await run_scenario(
        _exfil(), _abl("full"), _Keys(), ModelAgentSpec(ScriptedClient(careful), "fake")
    )
    assert result.saw_payload and result.attack_attempted is False
    assert result.goal_action is None and result.task_completed


async def test_unknown_tool_gets_an_error_without_reaching_the_gateway():
    def policy(request: ModelRequest) -> ModelResponse:
        if model_turns(request) == 0:
            return ModelResponse(calls=(call("bank__wire", {"to": "x"}),))
        return ModelResponse(text="ok")

    client = ScriptedClient(policy)
    result = await run_scenario(_exfil(), _abl("none"), _Keys(), ModelAgentSpec(client, "fake"))
    assert "no tool named 'bank__wire'" in tool_outputs(client.requests[-1])
    assert result.legit_calls == 0 and result.overheads_ms == []


async def test_max_turns_stops_a_looping_model():
    loop = ScriptedClient(lambda r: ModelResponse(calls=(call("portfolio__get_holdings", {}),)))
    result = await run_scenario(
        _exfil(), _abl("none"), _Keys(), ModelAgentSpec(loop, "fake", max_turns=3)
    )
    assert result.stop == "max_turns" and result.turns == 3


async def test_tools_are_offered_with_their_schemas_and_poisoned_tools_are_hidden():
    scenario = next(s for s in build_corpus("full") if s.category == "tool_poisoning")
    client = ScriptedClient(lambda r: ModelResponse(text="done"))
    await run_scenario(scenario, _abl("none"), _Keys(), ModelAgentSpec(client, "fake"))
    names = {t.name for t in client.requests[0].tools}
    assert "weather__get_weather" in names and "email__send_email" in names
    send = next(t for t in client.requests[0].tools if t.name == "email__send_email")
    assert "to" in send.parameters["properties"]

    client = ScriptedClient(lambda r: ModelResponse(text="done"))
    await run_scenario(scenario, _abl("full"), _Keys(), ModelAgentSpec(client, "fake"))
    assert "weather__get_weather" not in {t.name for t in client.requests[0].tools}


# -- cache and throttle --------------------------------------------------------------------------


def _request(text: str = "hi", seed: int | None = None) -> ModelRequest:
    return ModelRequest(
        "fake",
        "sys",
        (ToolSpec("t", "d", {"type": "object"}),),
        ({"role": "user", "text": text},),
        seed=seed,
    )


def test_cache_records_then_replays_without_the_model(tmp_path):
    path = tmp_path / "cache.jsonl"
    live = ScriptedClient(lambda r: ModelResponse(text="answer", finish="STOP"))
    recorder = CachedClient(live, path)
    assert recorder.generate(_request()).text == "answer"
    assert recorder.generate(_request()).text == "answer"
    assert len(live.requests) == 1 and recorder.hits == 1 and recorder.misses == 1

    replay = CachedClient(None, path)
    assert replay.generate(_request()) == ModelResponse(text="answer")
    with pytest.raises(CacheMiss):
        replay.generate(_request("different"))
    # Seeds are part of the key, so repeats are separate samples.
    assert _request(seed=1).key() != _request(seed=2).key()
    assert json.loads(path.read_text(encoding="utf-8").splitlines()[0])["model"] == "fake"


def test_throttle_spaces_calls_retries_rate_limits_and_enforces_budget():
    sleeps: list[float] = []
    now = [0.0]

    def sleep(s: float) -> None:
        sleeps.append(s)
        now[0] += s

    attempts = {"n": 0}

    def flaky(request: ModelRequest) -> ModelResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise RateLimited("slow down", retry_after=30)
        return ModelResponse(text="ok")

    t = ThrottledClient(ScriptedClient(flaky), rpm=6, budget=3, sleep=sleep, clock=lambda: now[0])
    assert t.generate(_request()).text == "ok"
    assert sleeps[0] >= 30  # honoured the server's retry delay
    assert t.calls == 2
    t.generate(_request())
    assert sleeps[-1] == pytest.approx(10.0, abs=0.01)  # 6 rpm means 10 s apart
    with pytest.raises(BudgetExhausted):
        t.generate(_request())


async def test_run_stops_cleanly_and_reports_progress(tmp_path):
    client = CachedClient(None, tmp_path / "empty.jsonl")
    with pytest.raises(IncompleteRun) as info:
        await run_suite("quick", ["none"], agent=ModelAgentSpec(client, "fake"))
    assert info.value.done == 0 and info.value.total == len(build_corpus("quick"))


# -- reporting -----------------------------------------------------------------------------------


async def test_model_report_shows_attempted_and_intervals():
    scenario = _exfil()
    attacker = scenario.attack.values["email"]
    keys = _Keys()
    rows = [
        await run_scenario(
            scenario, _abl(c), keys, ModelAgentSpec(ScriptedClient(gullible(attacker)), "fake")
        )
        for c in ("none", "full")
    ]
    summary = summarise(rows)
    assert summary["full"]["attempted"] == 100.0 and summary["full"]["asr"] == 0.0
    md = render_markdown("quick", summary, "abc", agent="gemini:fake")
    assert "Attempted" in md and "gemini:fake" in md


def test_wilson_interval():
    assert wilson(0, 0) == (0.0, 0.0)
    lo, hi = wilson(0, 30)
    assert lo == 0.0 and 10 < hi < 12
    lo, hi = wilson(15, 30)
    assert lo < 50 < hi


def test_history_gets_an_agent_column(tmp_path):
    history = tmp_path / "history.csv"
    history.write_text("time,commit,suite,config,asr\nt,c,quick,none,100.0\n", encoding="utf-8")
    _migrate_history(history)
    rows = list(csv.reader(history.open(encoding="utf-8")))
    assert rows[0][3] == "agent" and rows[1][3] == "obedient" and rows[1][4] == "none"
