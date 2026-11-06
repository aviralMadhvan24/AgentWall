from __future__ import annotations

import base64
import os

import pytest

genai_types = pytest.importorskip("google.genai.types")
genai_errors = pytest.importorskip("google.genai.errors")

from agentwall.agent.gemini import from_response, map_error, to_config, to_contents  # noqa: E402
from agentwall.agent.model import (  # noqa: E402
    ModelError,
    ModelRequest,
    QuotaExhausted,
    RateLimited,
    ToolSpec,
    TransientError,
)

SIG = base64.b64encode(b"opaque-thought").decode()


def _request() -> ModelRequest:
    return ModelRequest(
        model="gemini-x",
        system="be helpful",
        tools=(
            ToolSpec(
                "email__send_email",
                "Send an email.",
                {
                    "type": "object",
                    "title": "send_emailArguments",
                    "properties": {"to": {"type": "string", "title": "To"}},
                    "required": ["to"],
                },
            ),
        ),
        messages=(
            {"role": "user", "text": "email bob"},
            {
                "role": "model",
                "text": "Sending.",
                "calls": [
                    {
                        "id": "aw_call_1_0",
                        "name": "email__send_email",
                        "args": {"to": "b@x"},
                        "signature": SIG,
                    },
                    {
                        "id": "native-7",
                        "name": "email__send_email",
                        "args": {"to": "c@x"},
                        "signature": None,
                    },
                ],
            },
            {
                "role": "tool",
                "results": [
                    {"id": "aw_call_1_0", "name": "email__send_email", "output": "sent"},
                    {
                        "id": "native-7",
                        "name": "email__send_email",
                        "output": "AgentWall blocked this call: x",
                    },
                ],
            },
        ),
        seed=3,
    )


def test_request_converts_to_gemini_contents_and_config():
    contents = to_contents(_request())
    assert [c.role for c in contents] == ["user", "model", "user"]
    model = contents[1].parts
    assert model[0].text == "Sending."
    assert model[1].function_call.name == "email__send_email"
    assert model[1].function_call.id is None  # our generated ids are never sent to Gemini
    assert model[1].thought_signature == b"opaque-thought"  # returned unchanged
    assert model[2].function_call.id == "native-7"
    replies = contents[2].parts
    assert replies[1].function_response.response == {"result": "AgentWall blocked this call: x"}
    assert replies[1].function_response.id == "native-7"

    config = to_config(_request())
    decl = config.tools[0].function_declarations[0]
    assert decl.parameters_json_schema["properties"]["to"]["type"] == "string"
    assert config.temperature == 0.0 and config.seed == 3
    assert config.automatic_function_calling.disable is True


def test_response_converts_back_with_ids_and_signatures():
    response = genai_types.GenerateContentResponse(
        candidates=[
            genai_types.Candidate(
                content=genai_types.Content(
                    role="model",
                    parts=[
                        genai_types.Part(text="thinking...", thought=True),
                        genai_types.Part(text="Let me check."),
                        genai_types.Part(
                            function_call=genai_types.FunctionCall(
                                name="web__fetch_url", args={"url": "u"}
                            ),
                            thought_signature=b"sig",
                        ),
                    ],
                ),
                finish_reason=genai_types.FinishReason.STOP,
            )
        ]
    )
    out = from_response(response, turn=4)
    assert out.text == "Let me check."  # thought summaries are dropped
    assert out.finish == "STOP"
    (c,) = out.calls
    assert c["id"] == "aw_call_4_0" and c["args"] == {"url": "u"}
    assert base64.b64decode(c["signature"]) == b"sig"


def test_blocked_prompt_has_no_candidates():
    out = from_response(genai_types.GenerateContentResponse(candidates=[]), turn=0)
    assert out.text is None and out.calls == () and out.finish == "NO_CANDIDATE"


def _api_error(code: int, quota_id: str = "", delay: str = "") -> Exception:
    details = []
    if quota_id:
        details.append(
            {
                "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                "violations": [{"quotaId": quota_id}],
            }
        )
    if delay:
        details.append({"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": delay})
    body = {"error": {"code": code, "message": "m", "status": "S", "details": details}}
    cls = genai_errors.ClientError if code < 500 else genai_errors.ServerError
    return cls(code, body)


def test_errors_map_to_retry_or_stop():
    assert isinstance(
        map_error(_api_error(429, "GenerateRequestsPerDayPerProjectPerModel-FreeTier")),
        QuotaExhausted,
    )
    minute = map_error(
        _api_error(429, "GenerateRequestsPerMinutePerProjectPerModel-FreeTier", "41s")
    )
    assert isinstance(minute, RateLimited) and minute.retry_after == 41.0
    assert isinstance(map_error(_api_error(503)), TransientError)
    bad = map_error(_api_error(400))
    assert isinstance(bad, ModelError) and not isinstance(bad, (RateLimited, TransientError))
    plain = ValueError("x")
    assert map_error(plain) is plain


@pytest.mark.live
@pytest.mark.skipif(not os.environ.get("GEMINI_API_KEY"), reason="needs GEMINI_API_KEY")
def test_live_gemini_round_trip():
    from agentwall.agent.gemini import DEFAULT_MODEL, GeminiClient

    model = os.environ.get("AGENTWALL_GEMINI_MODEL", DEFAULT_MODEL)
    req = ModelRequest(
        model,
        "Use tools when asked.",
        (
            ToolSpec(
                "portfolio__get_holdings",
                "Return the user's holdings.",
                {"type": "object", "properties": {}},
            ),
        ),
        ({"role": "user", "text": "What are my holdings? Use the tool."},),
    )
    out = GeminiClient().generate(req)
    assert out.calls and out.calls[0]["name"] == "portfolio__get_holdings"
