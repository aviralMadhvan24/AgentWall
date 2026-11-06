"""Gemini adapter: converts plain ``ModelRequest``/``ModelResponse`` objects to and from google-genai.

Only this module imports the SDK, so the rest of the agent code (and its tests) runs without it.
"""

from __future__ import annotations

import base64
import os
import re
from typing import Any

from agentwall.agent.model import (
    GENERATED_ID_PREFIX,
    ModelError,
    ModelRequest,
    ModelResponse,
    QuotaExhausted,
    RateLimited,
    TransientError,
)

DEFAULT_MODEL = "gemini-3.5-flash"  # 2.5-flash is closed to new users; verified with a free key
_RETRY_DELAY = re.compile(r"retryDelay['\"]?\s*:\s*['\"]?(\d+(?:\.\d+)?)s")


def api_key_from_env() -> str | None:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")


def _types() -> Any:
    from google.genai import types

    return types


def to_contents(request: ModelRequest) -> list[Any]:
    types = _types()
    contents = []
    for msg in request.messages:
        role = msg["role"]
        if role == "user":
            contents.append(types.Content(role="user", parts=[types.Part(text=msg["text"])]))
        elif role == "model":
            parts = []
            if msg.get("text"):
                parts.append(types.Part(text=msg["text"]))
            for call in msg.get("calls") or ():
                native_id = call["id"] if not call["id"].startswith(GENERATED_ID_PREFIX) else None
                sig = call.get("signature")
                parts.append(
                    types.Part(
                        function_call=types.FunctionCall(
                            name=call["name"], args=call["args"], id=native_id
                        ),
                        thought_signature=base64.b64decode(sig) if sig else None,
                    )
                )
            contents.append(types.Content(role="model", parts=parts or [types.Part(text="")]))
        elif role == "tool":
            parts = []
            for res in msg["results"]:
                native_id = res["id"] if not res["id"].startswith(GENERATED_ID_PREFIX) else None
                parts.append(
                    types.Part(
                        function_response=types.FunctionResponse(
                            id=native_id, name=res["name"], response={"result": res["output"]}
                        )
                    )
                )
            contents.append(types.Content(role="user", parts=parts))
        else:
            raise ValueError(f"unknown message role {role!r}")
    return contents


def to_config(request: ModelRequest) -> Any:
    types = _types()
    tools = None
    if request.tools:
        tools = [
            types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name=t.name,
                        description=t.description,
                        parameters_json_schema=t.parameters or {"type": "object", "properties": {}},
                    )
                    for t in request.tools
                ]
            )
        ]
    return types.GenerateContentConfig(
        system_instruction=request.system or None,
        tools=tools,
        temperature=request.temperature,
        seed=request.seed,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )


def from_response(response: Any, turn: int) -> ModelResponse:
    candidates = response.candidates or []
    if not candidates:
        reason = getattr(getattr(response, "prompt_feedback", None), "block_reason", None)
        return ModelResponse(None, (), f"PROMPT_BLOCKED:{reason}" if reason else "NO_CANDIDATE")
    cand = candidates[0]
    texts: list[str] = []
    calls: list[dict[str, Any]] = []
    for part in cand.content.parts if cand.content and cand.content.parts else []:
        if part.thought:
            continue
        if part.function_call is not None:
            fc = part.function_call
            sig = part.thought_signature
            calls.append(
                {
                    "id": fc.id or f"{GENERATED_ID_PREFIX}{turn}_{len(calls)}",
                    "name": fc.name or "",
                    "args": dict(fc.args or {}),
                    "signature": base64.b64encode(sig).decode("ascii") if sig else None,
                }
            )
        elif part.text:
            texts.append(part.text)
    finish = cand.finish_reason
    finish_name = getattr(finish, "name", None) or (str(finish) if finish else "STOP")
    return ModelResponse("".join(texts) or None, tuple(calls), finish_name)


def map_error(exc: Exception) -> Exception:
    """Translate a google-genai error into the retry/stop classes the throttle understands."""
    from google.genai import errors

    if not isinstance(exc, errors.APIError):
        # A request that times out or loses its connection is worth retrying (httpx raises
        # TimeoutException / ConnectError / RemoteProtocolError subclasses).
        name = type(exc).__name__
        if any(k in name for k in ("Timeout", "ConnectError", "RemoteProtocolError", "ReadError")):
            return TransientError(f"{name}: {exc}")
        return exc
    text = str(exc)
    if exc.code == 429:
        if "PerDay" in text:
            return QuotaExhausted(
                "Gemini daily free-tier quota used up; re-run the same command tomorrow to resume"
            )
        match = _RETRY_DELAY.search(text)
        return RateLimited(exc.message or text, float(match.group(1)) if match else None)
    if exc.code in (500, 502, 503, 504):
        return TransientError(exc.message or text)
    return ModelError(f"Gemini API error {exc.code}: {exc.message or text}")


class GeminiClient:
    def __init__(self, api_key: str | None = None, timeout_s: float = 120.0) -> None:
        from google import genai
        from google.genai import types

        key = api_key or api_key_from_env()
        if not key:
            raise ModelError(
                "set GEMINI_API_KEY (free key: https://aistudio.google.com/apikey), "
                "or pass --replay-only to use cached responses"
            )
        # Without a timeout one stuck request can hang a whole benchmark run.
        self._client = genai.Client(
            api_key=key, http_options=types.HttpOptions(timeout=int(timeout_s * 1000))
        )

    def generate(self, request: ModelRequest) -> ModelResponse:
        try:
            response = self._client.models.generate_content(
                model=request.model, contents=to_contents(request), config=to_config(request)
            )
        except Exception as exc:
            mapped = map_error(exc)
            if mapped is exc:
                raise
            raise mapped from exc
        return from_response(response, len(request.messages))

    def list_models(self) -> list[str]:
        names = []
        for m in self._client.models.list():
            actions = getattr(m, "supported_actions", None) or []
            if "generateContent" in actions and m.name:
                names.append(m.name.removeprefix("models/"))
        return sorted(names)
