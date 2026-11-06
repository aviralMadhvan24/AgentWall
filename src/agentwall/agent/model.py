"""Provider-neutral model requests and responses, plus the client wrappers every run goes through.

A request is plain JSON (no SDK objects), so it can be hashed and cached, and a cached response replays
byte-for-byte. Clients are layered::

    CachedClient(ThrottledClient(GeminiClient(...)))

- ``CachedClient`` answers repeated requests from a JSONL file; in replay mode it never calls out.
- ``ThrottledClient`` spaces requests to a requests-per-minute limit, retries rate limits and server
  errors, and stops cleanly at a call budget or when the provider's daily quota is used up.

Message shapes inside ``ModelRequest.messages``::

    {"role": "user", "text": "..."}
    {"role": "model", "text": "..." | None, "calls": [ToolCall, ...]}
    {"role": "tool", "results": [{"id": ..., "name": ..., "output": "..."}]}

A ``ToolCall`` is ``{"id", "name", "args", "signature"}``. ``signature`` is the provider's opaque
reasoning token (Gemini's thought signature, base64), which must be sent back unchanged on later turns.
"""

from __future__ import annotations

import hashlib
import json
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

GENERATED_ID_PREFIX = "aw_call_"


class ModelError(RuntimeError):
    """The provider rejected a request in a way retrying will not fix."""


class RateLimited(ModelError):
    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class TransientError(ModelError):
    """A server-side error worth retrying."""


class RunStopped(RuntimeError):
    """A run must stop early; finished work is kept and the same command resumes it."""


class QuotaExhausted(RunStopped):
    """The provider's daily quota is used up."""


class BudgetExhausted(RunStopped):
    """The ``--budget`` of network calls for this run is used up."""


class CacheMiss(RunStopped):
    """Replay-only mode met a request that is not in the cache."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ModelRequest:
    model: str
    system: str
    tools: tuple[ToolSpec, ...]
    messages: tuple[dict[str, Any], ...]
    temperature: float = 0.0
    seed: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "system": self.system,
            "tools": [asdict(t) for t in self.tools],
            "messages": list(self.messages),
            "temperature": self.temperature,
            "seed": self.seed,
        }

    def key(self) -> str:
        canonical = json.dumps(self.to_json(), sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ModelResponse:
    text: str | None = None
    calls: tuple[dict[str, Any], ...] = ()
    finish: str = "STOP"

    def to_json(self) -> dict[str, Any]:
        return {"text": self.text, "calls": list(self.calls), "finish": self.finish}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> ModelResponse:
        return cls(data.get("text"), tuple(data.get("calls") or ()), data.get("finish", "STOP"))


class ModelClient(Protocol):
    def generate(self, request: ModelRequest) -> ModelResponse: ...


# -- caching -------------------------------------------------------------------------------------


class CachedClient:
    """Answer requests from a JSONL cache; on a miss, ask ``inner`` (or stop, in replay mode)."""

    def __init__(self, inner: ModelClient | None, path: str | Path, replay_only: bool = False):
        self.inner = inner
        self.path = Path(path)
        self.replay_only = replay_only or inner is None
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            with self.path.open(encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        entry = json.loads(line)
                        self._entries[entry["key"]] = entry["response"]

    def __len__(self) -> int:
        return len(self._entries)

    def generate(self, request: ModelRequest) -> ModelResponse:
        key = request.key()
        with self._lock:
            cached = self._entries.get(key)
        if cached is not None:
            self.hits += 1
            return ModelResponse.from_json(cached)
        if self.replay_only or self.inner is None:
            raise CacheMiss(
                f"request {key[:12]} is not in {self.path}; run without --replay-only to fetch it"
            )
        response = self.inner.generate(request)
        self.misses += 1
        payload = response.to_json()
        entry = {"key": key, "model": request.model, "response": payload}
        with self._lock:
            self._entries[key] = payload
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        return response


# -- throttling ----------------------------------------------------------------------------------


@dataclass
class ThrottledClient:
    """Free-tier friendly access: a minimum gap between calls, retries, and a hard call budget."""

    inner: ModelClient
    rpm: float = 8.0
    budget: int = 0  # 0 means no limit
    max_retries: int = 6
    max_backoff_s: float = 120.0
    sleep: Any = time.sleep
    clock: Any = time.monotonic
    calls: int = 0
    _last: float | None = field(default=None, repr=False)

    def _wait_turn(self) -> None:
        if self.rpm <= 0 or self._last is None:
            return
        gap = 60.0 / self.rpm - (self.clock() - self._last)
        if gap > 0:
            self.sleep(gap)

    def generate(self, request: ModelRequest) -> ModelResponse:
        for attempt in range(self.max_retries + 1):
            if self.budget and self.calls >= self.budget:
                raise BudgetExhausted(f"call budget of {self.budget} used up")
            self._wait_turn()
            self.calls += 1
            self._last = self.clock()
            try:
                return self.inner.generate(request)
            except (RateLimited, TransientError) as exc:
                if attempt == self.max_retries:
                    raise
                hint = exc.retry_after if isinstance(exc, RateLimited) else None
                backoff = min(self.max_backoff_s, 5.0 * 2**attempt) * (0.8 + 0.4 * random.random())
                self.sleep(max(hint or 0.0, backoff))
        raise AssertionError("unreachable")
