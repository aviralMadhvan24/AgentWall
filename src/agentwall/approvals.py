"""Human approvals for calls the policy sends to ``ask``.

When a rule says ``ask``, the gateway hands the call to an approver. ``StoreApprover`` keeps requests
in a JSON file that operators answer from the CLI (``agentwall approvals``) or the console:

- A **remembered** decision (approve or deny, ``--remember``) answers every future call with the same
  fingerprint automatically.
- A one-time approval lets exactly one matching call through, so the usual flow in proxy mode is:
  the call is held, the agent is told the request id, the operator approves, the agent retries.
- Optionally the approver waits ``wait_seconds`` for an answer before holding the call (fail closed).

The fingerprint covers the server, tool, the matched rules and the values of the control arguments
(recipient, URL, path, amount), never the payload. Approving "email aviral@home.in" therefore never
approves "email someone@else"; a changed message body to the same recipient is the same request.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import anyio

from agentwall.policy.context import CallContext
from agentwall.policy.engine import Decision
from agentwall.provenance.normalize import normalize

STATUSES = ("pending", "approved", "denied")


def fingerprint(ctx: CallContext, decision: Decision) -> str:
    controls = {a.path: normalize(a.value) for a in ctx.control_attributions()}
    body = {
        "server": ctx.server,
        "tool": ctx.tool,
        "rules": sorted(m.rule_id for m in decision.matches if m.action == "ask"),
        "control": dict(sorted(controls.items())),
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()[:16]


@dataclass
class ApprovalRequest:
    id: str
    fingerprint: str
    server: str
    tool: str
    control: dict[str, str]
    reasons: list[str]
    created: float
    status: str = "pending"
    remember: bool = False
    used: bool = False  # a one-time approval is consumed by the call it lets through
    decided_at: float | None = None
    calls_seen: int = 1


@dataclass
class _State:
    requests: dict[str, ApprovalRequest] = field(default_factory=dict)


class ApprovalStore:
    """JSON-file store (or in-memory with ``path=None``). Safe to share between processes."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._memory = _State()

    # -- persistence ---------------------------------------------------------------------------
    def _read(self) -> _State:
        if self.path is None:
            return self._memory
        if not self.path.exists():
            return _State()
        raw = json.loads(self.path.read_text(encoding="utf-8") or "{}")
        return _State({k: ApprovalRequest(**v) for k, v in (raw.get("requests") or {}).items()})

    def _write(self, state: _State) -> None:
        if self.path is None:
            self._memory = state
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps({"requests": {k: asdict(v) for k, v in state.requests.items()}}, indent=1)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".approvals-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(data)
        os.replace(tmp, self.path)  # atomic: readers never see a half-written file

    # -- queries -------------------------------------------------------------------------------
    def all(self) -> list[ApprovalRequest]:
        with self._lock:
            return sorted(self._read().requests.values(), key=lambda r: r.created)

    def pending(self) -> list[ApprovalRequest]:
        return [r for r in self.all() if r.status == "pending"]

    def get(self, request_id: str) -> ApprovalRequest:
        with self._lock:
            state = self._read()
        if request_id not in state.requests:
            raise KeyError(f"no approval request {request_id!r}")
        return state.requests[request_id]

    # -- decisions -----------------------------------------------------------------------------
    def resolve(self, fp: str) -> bool | None:
        """A standing answer for this fingerprint: remembered, or an unused one-time approval
        (which this call consumes). None means a human has to decide."""
        with self._lock:
            state = self._read()
            mine = [r for r in state.requests.values() if r.fingerprint == fp]
            for r in sorted(mine, key=lambda r: r.decided_at or 0, reverse=True):
                if r.remember and r.status != "pending":
                    return r.status == "approved"
            for r in mine:
                if r.status == "approved" and not r.used:
                    r.used = True
                    self._write(state)
                    return True
        return None

    def submit(self, fp: str, ctx: CallContext, reasons: list[str]) -> ApprovalRequest:
        """File a request, or bump the open one for the same fingerprint."""
        with self._lock:
            state = self._read()
            for r in state.requests.values():
                if r.fingerprint == fp and r.status == "pending":
                    r.calls_seen += 1
                    self._write(state)
                    return r
            req = ApprovalRequest(
                id=secrets.token_hex(3),
                fingerprint=fp,
                server=ctx.server,
                tool=ctx.tool,
                control={a.path: a.value[:200] for a in ctx.control_attributions()},
                reasons=reasons,
                created=round(time.time(), 3),
            )
            state.requests[req.id] = req
            self._write(state)
            return req

    def decide(self, request_id: str, approve: bool, remember: bool = False) -> ApprovalRequest:
        with self._lock:
            state = self._read()
            if request_id not in state.requests:
                raise KeyError(f"no approval request {request_id!r}")
            req = state.requests[request_id]
            req.status = "approved" if approve else "denied"
            req.remember = remember
            req.decided_at = round(time.time(), 3)
            self._write(state)
            return req

    def forget(self, request_id: str) -> None:
        with self._lock:
            state = self._read()
            state.requests.pop(request_id, None)
            self._write(state)


class StoreApprover:
    """Gateway approver backed by an :class:`ApprovalStore`.

    Returns ``(approved, note)``; the note tells the agent what happened (e.g. which request id the
    user should approve before a retry).
    """

    def __init__(
        self, store: ApprovalStore, wait_seconds: float = 0.0, poll_seconds: float = 0.5
    ) -> None:
        self.store = store
        self.wait_seconds = wait_seconds
        self.poll_seconds = poll_seconds

    async def __call__(self, ctx: CallContext, decision: Decision) -> tuple[bool, str]:
        fp = fingerprint(ctx, decision)
        standing = self.store.resolve(fp)
        if standing is not None:
            return standing, "decided by an operator earlier" + ("" if standing else " (denied)")
        reasons = [m.reason or m.rule_id for m in decision.matches if m.action == "ask"]
        req = self.store.submit(fp, ctx, reasons)
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            await anyio.sleep(min(self.poll_seconds, max(0.0, deadline - time.monotonic())))
            current = self.store.get(req.id)
            if current.status != "pending":
                if current.status == "approved" and not current.remember:
                    self.store.resolve(fp)  # consume the one-time approval for this call
                return current.status == "approved", f"request {req.id} {current.status}"
        return False, (
            f"approval request {req.id} is waiting for the user. Ask them to run "
            f"`agentwall approvals approve {req.id}` (or use the console), then retry the same call."
        )


def approval_summary(req: ApprovalRequest) -> dict[str, Any]:
    return {
        "id": req.id,
        "status": req.status + (" (remembered)" if req.remember else ""),
        "tool": f"{req.server}/{req.tool}",
        "control": req.control,
        "reasons": req.reasons,
        "calls_seen": req.calls_seen,
        "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(req.created)),
    }
