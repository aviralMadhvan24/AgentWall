"""Gateway core: the checks every tool call passes before any server sees it.

Request path for ``call_tool``:

1. resolve the namespaced tool and refuse anything hidden by the registry
2. attribute every argument to the context spans it came from
3. evaluate the policy
4. record the decision in the audit log
5. on ``allow``, forward to the backend and label the output from the server's manifest
   (the detector may downgrade it) before it re-enters the context
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Iterable
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from agentwall.audit.log import AuditLog
from agentwall.labels import TRUSTED_PUBLIC, Label
from agentwall.policy.context import CallContext
from agentwall.policy.engine import Decision, Policy, RuleMatch
from agentwall.provenance.attribution import ValueAttribution, attribute_args
from agentwall.provenance.ledger import DetectorFn, Ledger, Span
from agentwall.registry.manifest import ToolPin
from agentwall.registry.registry import Registry, ToolStatus
from agentwall.types import ToolInfo, ToolResult

SEP = "__"

Approver = Callable[[CallContext, Decision], Awaitable[bool]]


def qualify(server: str, tool: str) -> str:
    return f"{server}{SEP}{tool}"


@dataclass
class GatewayConfig:
    policy: Policy = field(default_factory=lambda: Policy.load("default"))
    registry: Registry = field(default_factory=Registry)
    detector: DetectorFn | None = None
    flag_threshold: float = 0.5
    attribution: bool = True
    enforce_manifests: bool = True
    destination_allowlist: tuple[str, ...] = ()
    unknown_capability: str = "egress"
    approver: Approver | None = None
    audit: AuditLog = field(default_factory=AuditLog)


@dataclass
class ExposedTool:
    qualified: str
    server: str
    info: ToolInfo
    status: ToolStatus
    pin: ToolPin | None

    @property
    def visible(self) -> bool:
        return self.status.visible


@dataclass
class CallOutcome:
    tool: str
    arguments: dict[str, Any]
    decision: Decision
    executed: bool
    result: ToolResult | None = None
    attributions: dict[str, ValueAttribution] = field(default_factory=dict)
    output_span: Span | None = None
    overhead_ms: float = 0.0

    @property
    def action(self) -> str:
        return self.decision.action

    def message_for_agent(self) -> str:
        if self.executed and self.result is not None:
            return self.result.text
        reasons = "; ".join(m.reason or m.rule_id for m in self.decision.matches) or "policy"
        if self.decision.action == "ask":
            return f"AgentWall held this call for human approval: {reasons}"
        return f"AgentWall blocked this call: {reasons}"


class Session:
    """One agent conversation: its provenance ledger and call history."""

    def __init__(self, gateway: Gateway, session_id: str) -> None:
        self.id = session_id
        self.gateway = gateway
        cfg = gateway.config
        self.ledger = Ledger(detector=cfg.detector, flag_threshold=cfg.flag_threshold)
        self.calls: list[CallOutcome] = []
        for tool in gateway.visible_tools():
            # A description that still matches its signed pin was reviewed by the operator, so it is
            # trusted. Anything else carries the server's output label.
            reviewed = tool.pin is not None and tool.pin.matches(tool.info)
            self.ledger.add(
                tool.info.description,
                kind="tool_description",
                source=f"{tool.server}/{tool.info.name}",
                label=TRUSTED_PUBLIC if reviewed else gateway.label_for(tool.server),
            )

    def add_user_message(self, text: str) -> Span:
        return self.ledger.add(text, kind="user", source="user", label=TRUSTED_PUBLIC)

    def add_system_message(self, text: str) -> Span:
        return self.ledger.add(text, kind="system", source="system", label=TRUSTED_PUBLIC)

    async def call_tool(
        self, qualified: str, arguments: dict[str, Any] | None = None
    ) -> CallOutcome:
        outcome = await self.gateway.call_tool(self, qualified, arguments or {})
        self.calls.append(outcome)
        return outcome


class Gateway:
    def __init__(self, backends: Iterable[Any], config: GatewayConfig | None = None) -> None:
        self.backends = {b.name: b for b in backends}
        self.config = config or GatewayConfig()
        self.tools: dict[str, ExposedTool] = {}
        self._sessions = 0
        self._stack: AsyncExitStack | None = None

    # -- lifecycle ----------------------------------------------------------------------------
    async def __aenter__(self) -> Gateway:
        """Connect every backend; they are closed in reverse order on exit."""
        self._stack = AsyncExitStack()
        for backend in self.backends.values():
            if hasattr(backend, "__aenter__"):
                await self._stack.enter_async_context(backend)
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None

    # -- tool listing -------------------------------------------------------------------------
    async def refresh(self) -> list[ToolStatus]:
        """List tools from every backend and run them through the registry."""
        cfg = self.config
        statuses: list[ToolStatus] = []
        tools: dict[str, ExposedTool] = {}
        for name, backend in self.backends.items():
            listing = await backend.list_tools()
            if cfg.enforce_manifests:
                checked = cfg.registry.check_listing(
                    name, listing, cfg.detector, cfg.flag_threshold
                )
            else:
                checked = [
                    ToolStatus(name, t.name, "approved", "manifests not enforced") for t in listing
                ]
            for info, status in zip(listing, checked, strict=True):
                q = qualify(name, info.name)
                tools[q] = ExposedTool(q, name, info, status, cfg.registry.pin_for(name, info.name))
                statuses.append(status)
                if not status.visible:
                    cfg.audit.record(
                        {
                            "event": "tool_hidden",
                            "tool": q,
                            "state": status.state,
                            "reason": status.reason,
                        }
                    )
        self.tools = tools
        return statuses

    def visible_tools(self) -> list[ExposedTool]:
        return [t for t in self.tools.values() if t.visible]

    def label_for(self, server: str, tool: str | None = None) -> Label:
        return self.config.registry.label_for(server, tool)

    def new_session(self) -> Session:
        self._sessions += 1
        return Session(self, f"session-{self._sessions}")

    # -- calls --------------------------------------------------------------------------------
    async def call_tool(
        self, session: Session, qualified: str, arguments: dict[str, Any]
    ) -> CallOutcome:
        cfg = self.config
        start = time.perf_counter()
        tool = self.tools.get(qualified)
        if tool is None or not tool.visible:
            state = tool.status.state if tool else "unknown"
            decision = Decision(
                "block", (RuleMatch("tool-not-exposed", "block", f"tool is {state}", ()),)
            )
            outcome = CallOutcome(qualified, arguments, decision, False, overhead_ms=_ms(start))
            self._audit(session, outcome, tool.server if tool else "?")
            return outcome

        pin = tool.pin
        ctx = CallContext(
            server=tool.server,
            tool=tool.info.name,
            capability=pin.capability if pin else cfg.unknown_capability,
            attributions=attribute_args(arguments, session.ledger, enabled=cfg.attribution),
            ledger=session.ledger,
            server_label=self.label_for(tool.server),
            control_args=pin.control_args if pin else (),
            data_args=pin.data_args if pin else (),
            destination_allowlist=cfg.destination_allowlist,
        )
        decision = cfg.policy.evaluate(ctx)
        overhead = _ms(start)

        approved = decision.allowed
        if decision.action == "ask" and cfg.approver is not None:
            approved = await cfg.approver(ctx, decision)

        outcome = CallOutcome(qualified, arguments, decision, False, attributions=ctx.attributions)
        if approved:
            result = await self.backends[tool.server].call_tool(tool.info.name, arguments)
            t_label = time.perf_counter()
            outcome.output_span = session.ledger.add(
                result.text,
                kind="tool_output",
                source=f"{tool.server}/{tool.info.name}",
                label=self.label_for(tool.server, tool.info.name),
            )
            overhead += _ms(t_label)
            outcome.executed, outcome.result = True, result
        outcome.overhead_ms = overhead
        self._audit(session, outcome, tool.server)
        return outcome

    def _audit(self, session: Session, outcome: CallOutcome, server: str) -> None:
        self.config.audit.record(
            {
                "event": "tool_call",
                "session": session.id,
                "server": server,
                "tool": outcome.tool,
                "action": outcome.action,
                "executed": outcome.executed,
                "rules": [m.rule_id for m in outcome.decision.matches],
                "attributions": [a.to_dict() for a in outcome.attributions.values()],
                "output_span": outcome.output_span.to_dict() if outcome.output_span else None,
                "overhead_ms": round(outcome.overhead_ms, 3),
            }
        )


def _ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0
