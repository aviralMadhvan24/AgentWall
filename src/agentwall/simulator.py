"""Policy simulator: replay past decisions from an audit log against a draft policy.

The audit log records, for every tool call, everything the policy looked at: the argument attributions
(full values, labels, sources), the tool's capability and argument roles, the server's label and the
destination allowlist, plus a ``span`` event for every piece of text that entered the context (labels,
entities and detector flags, not the text itself). The simulator rebuilds each session's ledger as it
was when each call was decided and evaluates the draft policy on it.

Replaying a log against the policy that produced it gives the same decisions (the test suite checks
this on the whole quick harness), so any difference is caused by the draft.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agentwall.labels import Confidentiality, Integrity, Label
from agentwall.policy.context import CallContext
from agentwall.policy.engine import Policy
from agentwall.provenance.attribution import ValueAttribution
from agentwall.provenance.ledger import Ledger, Span


@dataclass
class SimulatedCall:
    seq: int
    session: str
    tool: str
    old_action: str
    new_action: str
    old_rules: list[str]
    new_rules: list[str]
    explanation: str

    @property
    def changed(self) -> bool:
        return self.old_action != self.new_action


@dataclass
class SimulationReport:
    calls: list[SimulatedCall] = field(default_factory=list)
    skipped: int = 0  # calls the log cannot replay (hidden tools, built-ins, older log format)

    @property
    def changed(self) -> list[SimulatedCall]:
        return [c for c in self.calls if c.changed]

    def transitions(self) -> Counter[tuple[str, str]]:
        return Counter((c.old_action, c.new_action) for c in self.changed)


def _label(text: str) -> Label:
    integrity, confidentiality = str(text).split("/", 1)
    return Label.parse(integrity, confidentiality)


def _span(record: dict[str, Any]) -> Span:
    span = Span(
        id=record["id"],
        kind=record["kind"],
        source=record["source"],
        text="",
        label=_label(record["label"]),
        seq=int(record["seq"]),
        flagged=bool(record.get("flagged")),
        detector_score=float(record.get("detector_score") or 0.0),
        parent=record.get("parent"),
    )
    # The text is not logged; restore what predicates read instead.
    span.entities = frozenset(record.get("entities") or ())
    span.norm = record.get("norm", "")
    return span


def _ledger(spans: Iterable[Span]) -> Ledger:
    ledger = Ledger()
    ledger._spans = list(spans)
    return ledger


def _attribution(record: dict[str, Any]) -> ValueAttribution:
    return ValueAttribution(
        path=record["path"],
        value=str(record["value"]),
        integrity=Integrity.parse(record["integrity"]),
        confidentiality=Confidentiality.parse(record["confidentiality"]),
        method=record["method"],
        sources=tuple(record.get("sources") or ()),
        from_flagged=bool(record.get("from_flagged")),
    )


def simulate(
    entries: Iterable[dict[str, Any]],
    policy: Policy,
    destination_allowlist: tuple[str, ...] | None = None,
) -> SimulationReport:
    """Re-decide every replayable tool call in ``entries`` with ``policy``.

    ``destination_allowlist`` overrides the recorded allowlist (to try a draft allowlist too).
    """
    report = SimulationReport()
    spans: dict[str, list[Span]] = defaultdict(list)
    for entry in entries:
        event = entry.get("event")
        if event == "span":
            spans[entry["session"]].append(_span(entry["span"]))
            continue
        if event != "tool_call":
            continue
        context = entry.get("context")
        if not context:
            report.skipped += 1
            continue
        # The call's own output (and anything decoded from it) was added after the decision.
        out_id = (entry.get("output_span") or {}).get("id")
        before = [
            s
            for s in spans[entry["session"]]
            if out_id is None or (s.id != out_id and s.parent != out_id)
        ]
        server, _, tool = str(entry["tool"]).partition("__")
        ctx = CallContext(
            server=entry.get("server", server),
            tool=tool,
            capability=context["capability"],
            attributions={a["path"]: _attribution(a) for a in entry.get("attributions") or []},
            ledger=_ledger(before),
            server_label=_label(context["server_label"]),
            control_args=tuple(context.get("control_args") or ()),
            data_args=tuple(context.get("data_args") or ()),
            destination_allowlist=(
                destination_allowlist
                if destination_allowlist is not None
                else tuple(context.get("destination_allowlist") or ())
            ),
        )
        decision = policy.evaluate(ctx)
        report.calls.append(
            SimulatedCall(
                seq=int(entry.get("seq", 0)),
                session=entry["session"],
                tool=entry["tool"],
                old_action=entry["action"],
                new_action=decision.action,
                old_rules=list(entry.get("rules") or []),
                new_rules=[m.rule_id for m in decision.matches],
                explanation=decision.explain(),
            )
        )
    return report


def render_report(report: SimulationReport, policy_name: str, show_all: bool = False) -> str:
    total = len(report.calls)
    lines = [
        f"Replayed {total} decisions against policy {policy_name!r}"
        + (f" ({report.skipped} not replayable)" if report.skipped else "")
        + f": {len(report.changed)} would change.",
    ]
    for (old, new), n in sorted(report.transitions().items()):
        lines.append(f"  {old} -> {new}: {n}")
    shown = report.calls if show_all else report.changed
    for c in shown:
        mark = "*" if c.changed else " "
        lines.append(
            f"{mark} #{c.seq} {c.session} {c.tool}: {c.old_action} -> {c.new_action}"
            + (f"  [{', '.join(c.new_rules)}]" if c.new_rules else "")
        )
        if c.changed:
            lines.extend(f"      {line}" for line in c.explanation.splitlines())
    return "\n".join(lines)
