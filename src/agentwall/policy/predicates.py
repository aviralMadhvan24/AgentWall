"""Named predicates that policy rules combine. Each returns (holds, explanation)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentwall.labels import Confidentiality, Integrity
from agentwall.policy.context import CallContext
from agentwall.provenance.entities import destination_entities, extract_entities

PredicateFn = Callable[[CallContext, dict[str, Any]], tuple[bool, str]]
PREDICATES: dict[str, PredicateFn] = {}


def predicate(name: str) -> Callable[[PredicateFn], PredicateFn]:
    def register(fn: PredicateFn) -> PredicateFn:
        PREDICATES[name] = fn
        return fn

    return register


@predicate("control_args_untrusted")
def control_args_untrusted(ctx: CallContext, params: dict[str, Any]) -> tuple[bool, str]:
    bad = [a for a in ctx.control_attributions() if a.integrity is Integrity.UNTRUSTED]
    if not bad:
        return False, ""
    parts = []
    for a in bad:
        origin = (
            ", ".join(f"{s} ({ctx.ledger.get(s).source})" for s in a.sources)
            or "model output after untrusted content"
        )
        parts.append(f"{a.path}={a.value[:60]!r} traced to {origin} via {a.method}")
    return True, "; ".join(parts)


def _destination_approved(ctx: CallContext) -> tuple[bool, str]:
    controls = ctx.control_attributions()
    if any(a.integrity is Integrity.UNTRUSTED for a in controls):
        return False, "destination is untrusted"
    for a in controls:
        if any(ctx.ledger.get(s).kind == "user" for s in a.sources):
            continue
        dests = destination_entities(extract_entities(a.value))
        if dests and all(ctx.destination_allowed(d) for d in dests):
            continue
        return False, f"{a.path}={a.value[:60]!r} was not given by the user and is not allowlisted"
    return True, ""


@predicate("sensitive_data_to_unapproved_destination")
def sensitive_data_to_unapproved_destination(
    ctx: CallContext, params: dict[str, Any]
) -> tuple[bool, str]:
    level = Confidentiality.parse(params.get("level", "sensitive"))
    sensitive = [
        a for a in ctx.attributions.values() if a.confidentiality >= level and a.method != "trivial"
    ]
    if not sensitive:
        return False, ""
    approved, why = _destination_approved(ctx)
    if approved:
        return False, ""
    paths = ", ".join(a.path for a in sensitive)
    return True, f"{level} data in [{paths}]; {why}"


@predicate("session_tainted")
def session_tainted(ctx: CallContext, params: dict[str, Any]) -> tuple[bool, str]:
    if ctx.ledger.tainted():
        sources = sorted({s.source for s in ctx.ledger if s.label.integrity is Integrity.UNTRUSTED})
        return True, "context contains untrusted content from " + ", ".join(sources)
    return False, ""


@predicate("session_has_flagged_span")
def session_has_flagged_span(ctx: CallContext, params: dict[str, Any]) -> tuple[bool, str]:
    flagged = ctx.ledger.flagged()
    if flagged:
        return True, "detector flagged " + ", ".join(f"{s.id} ({s.source})" for s in flagged)
    return False, ""


@predicate("args_from_flagged_span")
def args_from_flagged_span(ctx: CallContext, params: dict[str, Any]) -> tuple[bool, str]:
    """Arguments copied from content the detector flagged.

    ``scope: control`` (default) checks only target-choosing arguments; ``scope: any`` also checks
    payloads, which is stricter but blocks benign messages that quote a flagged page.
    """
    pool = ctx.attributions.values() if params.get("scope") == "any" else ctx.control_attributions()
    hits = [a for a in pool if a.from_flagged]
    if hits:
        return True, "arguments copied from flagged content: " + ", ".join(a.path for a in hits)
    return False, ""


@predicate("server_untrusted")
def server_untrusted(ctx: CallContext, params: dict[str, Any]) -> tuple[bool, str]:
    if ctx.server_label.integrity is Integrity.UNTRUSTED:
        return True, f"server {ctx.server} is untrusted"
    return False, ""


@predicate("data_args_carry_untrusted_destinations")
def data_args_carry_untrusted_destinations(
    ctx: CallContext, params: dict[str, Any]
) -> tuple[bool, str]:
    """Outbound payload contains an address or link that only untrusted content supplied.

    Catches content injection into trusted channels: the destination is fine, but the attacker gets a
    phishing link or a payee address into the message body.
    """
    controls = {id(a) for a in ctx.control_attributions()}
    found: list[str] = []
    for a in ctx.attributions.values():
        if id(a) in controls or a.method == "trivial":
            continue
        for entity in destination_entities(extract_entities(a.value)):
            hits = [s for s in ctx.ledger if entity in s.entities]
            if hits and all(s.label.integrity is Integrity.UNTRUSTED for s in hits):
                found.append(f"{a.path} carries {entity} from {hits[0].source}")
            elif not hits and ctx.ledger.tainted():
                found.append(f"{a.path} carries {entity} first seen after untrusted content")
    return (True, "; ".join(found)) if found else (False, "")
