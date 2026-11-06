"""Views over audit-log entries for the console. Pure functions, no I/O."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from agentwall.audit.log import verify_chain

ACTIONS = ("allow", "redact", "ask", "block")


def _preview(value: Any, limit: int = 160) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    calls = [e for e in entries if e.get("event") == "tool_call"]
    actions = Counter(e.get("action") for e in calls)
    by_tool: dict[str, Counter[str]] = defaultdict(Counter)
    for e in calls:
        by_tool[str(e.get("tool"))][str(e.get("action"))] += 1
    rules = Counter(r for e in calls for r in e.get("rules") or [])
    ok, bad = verify_chain(entries)
    return {
        "calls": len(calls),
        "actions": {a: actions.get(a, 0) for a in ACTIONS},
        "executed": sum(bool(e.get("executed")) for e in calls),
        "redacted": sum(bool(e.get("redactions")) for e in calls),
        "quarantined": sum(bool(e.get("quarantined")) for e in calls),
        "hidden_tools": sorted(
            {str(e.get("tool")) for e in entries if e.get("event") == "tool_hidden"}
        ),
        "sessions": len({e.get("session") for e in calls}),
        "tools": [
            {"tool": tool, **{a: counts.get(a, 0) for a in ACTIONS}}
            for tool, counts in sorted(by_tool.items(), key=lambda kv: -sum(kv[1].values()))
        ],
        "top_rules": rules.most_common(8),
        "chain_ok": ok,
        "chain_broken_at": bad,
        "last_seq": entries[-1].get("seq", 0) if entries else 0,
    }


def events(entries: list[dict[str, Any]], after: int = 0, limit: int = 200) -> list[dict[str, Any]]:
    """Tool calls and hidden tools after ``after`` (audit seq), oldest first, at most ``limit``."""
    out = []
    for e in entries:
        if e.get("seq", 0) <= after or e.get("event") not in ("tool_call", "tool_hidden"):
            continue
        if e["event"] == "tool_hidden":
            out.append(
                {
                    "seq": e.get("seq"),
                    "ts": e.get("ts"),
                    "event": "tool_hidden",
                    "tool": e.get("tool"),
                    "action": "hidden",
                    "reason": _preview(e.get("reason", "")),
                }
            )
            continue
        out.append(
            {
                "seq": e.get("seq"),
                "ts": e.get("ts"),
                "event": "tool_call",
                "session": e.get("session"),
                "tool": e.get("tool"),
                "action": e.get("action"),
                "executed": e.get("executed"),
                "rules": e.get("rules") or [],
                "redactions": e.get("redactions") or [],
                "quarantined": e.get("quarantined"),
                "approval": e.get("approval"),
                "args": [
                    {
                        "path": a.get("path"),
                        "value": _preview(a.get("value", "")),
                        "label": f"{a.get('integrity')}/{a.get('confidentiality')}",
                        "method": a.get("method"),
                        "flagged": bool(a.get("from_flagged")),
                    }
                    for a in e.get("attributions") or []
                ],
            }
        )
    return out[-limit:]


def flows(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Where tool arguments came from: source -> tool edges, counted by decision.

    A source is the span an argument was traced to (``user``, ``web/fetch_url``, ...). Arguments that
    matched nothing are attributed to ``model (no source)``.
    """
    sources: dict[tuple[str, str], str] = {}
    labels: dict[str, str] = {}
    edges: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for e in entries:
        if e.get("event") == "span":
            span = e["span"]
            source = "user" if span.get("kind") == "user" else str(span.get("source"))
            sources[(str(e.get("session")), str(span.get("id")))] = source
            labels[source] = str(span.get("label", ""))
        elif e.get("event") == "tool_call":
            tool = str(e.get("tool"))
            seen: set[str] = set()
            for a in e.get("attributions") or []:
                if a.get("method") == "trivial":
                    continue
                names = [sources.get((str(e.get("session")), s), s) for s in a.get("sources") or []]
                seen.update(names or ["model (no source)"])
            for name in seen:
                edges[(name, tool)][str(e.get("action"))] += 1
    return {
        "sources": sorted({s for s, _ in edges}),
        "tools": sorted({t for _, t in edges}),
        "labels": labels,
        "edges": [
            {"source": s, "tool": t, "counts": dict(c), "total": sum(c.values())}
            for (s, t), c in sorted(edges.items())
        ],
    }
