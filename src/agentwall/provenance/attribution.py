"""Argument attribution: trace each tool-call argument back to the context spans it came from.

Matching runs cheapest first: exact substring, normalised substring, exact-value entities, then fuzzy
for long text. A value with no source was produced by the model and inherits the session's low-water
integrity and maximum confidentiality (the conservative fallback).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from rapidfuzz import fuzz

from agentwall.labels import Confidentiality, Integrity
from agentwall.provenance.entities import extract_entities
from agentwall.provenance.ledger import Ledger, Span
from agentwall.provenance.normalize import normalize

MIN_VALUE_LEN = 3
FUZZY_MIN_LEN = 40
FUZZY_THRESHOLD = 90.0

METHODS = ("trivial", "exact", "normalized", "entity", "fuzzy", "none", "disabled")


@dataclass(frozen=True)
class ValueAttribution:
    path: str
    value: str
    integrity: Integrity
    confidentiality: Confidentiality
    method: str
    sources: tuple[str, ...]
    from_flagged: bool = False

    def to_dict(self) -> dict[str, object]:
        preview = self.value if len(self.value) <= 80 else self.value[:77] + "..."
        return {
            "path": self.path,
            "value": preview,
            "integrity": str(self.integrity),
            "confidentiality": str(self.confidentiality),
            "method": self.method,
            "sources": list(self.sources),
            "from_flagged": self.from_flagged,
        }


def flatten(args: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Yield (path, leaf) pairs: ``{"a": {"b": [1]}}`` gives ``("a.b[0]", 1)``."""
    if isinstance(args, Mapping):
        for key, value in args.items():
            yield from flatten(value, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(args, (list, tuple)):
        for i, value in enumerate(args):
            yield from flatten(value, f"{prefix}[{i}]")
    else:
        yield prefix, args


def root_arg(path: str) -> str:
    """Top-level argument name of a flattened path: ``to[0]`` and ``to.x`` give ``to``."""
    return path.split(".", 1)[0].split("[", 1)[0]


def _summarise(path: str, value: str, spans: list[Span], method: str) -> ValueAttribution:
    return ValueAttribution(
        path=path,
        value=value,
        integrity=Integrity(max(s.label.integrity for s in spans)),
        confidentiality=Confidentiality(max(s.label.confidentiality for s in spans)),
        method=method,
        sources=tuple(dict.fromkeys(s.id for s in spans)),
        # Like integrity: a value the user typed is the user's, even if flagged content repeats it
        # (e.g. a tool's "Email sent to <the user's contact>" confirmation).
        from_flagged=any(s.flagged for s in spans) and not any(s.kind == "user" for s in spans),
    )


def _fallback(path: str, value: str, ledger: Ledger, method: str) -> ValueAttribution:
    return ValueAttribution(
        path, value, ledger.low_water(), ledger.max_confidentiality(), method, ()
    )


def attribute_value(path: str, raw: Any, ledger: Ledger) -> ValueAttribution:
    if raw is None or isinstance(raw, bool):
        return ValueAttribution(
            path, str(raw), Integrity.TRUSTED, Confidentiality.PUBLIC, "trivial", ()
        )
    value = str(raw)
    if len(value.strip()) < MIN_VALUE_LEN:
        return ValueAttribution(
            path, value, Integrity.TRUSTED, Confidentiality.PUBLIC, "trivial", ()
        )

    spans = list(ledger)

    # Entities are checked first and independently: every address-like value inside the argument
    # must be justified by a trusted source, otherwise the whole argument is untrusted.
    entities = extract_entities(value)
    if entities:
        per_entity: list[ValueAttribution] = []
        for entity in sorted(entities):
            hits = [s for s in spans if entity in s.entities]
            if hits:
                per_entity.append(_summarise(path, value, hits, "entity"))
            else:
                per_entity.append(_fallback(path, value, ledger, "none"))
        worst = min(per_entity, key=lambda a: a.integrity)
        if worst.integrity is Integrity.UNTRUSTED:
            return worst

    exact = [s for s in spans if value in s.text]
    if exact:
        return _summarise(path, value, exact, "exact")

    norm = normalize(value)
    if len(norm) >= MIN_VALUE_LEN:
        normalized = [s for s in spans if norm in s.norm]
        if normalized:
            return _summarise(path, value, normalized, "normalized")

    if entities:
        hits = [s for s in spans if entities & s.entities]
        if hits:
            return _summarise(path, value, hits, "entity")

    if len(norm) >= FUZZY_MIN_LEN:
        fuzzy = [s for s in spans if fuzz.partial_ratio(norm, s.norm) >= FUZZY_THRESHOLD]
        if fuzzy:
            return _summarise(path, value, fuzzy, "fuzzy")

    return _fallback(path, value, ledger, "none")


def attribute_args(
    args: Mapping[str, Any], ledger: Ledger, *, enabled: bool = True
) -> dict[str, ValueAttribution]:
    """Attribute every leaf value in ``args``.

    With ``enabled=False`` (the low-water-mark-only ablation) every non-trivial value simply takes the
    session's low-water integrity and maximum confidentiality.
    """
    result: dict[str, ValueAttribution] = {}
    for path, raw in flatten(args):
        if enabled:
            result[path] = attribute_value(path, raw, ledger)
            continue
        value = "" if raw is None else str(raw)
        if raw is None or isinstance(raw, bool) or len(value.strip()) < MIN_VALUE_LEN:
            result[path] = ValueAttribution(
                path, value, Integrity.TRUSTED, Confidentiality.PUBLIC, "trivial", ()
            )
        else:
            result[path] = _fallback(path, value, ledger, "disabled")
    return result
