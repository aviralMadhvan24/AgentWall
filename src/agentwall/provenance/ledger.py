"""Per-session provenance ledger: every piece of text that entered the agent's context, with its label."""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from agentwall.labels import Confidentiality, Integrity, Label
from agentwall.provenance.entities import extract_entities
from agentwall.provenance.normalize import decoded_base64_segments, normalize

# A detector returns a score in [0, 1]; higher means more likely to contain injected instructions.
DetectorFn = Callable[[str], float]

SPAN_KINDS = ("user", "system", "tool_output", "tool_description", "model", "derived")


@dataclass
class Span:
    id: str
    kind: str
    source: str
    text: str
    label: Label
    seq: int
    flagged: bool = False
    detector_score: float = 0.0
    parent: str | None = None
    norm: str = field(init=False, repr=False)
    entities: frozenset[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.kind not in SPAN_KINDS:
            raise ValueError(f"unknown span kind {self.kind!r}")
        self.norm = normalize(self.text)
        self.entities = extract_entities(self.text)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "kind": self.kind,
            "source": self.source,
            "label": str(self.label),
            "flagged": self.flagged,
            "detector_score": round(self.detector_score, 3),
            "parent": self.parent,
            "chars": len(self.text),
        }


class Ledger:
    """Ordered record of labelled spans for one agent session."""

    def __init__(self, detector: DetectorFn | None = None, flag_threshold: float = 0.5) -> None:
        self._spans: list[Span] = []
        self._ids = itertools.count(1)
        self._detector = detector
        self._threshold = flag_threshold

    def __iter__(self) -> Iterator[Span]:
        return iter(self._spans)

    def __len__(self) -> int:
        return len(self._spans)

    def get(self, span_id: str) -> Span:
        for span in self._spans:
            if span.id == span_id:
                return span
        raise KeyError(span_id)

    def add(
        self, text: str, *, kind: str, source: str, label: Label, scan: bool | None = None
    ) -> Span:
        """Record text entering the context.

        Tool outputs and descriptions are scanned by the detector (when configured). A flagged span is
        downgraded to untrusted whatever its server's manifest says. Base64 runs inside the text are
        decoded and recorded as derived spans with the same label, so hidden values stay traceable.
        """
        should_scan = scan if scan is not None else kind in ("tool_output", "tool_description")
        score = 0.0
        if should_scan and self._detector is not None:
            score = float(self._detector(text))
        flagged = score >= self._threshold
        if flagged:
            label = Label(Integrity.UNTRUSTED, label.confidentiality)
        span = self._append(text, kind, source, label, flagged, score, None)
        for decoded in decoded_base64_segments(text):
            self._append(decoded, "derived", source, label, flagged, score, span.id)
        return span

    def _append(
        self,
        text: str,
        kind: str,
        source: str,
        label: Label,
        flagged: bool,
        score: float,
        parent: str | None,
    ) -> Span:
        n = next(self._ids)
        span = Span(f"s{n}", kind, source, text, label, n, flagged, score, parent)
        self._spans.append(span)
        return span

    def low_water(self) -> Integrity:
        """Lowest integrity of anything in context. Trusted while the context is clean."""
        return Integrity(min((s.label.integrity for s in self._spans), default=Integrity.TRUSTED))

    def max_confidentiality(self) -> Confidentiality:
        return Confidentiality(
            max((s.label.confidentiality for s in self._spans), default=Confidentiality.PUBLIC)
        )

    def tainted(self) -> bool:
        return self.low_water() is Integrity.UNTRUSTED

    def flagged(self) -> list[Span]:
        return [s for s in self._spans if s.flagged]
