"""Injection detectors. A detector is any callable ``text -> score in [0, 1]``."""

from __future__ import annotations

from collections.abc import Callable

from agentwall.detector.heuristic import HeuristicDetector

Detector = Callable[[str], float]


def build_detector(name: str = "heuristic", **kwargs: object) -> Detector:
    if name == "heuristic":
        return HeuristicDetector()
    if name in ("transformer", "ensemble"):
        from agentwall.detector.transformer import EnsembleDetector, TransformerDetector

        model = TransformerDetector(**kwargs)  # type: ignore[arg-type]
        return model if name == "transformer" else EnsembleDetector(HeuristicDetector(), model)
    raise ValueError(f"unknown detector {name!r}")


__all__ = ["Detector", "HeuristicDetector", "build_detector"]
