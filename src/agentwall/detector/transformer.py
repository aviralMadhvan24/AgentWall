"""Optional transformer-based injection classifier (install with ``pip install agentwall[ml]``).

Wraps a Hugging Face text-classification model trained for prompt-injection detection. The default is
ProtectAI's DeBERTa-v3 classifier; swap in your own fine-tuned checkpoint with ``model=``.
"""

from __future__ import annotations

from typing import Any

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
INJECTION_LABELS = {"INJECTION", "LABEL_1", "injection", "unsafe"}


class TransformerDetector:
    name = "transformer"

    def __init__(self, model: str = DEFAULT_MODEL, max_chars: int = 2000, device: int = -1) -> None:
        try:
            from transformers import pipeline
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("TransformerDetector needs `pip install agentwall[ml]`") from exc
        self._pipe: Any = pipeline(
            "text-classification", model=model, truncation=True, device=device
        )
        self.max_chars = max_chars

    def score(self, text: str) -> float:
        if not text:
            return 0.0
        chunks = [text[i : i + self.max_chars] for i in range(0, len(text), self.max_chars)] or [""]
        best = 0.0
        for result in self._pipe(chunks):
            score = float(result["score"])
            best = max(best, score if result["label"] in INJECTION_LABELS else 1.0 - score)
        return best

    def __call__(self, text: str) -> float:
        return self.score(text)


class EnsembleDetector:
    """Max over member detectors."""

    name = "ensemble"

    def __init__(self, *members: Any) -> None:
        self.members = members

    def __call__(self, text: str) -> float:
        return max((m(text) for m in self.members), default=0.0)
