"""Rule-based prompt-injection detector.

A cheap first signal: weighted patterns for instructions aimed at an AI model, tool-call coercion,
secrecy demands and exfiltration requests, in English, Hindi and Hinglish. Scores combine as
``1 - prod(1 - w)`` over matched patterns, so several weak hints add up to a strong one.

This detector is a signal, not a verdict. The policy engine makes decisions from provenance; a flag only
downgrades a span to untrusted. Expect it to miss polite, well-paraphrased injections; that is exactly
what the ablation study measures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentwall.provenance.normalize import decoded_base64_segments, deobfuscate, normalize

_EMAIL = r"[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+"


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    weight: float


def _p(name: str, pattern: str, weight: float) -> Pattern:
    return Pattern(name, re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL), weight)


PATTERNS: tuple[Pattern, ...] = (
    _p(
        "override",
        r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}?\b(previous|prior|above|earlier|all|any|your)\b.{0,25}?\b(instructions?|rules|prompts?|directions?|guidelines)",
        0.9,
    ),
    _p(
        "role_reset",
        r"\b(you are now|from now on|new instructions?|updated instructions?|system override|developer mode|admin mode)\b",
        0.6,
    ),
    _p("fake_role_header", r"^\s*(system|assistant|ai|agent|developer)\s*:", 0.5),
    _p(
        "fake_tags",
        r"<\s*/?\s*(system|instructions?|important|admin|inst)\s*>|\[\s*(system|inst|admin)\s*\]",
        0.6,
    ),
    _p(
        "addressed_to_ai",
        r"\b(assistant|ai agent|ai model|language model|llm|claude|gpt|gemini|chatbot)\b.{0,40}?\b(must|should|needs? to|has to|is required to|please)\b",
        0.45,
    ),
    _p(
        "tool_coercion",
        r"\b(call|use|invoke|run|execute|trigger)\b.{0,20}?\b(the\s+)?\w*(send|email|post|upload|write|transfer|delete|http)\w*\s*(tool|function)?\b",
        0.35,
    ),
    _p(
        "exfil_email",
        rf"\b(send|forward|email|mail|upload|share|copy|transfer|exfiltrate|cc|bcc)\b.{{0,80}}?{_EMAIL}",
        0.5,
    ),
    _p("exfil_url", r"\b(send|forward|post|upload|share|submit)\b.{0,60}?https?://", 0.45),
    _p(
        "secrecy",
        r"\b(do not|don't|never|without)\b.{0,25}?\b(tell|telling|inform|informing|mention|mentioning|reveal|notify|notifying|asking|alert)\b.{0,25}?\b(user|human|owner|anyone)\b",
        0.6,
    ),
    _p(
        "urgency_override",
        r"\b(immediately|right now|urgent|before (responding|answering|anything else))\b.{0,60}?\b(send|forward|call|run|transfer)\b",
        0.35,
    ),
    _p(
        "sensitive_targets",
        r"\b(holdings|portfolio|password|api key|secret|token|credentials|bank details|account number)\b.{0,60}?\b(send|forward|post|upload|share)\b|\b(send|forward|post|upload|share)\b.{0,60}?\b(holdings|portfolio|password|api key|secret|token|credentials|bank details)\b",
        0.35,
    ),
    # Hindi (Devanagari) and Hinglish
    _p(
        "hi_override",
        r"(पिछले|पहले|पुराने|सभी).{0,25}(निर्देश|निर्देशों|आदेश).{0,25}(अनदेखा|भूल|नज़रअंदाज़|नजरअंदाज)",
        0.9,
    ),
    _p("hi_send", rf"(भेज|भेजो|भेजें|फॉरवर्ड).{{0,60}}{_EMAIL}|{_EMAIL}.{{0,60}}(भेज|भेजो|भेजें|फॉरवर्ड)", 0.5),
    _p(
        "hinglish_override",
        r"\b(pichle|pehle|purane|saare|sabhi)\b.{0,25}\b(instructions?|nirdesh|rules)\b.{0,25}\b(ignore|bhool|bhul|bhulo|chhod)\w*",
        0.9,
    ),
    _p(
        "hinglish_send",
        rf"\b(bhej|bhejo|bhejdo|bhej do|forward kar|send kar)\w*\b.{{0,60}}{_EMAIL}|{_EMAIL}.{{0,60}}\b(bhej|bhejo|bhejdo|bhej do|par bhej|pe bhej)\w*",
        0.5,
    ),
    _p(
        "hinglish_secrecy",
        r"\b(user|malik)\b.{0,20}\b(ko mat|ko na)\b.{0,20}\b(batana|batao|bolna)\b",
        0.6,
    ),
)

_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")


class HeuristicDetector:
    name = "heuristic"

    def __init__(self, patterns: tuple[Pattern, ...] = PATTERNS) -> None:
        self.patterns = patterns

    def matches(self, text: str) -> list[str]:
        prepared = deobfuscate(normalize(text))
        return [p.name for p in self.patterns if p.regex.search(prepared)]

    def score(self, text: str, _depth: int = 0) -> float:
        if not text:
            return 0.0
        miss = 1.0
        weights = {p.name: p.weight for p in self.patterns}
        for name in self.matches(text):
            miss *= 1.0 - weights[name]
        if len(_ZERO_WIDTH.findall(text)) >= 2:
            miss *= 0.7
        if _depth == 0:
            for decoded in decoded_base64_segments(text):
                if self.score(decoded, _depth=1) >= 0.5:
                    miss *= 0.2
        return round(1.0 - miss, 4)

    def __call__(self, text: str) -> float:
        return self.score(text)
