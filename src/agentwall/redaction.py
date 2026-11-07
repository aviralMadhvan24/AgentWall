"""Find and mask secrets and personal data in text.

Used two ways:

- Outbound: a policy rule with ``action: redact`` masks matches in a tool call's arguments and lets the
  call go ahead. Values the user typed themselves are left alone (provenance decides, not the pattern).
- Inbound: ``redact_outputs`` masks matches in tool outputs before they enter the agent's context.

Kinds are grouped: ``secrets`` (API keys, tokens, private keys, password assignments) and ``pii``
(emails, phone numbers, card numbers, government ids). Groups and single kinds can be mixed.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass


def _luhn_ok(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass(frozen=True)
class Pattern:
    kind: str
    group: str
    regex: re.Pattern[str]
    check: Callable[[str], bool] | None = None
    value_group: int = 0  # which regex group is the secret itself


PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        "private_key",
        "secrets",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    Pattern("aws_access_key", "secrets", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Pattern(
        "github_token",
        "secrets",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ),
    Pattern("google_api_key", "secrets", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Pattern(
        "openai_key", "secrets", re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}\b")
    ),
    Pattern("anthropic_key", "secrets", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    Pattern("slack_token", "secrets", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    Pattern("stripe_key", "secrets", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    Pattern(
        "jwt",
        "secrets",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    ),
    Pattern(
        "password_assignment",
        "secrets",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
            r"\s*[:=]\s*[\"']?([^\s\"']{6,})"
        ),
        value_group=1,
    ),
    Pattern("email", "pii", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    Pattern("credit_card", "pii", re.compile(r"\b(?:\d[ -]?){13,19}\b"), check=_luhn_ok),
    Pattern("us_ssn", "pii", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    Pattern("in_pan", "pii", re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
    # Exactly three groups of four: not the first twelve digits of a longer card number.
    Pattern("in_aadhaar", "pii", re.compile(r"(?<!\d)(?<!\d )\d{4} \d{4} \d{4}(?![ -]?\d)")),
    Pattern(
        "phone",
        "pii",
        re.compile(
            # International (+country code) or US-formatted numbers only, so amounts, dates and
            # card or id numbers are not mistaken for phones.
            r"(?<![\w+])(?:\+\d{1,3}[\s\-]?\d{2,5}[\s\-]?\d{3,5}(?:[\s\-]?\d{2,5})?"
            r"|\(\d{3}\)\s?\d{3}-\d{4}|\d{3}-\d{3}-\d{4})\b"
        ),
    ),
)

GROUPS = {"secrets", "pii"}
KINDS = {p.kind for p in PATTERNS}


def resolve_kinds(names: Iterable[str]) -> frozenset[str]:
    """Expand group names (``secrets``, ``pii``) into kinds; reject unknown names."""
    out: set[str] = set()
    for name in names:
        if name in GROUPS:
            out |= {p.kind for p in PATTERNS if p.group == name}
        elif name in KINDS:
            out.add(name)
        else:
            raise ValueError(f"unknown redaction kind {name!r}; use {sorted(GROUPS | KINDS)}")
    return frozenset(out)


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    value: str


def find(text: str, kinds: Iterable[str] = ("secrets",)) -> list[Finding]:
    """Non-overlapping matches of the given kinds, earliest and longest first."""
    wanted = resolve_kinds(kinds)
    found: list[Finding] = []
    for p in PATTERNS:
        if p.kind not in wanted:
            continue
        for m in p.regex.finditer(text):
            start, end = m.span(p.value_group)
            value = m.group(p.value_group)
            if p.check and not p.check(value):
                continue
            found.append(Finding(p.kind, start, end, value))
    found.sort(key=lambda f: (f.start, -(f.end - f.start)))
    kept: list[Finding] = []
    for f in found:
        if kept and f.start < kept[-1].end:
            continue
        kept.append(f)
    return kept


def mask(kind: str) -> str:
    return f"[REDACTED:{kind}]"


# One canonical value per secret kind, matching that kind's pattern and nothing real. The policy
# simulator substitutes these for masked audit values so a replay sees the same predicate results.
SAMPLES: dict[str, str] = {
    "private_key": "-----BEGIN PRIVATE KEY-----\nSAMPLE\n-----END PRIVATE KEY-----",
    "aws_access_key": "AKIA" + "A" * 16,
    "github_token": "ghp_" + "A" * 36,
    "google_api_key": "AIza" + "A" * 35,
    "openai_key": "sk-" + "A" * 20,
    "anthropic_key": "sk-ant-" + "A" * 20,
    "slack_token": "xoxb-" + "A" * 12,
    "stripe_key": "sk_live_" + "A" * 16,
    "jwt": "eyJ" + "A" * 10 + ".eyJ" + "A" * 10 + "." + "A" * 10,
    "password_assignment": "password: SAMPLEVALUE",
}


def sample(kind: str) -> str:
    return SAMPLES.get(kind, "")


def redact(
    text: str,
    kinds: Iterable[str] = ("secrets",),
    keep: Callable[[Finding], bool] | None = None,
) -> tuple[str, list[Finding]]:
    """Mask matches in ``text``. ``keep(finding)`` returning True leaves that match untouched."""
    findings = [f for f in find(text, kinds) if not (keep and keep(f))]
    out = text
    for f in reversed(findings):
        out = out[: f.start] + mask(f.kind) + out[f.end :]
    return out, findings
