"""Extraction of exact-value entities (the things attacks need to control).

An attacker who wants data sent to them must get an exact address into a tool argument: an email,
a URL, a domain, an account number or a file path. Those values survive paraphrasing, so they are
the most reliable thing to trace back to their source.
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from agentwall.provenance.normalize import deobfuscate, normalize

_EMAIL = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|in|co|example|dev|xyz|ru|info|biz|app)\b"
)
_ACCOUNT = re.compile(r"\b\d{9,18}\b")
_IBAN = re.compile(r"\b[a-z]{2}\d{2}[a-z0-9]{11,30}\b", re.IGNORECASE)
_PATH = re.compile(r"(?:(?<=\s)|^)(?:/[\w.\-]+){2,}|[a-z]:\\(?:[\w.\- ]+\\?)+", re.IGNORECASE)


def _canon_url(url: str) -> str:
    url = unquote(url).rstrip(".,;:)]}>")
    parts = urlsplit(url)
    host = (parts.hostname or "").removeprefix("www.")
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"url:{host}{path}{query}"


def _canon_domain(domain: str) -> str:
    return "domain:" + domain.lower().removeprefix("www.").rstrip(".")


def extract_entities(text: str) -> frozenset[str]:
    """Return canonical entity keys such as ``email:a@b.com`` or ``domain:b.com``."""
    if not text:
        return frozenset()
    norm = deobfuscate(normalize(unquote(text)))
    found: set[str] = set()
    for m in _EMAIL.finditer(norm):
        email = m.group(0).rstrip(".")
        found.add("email:" + email)
        found.add(_canon_domain(email.split("@", 1)[1]))
    for m in _URL.finditer(norm):
        found.add(_canon_url(m.group(0)))
        host = urlsplit(m.group(0)).hostname
        if host:
            found.add(_canon_domain(host))
    for m in _DOMAIN.finditer(norm):
        found.add(_canon_domain(m.group(0)))
    for m in _ACCOUNT.finditer(norm):
        found.add("acct:" + m.group(0))
    for m in _IBAN.finditer(norm):
        found.add("acct:" + m.group(0).lower())
    for m in _PATH.finditer(norm):
        found.add("path:" + m.group(0).strip())
    return frozenset(found)


def destination_entities(entities: frozenset[str]) -> frozenset[str]:
    """Entities that name a place data can be sent to.

    Domains derived from an email or URL are implied by it, so they are only returned when no more
    specific destination (email, URL, account) is present.
    """
    specific = frozenset(e for e in entities if e.startswith(("email:", "url:", "acct:")))
    if specific:
        return specific
    return frozenset(e for e in entities if e.startswith("domain:"))
