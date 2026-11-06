"""Text normalisation used before matching values against context spans.

Attackers hide values with Unicode tricks so that naive substring checks miss them. Everything that is
compared goes through :func:`normalize` first.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Zero-width and invisible formatting characters commonly used to split keywords.
_INVISIBLE = dict.fromkeys(
    [
        0x200B,
        0x200C,
        0x200D,
        0x200E,
        0x200F,
        0x2060,
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0xFEFF,
        0x00AD,
    ],
    None,
)

# Common Cyrillic/Greek homoglyphs of Latin letters (lowercase; applied after casefold).
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "ο": "o",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "τ": "t",
        "υ": "u",
    }
)

_WS = re.compile(r"\s+")
_AT = re.compile(r"\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|\{\s*at\s*\}|\s+at\s+)\s*", re.IGNORECASE)
_DOT = re.compile(r"\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\{\s*dot\s*\}|\s+dot\s+)\s*", re.IGNORECASE)
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def strip_invisible(text: str) -> str:
    return text.translate(_INVISIBLE)


def normalize(text: str) -> str:
    """NFKC, drop invisible characters, casefold, map homoglyphs, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    text = text.casefold().translate(_CONFUSABLES)
    return _WS.sub(" ", text).strip()


def deobfuscate(text: str) -> str:
    """Undo 'name [at] host [dot] com' style address obfuscation."""
    return _DOT.sub(".", _AT.sub("@", text))


def decoded_base64_segments(text: str, min_printable: float = 0.9) -> list[str]:
    """Return printable UTF-8 strings hidden in base64 runs inside ``text``."""
    out: list[str] = []
    for match in _B64.finditer(text):
        chunk = match.group(0)
        padded = chunk + "=" * (-len(chunk) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if not decoded:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in decoded) / len(decoded)
        if printable >= min_printable and any(ch.isalpha() for ch in decoded):
            out.append(decoded)
    return out
