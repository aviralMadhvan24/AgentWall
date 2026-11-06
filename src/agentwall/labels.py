"""Security labels for information-flow control.

Two independent axes, borrowed from the Biba (integrity) and Bell-LaPadula (confidentiality) models:

- Integrity answers: may this data give instructions or choose targets?
- Confidentiality answers: may this data leave the system?

Derived data takes the *join* of its inputs: the lowest integrity and the highest confidentiality.
Labels only ever get worse through a join, never better.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Integrity(IntEnum):
    UNTRUSTED = 0
    TRUSTED = 1

    @classmethod
    def parse(cls, value: str | Integrity) -> Integrity:
        if isinstance(value, Integrity):
            return value
        return cls[value.strip().upper()]

    def __str__(self) -> str:
        return self.name.lower()


class Confidentiality(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SENSITIVE = 2

    @classmethod
    def parse(cls, value: str | Confidentiality) -> Confidentiality:
        if isinstance(value, Confidentiality):
            return value
        return cls[value.strip().upper()]

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Label:
    integrity: Integrity
    confidentiality: Confidentiality

    def join(self, other: Label) -> Label:
        """Combine two labels for derived data: least trusted, most sensitive."""
        return Label(
            Integrity(min(self.integrity, other.integrity)),
            Confidentiality(max(self.confidentiality, other.confidentiality)),
        )

    @classmethod
    def parse(cls, integrity: str, confidentiality: str) -> Label:
        return cls(Integrity.parse(integrity), Confidentiality.parse(confidentiality))

    def __str__(self) -> str:
        return f"{self.integrity}/{self.confidentiality}"


TRUSTED_PUBLIC = Label(Integrity.TRUSTED, Confidentiality.PUBLIC)
TRUSTED_SENSITIVE = Label(Integrity.TRUSTED, Confidentiality.SENSITIVE)
UNTRUSTED_PUBLIC = Label(Integrity.UNTRUSTED, Confidentiality.PUBLIC)
