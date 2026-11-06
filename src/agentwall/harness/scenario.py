"""Scenario model for the evaluation harness."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CARRIERS = ("web_page", "file", "tool_description", "rug_pull")


@dataclass(frozen=True)
class Step:
    """A tool call the user's task needs. ``args`` may reference earlier outputs as ``{{result:tool}}``."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Attack:
    carrier: str
    payload: str
    goal: Step
    values: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.carrier not in CARRIERS:
            raise ValueError(f"carrier must be one of {CARRIERS}")


@dataclass(frozen=True)
class Scenario:
    id: str
    category: str
    kind: str  # "attack" or "benign"
    split: str  # "train" or "test"
    user_prompt: str
    steps: tuple[Step, ...]
    pages: dict[str, str] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    attack: Attack | None = None
    phrasing: str = ""
    obfuscation: str = "plain"
    note: str = ""
