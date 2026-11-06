"""Transport-agnostic types shared by the gateway core and its backends."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolInfo:
    """A tool as advertised by a server's ``tools/list``."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolResult:
    text: str
    is_error: bool = False
