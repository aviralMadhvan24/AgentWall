"""Tool backends: the downstream MCP servers the gateway forwards allowed calls to."""

from __future__ import annotations

from contextlib import AsyncExitStack
from typing import Any, Protocol

from mcp import Client, StdioServerParameters

from agentwall.types import ToolInfo, ToolResult


class Backend(Protocol):
    name: str

    async def list_tools(self) -> list[ToolInfo]: ...

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> ToolResult: ...


def result_text(result: Any) -> str:
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        parts.append(text if text is not None else f"[{getattr(block, 'type', 'content')}]")
    return "\n".join(parts)


class MCPBackend:
    """A downstream MCP server reached through the official SDK client.

    ``target`` can be an in-process ``MCPServer`` (tests, harness) or ``StdioServerParameters``
    (a real subprocess). Use as an async context manager, or call :meth:`start` and :meth:`stop`.
    """

    def __init__(self, name: str, target: Any) -> None:
        if "__" in name:
            raise ValueError("backend names may not contain '__' (used as the namespace separator)")
        self.name = name
        self._target = target
        self._stack: AsyncExitStack | None = None
        self._client: Any = None

    @classmethod
    def stdio(
        cls, name: str, command: str, args: list[str], env: dict[str, str] | None = None
    ) -> MCPBackend:
        return cls(name, StdioServerParameters(command=command, args=args, env=env))

    async def start(self) -> None:
        if self._client is not None:
            return
        self._stack = AsyncExitStack()
        self._client = await self._stack.enter_async_context(Client(self._target))

    async def stop(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack, self._client = None, None

    async def __aenter__(self) -> MCPBackend:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    async def list_tools(self) -> list[ToolInfo]:
        await self.start()
        listing = await self._client.list_tools()
        return [
            ToolInfo(t.name, t.description or "", dict(t.input_schema or {})) for t in listing.tools
        ]

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> ToolResult:
        await self.start()
        result = await self._client.call_tool(tool, arguments)
        return ToolResult(result_text(result), bool(getattr(result, "is_error", False)))
