"""Expose a :class:`Gateway` as a single MCP server over stdio.

The agent host connects to AgentWall instead of to each server. AgentWall lists the approved tools of
every downstream server (namespaced ``server__tool``) and runs each call through the gateway.
"""

from __future__ import annotations

from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from agentwall.gateway.core import Gateway, Session


def build_proxy_server(gateway: Gateway, name: str = "agentwall") -> Server[Any]:
    state: dict[str, Session] = {}

    async def session() -> Session:
        if "s" not in state:
            if not gateway.tools:
                await gateway.refresh()
            state["s"] = gateway.new_session()
        return state["s"]

    async def on_list_tools(ctx: Any, params: Any) -> types.ListToolsResult:
        await gateway.refresh()
        await session()
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=t.qualified,
                    description=t.info.description,
                    input_schema=t.info.input_schema or {"type": "object"},
                )
                for t in gateway.visible_tools()
            ]
        )

    async def on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        sess = await session()
        outcome = await sess.call_tool(params.name, dict(params.arguments or {}))
        is_error = not outcome.executed or bool(outcome.result and outcome.result.is_error)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=outcome.message_for_agent())],
            is_error=is_error,
        )

    return Server(name, on_list_tools=on_list_tools, on_call_tool=on_call_tool)


async def serve_stdio(gateway: Gateway) -> None:
    server = build_proxy_server(gateway)
    async with gateway, stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def run_stdio(gateway: Gateway) -> None:
    anyio.run(serve_stdio, gateway)
