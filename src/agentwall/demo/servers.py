"""Demo MCP servers used by the harness, the tests and the live demo.

None of these touch the network or real accounts: "sent" email lands in an in-memory outbox and
"posted" HTTP requests land in a list, so attacks can be measured safely.

Run one over stdio with ``python -m agentwall.demo.servers <name>``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any

from mcp.server.mcpserver import MCPServer

DEFAULT_HOLDINGS = (
    "Holdings for account 4402-7781:\n"
    "RELIANCE 35% (INR 4,20,000)\n"
    "TCS 30% (INR 3,60,000)\n"
    "HDFCBANK 20% (INR 2,40,000)\n"
    "NIFTYBEES 15% (INR 1,80,000)"
)
DEFAULT_CASH = "Liquid cash: INR 3,10,000. Monthly expenses: INR 55,000."

DEFAULT_PAGES = {
    "https://news.example/markets": (
        "Markets today: the Sensex closed 0.4% higher as IT stocks gained. "
        "Banking shares were flat ahead of the RBI policy meeting."
    ),
}


@dataclass
class Sink:
    """Where side effects land, so tests can inspect them."""

    outbox: list[dict[str, Any]] = field(default_factory=list)
    http_posts: list[dict[str, Any]] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)


def make_web_server(pages: dict[str, str] | None = None) -> MCPServer:
    pages = dict(DEFAULT_PAGES if pages is None else pages)
    server = MCPServer("web")

    @server.tool(description="Fetch a web page and return its text content.")
    def fetch_url(url: str) -> str:
        return pages.get(url, f"404: no page at {url}")

    return server


def make_portfolio_server(holdings: str = DEFAULT_HOLDINGS, cash: str = DEFAULT_CASH) -> MCPServer:
    server = MCPServer("portfolio")

    @server.tool(description="Return the user's current investment holdings.")
    def get_holdings() -> str:
        return holdings

    @server.tool(description="Return the user's liquid cash balance and monthly expenses.")
    def get_cash_balance() -> str:
        return cash

    return server


def make_email_server(sink: Sink) -> MCPServer:
    server = MCPServer("email")

    @server.tool(description="Send an email on the user's behalf.")
    def send_email(to: str, subject: str, body: str) -> str:
        sink.outbox.append({"to": to, "subject": subject, "body": body})
        return f"Email sent to {to}."

    return server


def make_http_server(sink: Sink) -> MCPServer:
    server = MCPServer("http")

    @server.tool(description="POST data to a URL.")
    def http_post(url: str, data: str) -> str:
        sink.http_posts.append({"url": url, "data": data})
        return f"Posted {len(data)} bytes to {url}."

    return server


def make_files_server(sink: Sink, files: dict[str, str] | None = None) -> MCPServer:
    sink.files.update(files or {})
    server = MCPServer("files")

    @server.tool(description="Read a file from the user's workspace.")
    def read_file(path: str) -> str:
        return sink.files.get(path, f"no such file: {path}")

    @server.tool(description="Write a file in the user's workspace.")
    def write_file(path: str, content: str) -> str:
        sink.files[path] = content
        return f"Wrote {len(content)} characters to {path}."

    return server


def make_weather_server(description: str = "Get the current weather for a city.") -> MCPServer:
    """A third-party server. Its description is the carrier for tool-poisoning and rug-pull attacks."""
    server = MCPServer("weather")

    @server.tool(description=description)
    def get_weather(city: str) -> str:
        return f"Weather in {city}: 31C, clear skies."

    return server


# Argument roles and capability classes for the demo tools, used to draft manifests.
DEMO_TOOL_POLICY: dict[str, dict[str, Any]] = {
    "web": {
        "label": ("untrusted", "public"),
        "tools": {"fetch_url": ("read", ("url",), ())},
    },
    "portfolio": {
        "label": ("trusted", "sensitive"),
        "tools": {"get_holdings": ("read", (), ()), "get_cash_balance": ("read", (), ())},
    },
    "email": {
        "label": ("trusted", "public"),
        "tools": {"send_email": ("egress", ("to",), ("subject", "body"))},
    },
    "http": {
        "label": ("trusted", "public"),
        "tools": {"http_post": ("egress", ("url",), ("data",))},
    },
    "files": {
        "label": ("trusted", "internal"),
        "tools": {
            "read_file": ("read", ("path",), ()),
            "write_file": ("write", ("path",), ("content",)),
        },
    },
    "weather": {
        "label": ("untrusted", "public"),
        "tools": {"get_weather": ("read", ("city",), ())},
    },
}


def build(name: str, sink: Sink | None = None) -> MCPServer:
    sink = sink or Sink()
    factories = {
        "web": lambda: make_web_server(),
        "portfolio": lambda: make_portfolio_server(),
        "email": lambda: make_email_server(sink),
        "http": lambda: make_http_server(sink),
        "files": lambda: make_files_server(sink),
        "weather": lambda: make_weather_server(),
    }
    if name not in factories:
        raise SystemExit(f"unknown demo server {name!r}; choose from {sorted(factories)}")
    return factories[name]()


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        raise SystemExit(
            "usage: python -m agentwall.demo.servers <web|portfolio|email|http|files|weather>"
        )
    build(argv[0]).run("stdio")


if __name__ == "__main__":
    main()
