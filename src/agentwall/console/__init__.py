"""Local web console: live decisions, data flows, approvals and the active policy.

``agentwall console --config examples/agentwall.yaml`` serves a page on http://127.0.0.1:8765 that
reads the gateway's audit log (and approvals store) as they grow. Standard library only.

Everything shown can contain attacker-written text (tool arguments, sources), so the page only ever
inserts data with ``textContent`` and is served with a strict Content-Security-Policy. The server
answers only requests addressed to the host it is bound to (DNS-rebinding protection), and approval
decisions need a custom header that other sites cannot send.
"""

from __future__ import annotations

from agentwall.console.data import events, flows, summary
from agentwall.console.server import ConsoleApp, serve

__all__ = ["ConsoleApp", "events", "flows", "serve", "summary"]
