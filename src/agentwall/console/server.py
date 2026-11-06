"""HTTP server for the console (standard library ``http.server``)."""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from agentwall.approvals import ApprovalStore, approval_summary
from agentwall.audit.log import AuditLog
from agentwall.console.data import events, flows, summary

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
WRITE_HEADER = "X-AgentWall-Console"


class ConsoleApp:
    """Request handling without sockets, so it can be tested directly."""

    def __init__(
        self,
        audit_path: str | Path,
        approvals_path: str | Path | None = None,
        policy_text: str = "",
        policy_name: str = "",
    ) -> None:
        self.audit_path = Path(audit_path)
        self.store = ApprovalStore(approvals_path) if approvals_path else None
        self.policy_text = policy_text
        self.policy_name = policy_name
        self._cache: tuple[tuple[float, int], list[dict[str, Any]]] | None = None
        self._lock = threading.Lock()

    def entries(self) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        stat = self.audit_path.stat()
        key = (stat.st_mtime, stat.st_size)
        with self._lock:
            if self._cache is None or self._cache[0] != key:
                self._cache = (key, AuditLog(self.audit_path).entries)
            return self._cache[1]

    def get(self, path: str, query: dict[str, list[str]]) -> tuple[int, Any]:
        if path == "/api/summary":
            return 200, {**summary(self.entries()), "audit_path": str(self.audit_path)}
        if path == "/api/events":
            after = int((query.get("after") or ["0"])[0] or 0)
            limit = min(int((query.get("limit") or ["200"])[0] or 200), 1000)
            return 200, {"events": events(self.entries(), after, limit)}
        if path == "/api/flows":
            return 200, flows(self.entries())
        if path == "/api/approvals":
            if self.store is None:
                return 200, {"enabled": False, "requests": []}
            return 200, {
                "enabled": True,
                "requests": [approval_summary(r) for r in self.store.all()[-200:]][::-1],
            }
        if path == "/api/policy":
            return 200, {"name": self.policy_name, "text": self.policy_text}
        return 404, {"error": "not found"}

    def post(self, path: str, body: dict[str, Any]) -> tuple[int, Any]:
        prefix = "/api/approvals/"
        if not path.startswith(prefix):
            return 404, {"error": "not found"}
        if self.store is None:
            return 400, {"error": "no approvals store configured"}
        decision = body.get("decision")
        if decision not in ("approve", "deny"):
            return 400, {"error": "decision must be approve or deny"}
        try:
            req = self.store.decide(
                path[len(prefix) :], decision == "approve", bool(body.get("remember"))
            )
        except KeyError:
            return 404, {"error": "no such request"}
        return 200, {"request": asdict(req)}


def _handler(app: ConsoleApp, allowed_hosts: set[str]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentWallConsole"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, data: Any) -> None:
            self._send(status, json.dumps(data, default=str).encode("utf-8"), "application/json")

        def _host_ok(self) -> bool:
            # DNS-rebinding protection: only answer requests addressed to this server.
            if self.headers.get("Host", "") not in allowed_hosts:
                self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "unexpected Host header"})
                return False
            return True

        def do_GET(self) -> None:
            if not self._host_ok():
                return
            url = urlparse(self.path)
            if url.path in STATIC:
                name, content_type = STATIC[url.path]
                body = (resources.files("agentwall.console") / "static" / name).read_bytes()
                self._send(200, body, content_type)
                return
            status, data = app.get(url.path, parse_qs(url.query))
            self._json(status, data)

        def do_POST(self) -> None:
            if not self._host_ok():
                return
            # A custom header cannot be sent cross-origin without a CORS preflight, which this
            # server never approves: other sites cannot click buttons for you.
            if self.headers.get(WRITE_HEADER) != "1":
                self._json(HTTPStatus.FORBIDDEN, {"error": f"missing {WRITE_HEADER} header"})
                return
            length = min(int(self.headers.get("Content-Length") or 0), 65536)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON"})
                return
            status, data = app.post(
                urlparse(self.path).path, body if isinstance(body, dict) else {}
            )
            self._json(status, data)

    return Handler


def make_server(app: ConsoleApp, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _handler(app, set()))
    bound_port = server.server_address[1]
    names = {host, "127.0.0.1", "localhost"} if host in ("127.0.0.1", "localhost") else {host}
    allowed = {f"{name}:{bound_port}" for name in names}
    server.RequestHandlerClass = _handler(app, allowed)
    return server


def serve(app: ConsoleApp, host: str = "127.0.0.1", port: int = 8765) -> None:
    if host not in ("127.0.0.1", "localhost"):
        print(
            f"warning: the console has no login; binding to {host} exposes audit data on the network",
            file=sys.stderr,
        )
    server = make_server(app, host, port)
    print(f"AgentWall console on http://{host}:{server.server_address[1]}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
