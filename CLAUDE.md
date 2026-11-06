# AgentWall

Provenance-aware security gateway for MCP agents. Full design: @docs/SPEC.md. Threat model: @docs/threat_model.md.

# Commands
- Install: `pip install -e ".[dev]"`
- Tests (fast): `pytest -q -m "not slow"`; one file: `pytest tests/test_policy.py -q`
- Lint/format: `ruff check --fix src tests && ruff format src tests`
- Harness (quick): `agentwall bench --suite quick`; full ablation: `agentwall bench --suite full`
- Run proxy: `agentwall serve --config examples/agentwall.yaml`

# Rules
- Python >= 3.10 (no StrEnum, no `type` statements). `from __future__ import annotations` in every module.
- Core packages (labels, provenance, policy, registry, detector, audit) must not import `mcp`. Only `gateway/` and `demo/` touch the SDK.
- Never call real email, payment or HTTP endpoints. Demo servers in `src/agentwall/demo/` are the only tool backends.
- Every new policy predicate or attack class needs a unit test AND a harness scenario.
- IMPORTANT: a change that raises attack success rate or false-positive rate on `--suite quick` is a regression. Run the quick harness before committing gateway/policy changes and paste the numbers in the commit message.
- Don't tune the detector on `split: test` scenarios. Test phrasings stay held out.

# Gotchas
- mcp SDK is 2.x: `MCPServer` (not FastMCP), `mcp.Client(...)` for in-memory clients, lowlevel `Server(on_list_tools=..., on_call_tool=...)`.
- Tool names exposed by the proxy are namespaced `server__tool`.
- In proxy mode the gateway never sees the user's prompt; values first seen before any untrusted span count as trusted. See docs/SPEC.md "Proxy-mode limitation".
