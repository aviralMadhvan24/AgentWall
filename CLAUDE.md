# AgentWall

Provenance-aware security gateway for MCP agents. Full design: @docs/SPEC.md. Threat model: @docs/threat_model.md.

# Commands
- Install: `pip install -e ".[dev]"`
- Tests (fast): `pytest -q -m "not slow"`; one file: `pytest tests/test_policy.py -q`
- Lint/format: `ruff check --fix src tests && ruff format src tests`
- Harness (quick): `agentwall bench --suite quick`; full ablation: `agentwall bench --suite full`
- Run proxy: `agentwall serve --config examples/agentwall.yaml`
- Real model: `agentwall bench --agent gemini` / `agentwall dojo` (needs `GEMINI_API_KEY`, `pip install -e ".[agentdojo]"`); add `--replay-only` to rebuild from the cache without a key
- Adaptive attacks: `agentwall adaptive` (rules) or `--mutator gemini`; fixed rewrites run as `agentwall bench --suite adaptive`
- Ops: `agentwall approvals list`, `agentwall simulate --audit <log> --policy <draft>`, `agentwall console --config <yaml>`

# Rules
- Python >= 3.10 (no StrEnum, no `type` statements). `from __future__ import annotations` in every module.
- Core packages (labels, provenance, policy, registry, detector, audit) must not import `mcp`. Only `gateway/` and `demo/` touch the SDK.
- Never call real email, payment or HTTP endpoints. Demo servers in `src/agentwall/demo/` and AgentDojo's simulated environments are the only tool backends. The Gemini API is the only network call, and only for model inference.
- Never edit `results/*/cache.jsonl` or `results/agentdojo/runs.jsonl` by hand, and don't change AgentDojo manifests in `integrations/agentdojo/manifests.py` after seeing results.
- Console page (`console/static/app.js`): render data with `textContent` only. Tool arguments are attacker-controlled; a test fails on `innerHTML` and friends.
- Anything that changes what the audit log records must keep `tests/test_simulator.py` fidelity at zero changed decisions.
- Every new policy predicate or attack class needs a unit test AND a harness scenario.
- IMPORTANT: a change that raises attack success rate or false-positive rate on `--suite quick` is a regression. Run the quick harness before committing gateway/policy changes and paste the numbers in the commit message.
- Don't tune the detector on `split: test` scenarios. Test phrasings stay held out.

# Gotchas
- mcp SDK is 2.x: `MCPServer` (not FastMCP), `mcp.Client(...)` for in-memory clients, lowlevel `Server(on_list_tools=..., on_call_tool=...)`.
- Tool names exposed by the proxy are namespaced `server__tool`.
- In proxy mode the gateway never sees the user's prompt; values first seen before any untrusted span count as trusted. See docs/SPEC.md "Proxy-mode limitation".
