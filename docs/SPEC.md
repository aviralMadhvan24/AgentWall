# AgentWall: specification

AgentWall sits between an AI agent and every MCP server it uses. It tracks where each piece of data in the
agent's context came from and blocks tool calls that untrusted content tries to steer.

## Problem

MCP gives agents no way to verify what a server may do, no record of where context text came from, and
implicit trust across every connected server. One malicious or compromised server can inject instructions that
make the agent misuse a different, trusted server's tools: cross-server prompt injection, tool poisoning and
rug pulls. A 2026 formal analysis (arXiv 2601.17549) found MCP's design raised attack success by 23-41% versus
equivalent non-MCP integrations across 847 scenarios.

## Scope of v0.1 (hackathon cut)

| # | Module | Package |
|---|---|---|
| 1 | MCP gateway (stdio proxy + in-process core) | `agentwall.gateway` |
| 2 | Provenance ledger and labels | `agentwall.labels`, `agentwall.provenance.ledger` |
| 3 | Argument attribution | `agentwall.provenance.attribution` |
| 4 | Policy engine (YAML rules over named predicates) | `agentwall.policy` |
| 5 | Manifest registry: Ed25519 signatures, description pins, rug-pull quarantine | `agentwall.registry` |
| 6 | Injection detector (heuristic; optional transformer) | `agentwall.detector` |
| 10 | Audit log (hash-chained JSONL) | `agentwall.audit` |
| 12 | Attack corpus generator | `agentwall.harness.corpus` |
| 13 | Evaluation harness with ablations | `agentwall.harness` |

Out of scope for v0.1: quarantine LLM, approvals UI, redaction, web console, policy simulator, multi-tenant.

## Labels

- Integrity: `untrusted < trusted`. May this data give instructions or choose targets?
- Confidentiality: `public < internal < sensitive`. May this data leave the system?
- Join (for derived data): minimum integrity, maximum confidentiality.
- User and system messages are trusted. Tool outputs take the label in their server's manifest.
- Session low-water mark: the minimum integrity of any span in the session.

## Argument attribution

For each leaf value in a tool call's arguments, find the context spans it could have come from:
exact substring, then normalised (NFKC, casefold, whitespace, zero-width removed), then entity match
(emails, URLs, domains, account numbers, paths), then fuzzy (values >= 40 chars, partial ratio >= 90).

- Integrity = max over matching spans (a value the user supplied stays trusted even if an attacker repeats it).
- Confidentiality = max over matching spans.
- No match: integrity = session low-water mark; confidentiality = session maximum.
- Values shorter than 3 characters are trivial and carry no label.

## Tool classes and argument roles (from the manifest)

- `read`: no side effects. `write`: changes state. `egress`: sends data outside.
- `control_args`: arguments that pick targets or actions (recipient, url, path, amount).
- `data_args`: payload arguments (body, content).

## Policy

Rules are YAML. Each has `id`, `when` (tool class, tool glob, server glob), `if` (list of named predicates, all
must hold) and `action` (`block`, `ask`, `allow`). Precedence: block > ask > allow. Default: allow.

Predicates: `control_args_untrusted`, `sensitive_data_to_unapproved_destination`, `session_tainted`,
`session_has_flagged_span`, `args_from_flagged_span`, `server_untrusted`.

## Manifests

A manifest names a server, its default output labels, and per tool: capability class, argument roles, and
SHA-256 pins of the description and input schema. The operator signs the canonical JSON with Ed25519.
On every tool listing the gateway checks the signature and pins:

- unknown server or unpinned tool: hidden (when `require_manifests` is on)
- pin mismatch: rug pull, the whole server is quarantined until re-approved
- description flagged by the detector: tool hidden

## Evaluation

Scenarios run a worst-case obedient agent (it follows every injected instruction it sees) through the gateway.
Metrics: attack success rate (ASR), benign utility, utility under attack, false-positive rate (benign calls
blocked or sent to ask) and gateway overhead per call (p50, p95). Ablations: none, detector only,
policies with low-water mark only, policies with attribution, full.

The obedient agent measures the defence under the strongest attacker assumption. Real-model ASR (Gemini) is
reported separately and will be lower.

## Proxy-mode limitation

In stdio proxy mode the gateway sees tool calls but not the user's prompt. Values first seen before any
untrusted span are treated as trusted; values the model produces after taint inherit the low-water mark.
Hosts that can forward user messages should use the in-process API (`Gateway.add_user_message`).
