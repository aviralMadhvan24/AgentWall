# Threat model

## Assets
- Sensitive data reachable through tools (portfolio, files, email contents).
- Side-effecting tools (send email, HTTP POST, file writes, payments).
- The agent's long-term memory, if a memory server is connected.

## Trust boundaries
- The user and the system prompt are trusted.
- Each MCP server is trusted only as far as its signed manifest says.
- All text a server returns is data, never instructions, regardless of its label.

## Attacker capabilities (in scope)
| Attack | Carrier | Goal |
|---|---|---|
| Indirect prompt injection | Tool output (web page, file, email, API response) | Make the agent call another server's write or egress tool |
| Tool poisoning | Tool description at `tools/list` | Same, before any call happens |
| Rug pull | Description changed after the operator approved it | Same, bypassing review |
| Cross-server exfiltration | Any of the above | Move sensitive data to an attacker destination |
| Obfuscation | Base64, zero-width characters, homoglyphs, Hindi/Hinglish | Evade text filters |

## Out of scope (v0.1)
- A compromised gateway host or stolen signing key.
- Attacks that never touch a tool call (e.g. the model giving a misleading text answer).
- Covert channels inside paraphrased prose where no exact value is copied; the low-water mark and `ask`
  are the mitigation, not a guarantee.

## Assumptions
- Manifests are reviewed by a human before signing.
- The agent host routes every tool call through the gateway.
