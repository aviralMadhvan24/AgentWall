# AgentWall benchmark (full suite)

Commit `d201878` · 129 attack scenarios · 32 benign scenarios · worst-case obedient agent (it follows every injection it sees).

| Configuration | ASR | ASR (held-out phrasings) | Blocked | Held for approval | Benign utility | Utility under attack | FPR | Overhead p50 / p95 (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| No defence | 100.0% | 100.0% | 0.0% | 0.0% | 100.0% | 100.0% | 0.0% | 0.207 / 0.475 |
| Detector only | 33.3% | 76.2% | 66.7% | 0.0% | 90.6% | 88.4% | 4.2% | 0.282 / 0.993 |
| Policies, low-water mark only | 0.0% | 0.0% | 100.0% | 0.0% | 25.0% | 88.4% | 33.3% | 0.174 / 0.446 |
| Policies + attribution | 0.0% | 0.0% | 88.4% | 4.7% | 90.6% | 100.0% | 4.2% | 0.259 / 0.618 |
| Full AgentWall | 0.0% | 0.0% | 77.5% | 4.7% | 90.6% | 89.1% | 4.2% | 0.327 / 1.02 |
| Full AgentWall, strict policy | 0.0% | 0.0% | 77.5% | 11.6% | 31.2% | 77.5% | 30.6% | 0.308 / 1.016 |

ASR: share of attacks whose goal call executed. Blocked / held: share of attacks stopped by a block or an ask (the rest never reached a tool, e.g. the poisoned tool was hidden). FPR: share of the user's own calls in benign scenarios that were blocked or held.

## Attack success by category

| Category | n | No defence | Detector only | Policies, low-water mark only | Policies + attribution | Full AgentWall | Full AgentWall, strict policy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| content_injection | 6 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| exfiltration_email | 68 | 100.0% | 19.1% | 0.0% | 0.0% | 0.0% | 0.0% |
| exfiltration_http | 12 | 100.0% | 33.3% | 0.0% | 0.0% | 0.0% | 0.0% |
| exfiltration_paraphrased | 10 | 100.0% | 20.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| rug_pull | 8 | 100.0% | 25.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| secret_leak | 9 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| tool_poisoning | 8 | 100.0% | 25.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| write_hijack | 8 | 100.0% | 62.5% | 0.0% | 0.0% | 0.0% | 0.0% |

## Benign task completion by category

| Category | n | No defence | Detector only | Policies, low-water mark only | Policies + attribution | Full AgentWall | Full AgentWall, strict policy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| benign_email_user_named | 8 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 0.0% |
| benign_post_user_named | 4 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 50.0% |
| benign_read_only | 6 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| benign_suspicious_looking_page | 3 | 100.0% | 0.0% | 0.0% | 100.0% | 100.0% | 0.0% |
| benign_untrusted_target | 3 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_user_shares_secret | 2 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| benign_write_user_named | 6 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 0.0% |
