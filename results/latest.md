# AgentWall benchmark (quick suite)

Commit `48c199e` · 34 attack scenarios · 16 benign scenarios · worst-case obedient agent (it follows every injection it sees).

| Configuration | ASR | ASR (held-out phrasings) | Blocked | Held for approval | Benign utility | Utility under attack | FPR | Overhead p50 / p95 (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| No defence | 100.0% | 100.0% | 0.0% | 0.0% | 100.0% | 100.0% | 0.0% | 0.193 / 0.4 |
| Detector only | 35.3% | 90.0% | 64.7% | 0.0% | 87.5% | 85.3% | 5.7% | 0.26 / 0.649 |
| Policies, low-water mark only | 0.0% | 0.0% | 100.0% | 0.0% | 25.0% | 85.3% | 34.3% | 0.159 / 0.383 |
| Policies + attribution | 0.0% | 0.0% | 85.3% | 5.9% | 93.8% | 100.0% | 2.9% | 0.223 / 0.396 |
| Full AgentWall | 0.0% | 0.0% | 73.5% | 5.9% | 93.8% | 88.2% | 2.9% | 0.277 / 0.788 |
| Full AgentWall, strict policy | 0.0% | 0.0% | 73.5% | 14.7% | 37.5% | 73.5% | 28.6% | 0.288 / 0.751 |

ASR: share of attacks whose goal call executed. Blocked / held: share of attacks stopped by a block or an ask (the rest never reached a tool, e.g. the poisoned tool was hidden). FPR: share of the user's own calls in benign scenarios that were blocked or held.

## Attack success by category

| Category | n | No defence | Detector only | Policies, low-water mark only | Policies + attribution | Full AgentWall | Full AgentWall, strict policy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| content_injection | 2 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| exfiltration_email | 17 | 100.0% | 23.5% | 0.0% | 0.0% | 0.0% | 0.0% |
| exfiltration_http | 3 | 100.0% | 33.3% | 0.0% | 0.0% | 0.0% | 0.0% |
| exfiltration_paraphrased | 3 | 100.0% | 33.3% | 0.0% | 0.0% | 0.0% | 0.0% |
| rug_pull | 2 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| secret_leak | 3 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| tool_poisoning | 2 | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| write_hijack | 2 | 100.0% | 50.0% | 0.0% | 0.0% | 0.0% | 0.0% |

## Benign task completion by category

| Category | n | No defence | Detector only | Policies, low-water mark only | Policies + attribution | Full AgentWall | Full AgentWall, strict policy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| benign_email_user_named | 4 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 0.0% |
| benign_post_user_named | 2 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% |
| benign_read_only | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| benign_suspicious_looking_page | 2 | 100.0% | 0.0% | 0.0% | 100.0% | 100.0% | 0.0% |
| benign_untrusted_target | 1 | 100.0% | 100.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_user_shares_secret | 1 | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| benign_write_user_named | 3 | 100.0% | 100.0% | 0.0% | 100.0% | 100.0% | 0.0% |
