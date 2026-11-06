---
name: run-harness
description: Run the AgentWall ablation benchmark and summarise the results table
disable-model-invocation: true
---
1. Run `agentwall bench --suite ${ARGUMENTS:-quick} --out results/`.
2. Open `results/latest.md` and paste the ablation table into your reply.
3. Compare with the previous commit's numbers in `results/history.csv`. Flag any configuration where ASR or
   FPR got worse by more than 1 percentage point, and name the scenarios responsible
   (`results/latest.json` has per-scenario outcomes).
