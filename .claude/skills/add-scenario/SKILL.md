---
name: add-scenario
description: Add a new attack or benign scenario family to the AgentWall harness corpus and verify it runs
---
Add a scenario family for: $ARGUMENTS

1. Read `src/agentwall/harness/corpus.py` and `src/agentwall/harness/scenario.py` to see the existing families.
2. Add a generator function that yields `Scenario` objects. Give every scenario a stable id
   (`<category>-<carrier>-<target>-<n>`), a `category`, and `split` ("train" or "test").
   Put roughly 30% of new phrasings in `split: test` and never use them to tune the detector.
3. Register the family in `build_corpus()`.
4. Add a unit test in `tests/test_corpus.py` asserting the family produces scenarios and that ids are unique.
5. Run `agentwall bench --suite quick` and report ASR, utility and FPR before and after in your summary.
