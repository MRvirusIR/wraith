# Contributing

Thanks for helping. The most useful contributions, in order:

1. **A false positive.** A real description that fires a rule but should not. Open an issue
   with the exact definition.
2. **A rule.** New detection with a fixture that must fire and a fixture that must not.
3. **A lab fixture.** A realistic poisoned server pattern (a skill loader, a filesystem tool,
   an OAuth-broker) for `wraith/lab.py` or `examples/`.
4. **Docs.** Especially: how a specific program wants MCP findings reported.

## Setup

```bash
git clone https://github.com/MRvirusIR/wraith
cd wraith
python3 -m unittest discover -s tests -t .     # 51 tests, no dependencies
python3 -m wraith demo                          # smoke test the whole pipeline
```

## Adding a rule

1. Write `rule_<name>(tool, target) -> list[Finding]` in `wraith/rules.py`.
2. Append it to `RULES`.
3. Add the entry to `wraith/rulebook.py` and `docs/DETECTIONS.md` (severity, CWE, signal,
   false positives).
4. Add tests: one positive, one negative, in `tests/test_rules.py`.
5. If the rule can be noisy, say so in the docstring — reviewers care more about precision
   than coverage.

## Style

- Stdlib only. A pull request that adds a dependency needs a very good reason.
- No network in the rule engine, ever.
- Findings must be deterministic: same input, same ids.
- Comments explain *why*, not *what*.

## Commits

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`) and one topic per pull request.
