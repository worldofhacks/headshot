# T-F07a Test — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F07a-benchmark`. Inputs `tickets/T-F07a.md`, landed T-F06a. Allowed writes `tests/performance/test_platform_benchmark.py`. Own/tag RED tests; network disabled; focused pytest.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F07a-test.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F07a.md`; Test Agent owns only the ticket test_scopes; it must prove clean RED before freeze. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F07a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F07a.md` and repository interfaces named by that ticket; exact output: `.tdd-swarm/reports/T-F07a-test.md`.
