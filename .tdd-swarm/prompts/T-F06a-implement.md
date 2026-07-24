# T-F06a Implement — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F06a-replay-code`. Inputs ticket/frozen test/review/lessons. Allowed writes `src/agentforge/regression/replay.py`, `executor.py`, `src/agentforge/scheduler.py`, `src/agentforge/runner.py`. Never edit tests. Gate `.tdd-swarm/run-local-gates.sh tickets/T-F06a.md <DIFF_BASE>`.
No network/spend/live traffic; no main merge/push; max 3 loops. Output `.tdd-swarm/reports/T-F06a-implement.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F06a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F06a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F06a.md`, frozen ticket test_scopes, `.tdd-swarm/reports/T-F06a-test-review.md`, `.tdd-swarm/LESSONS.md`; exact output: `.tdd-swarm/reports/T-F06a-implement.md`.
