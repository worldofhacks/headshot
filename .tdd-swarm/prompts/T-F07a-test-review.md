# T-F07a Test Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F07a-benchmark`. Inputs ticket/test/RED. Allowed write `.tdd-swarm/reports/T-F07a-test-review.md`. Verify exact 100/full replay, reproducibility, invalid-run exit, baseline approval; freeze.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F07a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F07a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F07a.md`, ticket test_scopes, `.tdd-swarm/reports/T-F07a-test.md`; exact output: `.tdd-swarm/reports/T-F07a-test-review.md`.
