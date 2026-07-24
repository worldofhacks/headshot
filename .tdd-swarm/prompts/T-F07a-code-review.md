# T-F07a Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F07a-benchmark`. Inputs ticket/diff/reports. Allowed write `.tdd-swarm/reports/T-F07a-code-review.md`. Run wrapper; verify landed replay usage, raw metrics, percentiles, hashes, approved SLO.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F07a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F07a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F07a.md`, `.tdd-swarm/diffs/T-F07a.patch`, `.tdd-swarm/reports/T-F07a-implement.md`, `.tdd-swarm/reports/T-F07a-gates.md`; exact output: `.tdd-swarm/reports/T-F07a-code-review.md`.
