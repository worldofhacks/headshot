# T-F06a Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F06a-replay-code`. Inputs ticket/diff/reports. Allowed write `.tdd-swarm/reports/T-F06a-code-review.md`. Run wrapper; verify comparator/baseline hashes/cache/auth and timing output.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F06a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F06a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F06a.md`, `.tdd-swarm/diffs/T-F06a.patch`, `.tdd-swarm/reports/T-F06a-implement.md`, `.tdd-swarm/reports/T-F06a-gates.md`; exact output: `.tdd-swarm/reports/T-F06a-code-review.md`.
