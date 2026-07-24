# T-F03a Security Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F03a-judge-code`. Inputs: ticket/diff/gates. Allowed write `.tdd-swarm/reports/T-F03a-security.md`. Run wrapper; check injection, fail-open, credential leak, self re-enable, identity collision.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + severity.
Strict local contract: exact ticket input `tickets/T-F03a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F03a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F03a.md`, `.tdd-swarm/diffs/T-F03a.patch`, `.tdd-swarm/reports/T-F03a-implement.md`, `.tdd-swarm/reports/T-F03a-gates.md`; exact output: `.tdd-swarm/reports/T-F03a-security.md`.
