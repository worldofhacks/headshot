# T-F02 Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F02-root-contracts`. Inputs: ticket, `<DIFF_PACKAGE>`, implement/gate reports. Allowed write: `.tdd-swarm/reports/T-F02-code-review.md`. Run wrapper; verify package authority/root publication and CI parity.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F02.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F02.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F02.md`, `.tdd-swarm/diffs/T-F02.patch`, `.tdd-swarm/reports/T-F02-implement.md`, `.tdd-swarm/reports/T-F02-gates.md`; exact output: `.tdd-swarm/reports/T-F02-code-review.md`.
