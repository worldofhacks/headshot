# T-F01a Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F01a-eval-export`. Inputs: ticket, `<DIFF_PACKAGE>`, implement/gate reports. Allowed write: `.tdd-swarm/reports/T-F01a-code-review.md`. Named verifier: local wrapper; review exact exits/counts/artifact hashes and no inferred finding.
No network/spend/live traffic; no main merge/push; maximum 3 cycles. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F01a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F01a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F01a.md`, `.tdd-swarm/diffs/T-F01a.patch`, `.tdd-swarm/reports/T-F01a-implement.md`, `.tdd-swarm/reports/T-F01a-gates.md`; exact output: `.tdd-swarm/reports/T-F01a-code-review.md`.
