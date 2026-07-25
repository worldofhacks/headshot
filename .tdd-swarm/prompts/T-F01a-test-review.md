# T-F01a Test Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F01a-eval-export`. Inputs: ticket, test file, test report/RED. Allowed write: `.tdd-swarm/reports/T-F01a-test-review.md`. Named verifier: focused pytest; confirm exact exits/counts/hashes/redaction/gap behavior. Freeze tests after approval.
No network/spend/live traffic; no main merge/push; maximum 3 cycles. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F01a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F01a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F01a.md`, ticket test_scopes, `.tdd-swarm/reports/T-F01a-test.md`; exact output: `.tdd-swarm/reports/T-F01a-test-review.md`.
