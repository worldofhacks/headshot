# T-F00 Test Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F00-swarm-gates`. Inputs: `tickets/T-F00.md`, `tests/swarm/**`, `.tdd-swarm/reports/T-F00-test.md`. Allowed write: `.tdd-swarm/reports/T-F00-test-review.md` only. Named verifier: `.venv/bin/pytest tests/swarm -q`; confirm clean RED, all ACs, cycle/coverage/spec negative fixtures. Tests freeze only after review.
No network/spend/live traffic; no main merge/push; maximum 3 cycles. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` + verdict line.
Strict local contract: exact ticket input `tickets/T-F00.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F00.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F00.md`, ticket test_scopes, `.tdd-swarm/reports/T-F00-test.md`; exact output: `.tdd-swarm/reports/T-F00-test-review.md`.
