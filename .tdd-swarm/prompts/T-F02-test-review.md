# T-F02 Test Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F02-root-contracts`. Inputs: ticket, test, RED report. Allowed write: `.tdd-swarm/reports/T-F02-test-review.md`. Verifier `.venv/bin/pytest tests/contract/test_root_contracts.py -q`; ensure single authority/parity/wheel/breaking negatives; freeze after approval.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F02.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F02.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F02.md`, ticket test_scopes, `.tdd-swarm/reports/T-F02-test.md`; exact output: `.tdd-swarm/reports/T-F02-test-review.md`.
