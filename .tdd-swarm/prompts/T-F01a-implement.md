# T-F01a Implement — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F01a-eval-export`. Inputs: ticket, frozen test, test-review, lessons. Allowed writes: `src/agentforge/evals/export.py`, `src/agentforge/evals/__main__.py`, `scripts/export_live_eval.py`. Never edit tests. Gate: `.tdd-swarm/run-local-gates.sh tickets/T-F01a.md <DIFF_BASE>`.
No network/spend/live traffic; no main merge/push; maximum 3 loops. Output `.tdd-swarm/reports/T-F01a-implement.md`. Return four-status contract + one line.
Strict local contract: exact ticket input `tickets/T-F01a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F01a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F01a.md`, frozen ticket test_scopes, `.tdd-swarm/reports/T-F01a-test-review.md`, `.tdd-swarm/LESSONS.md`; exact output: `.tdd-swarm/reports/T-F01a-implement.md`.
