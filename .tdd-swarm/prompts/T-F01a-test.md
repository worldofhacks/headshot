# T-F01a Test — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F01a-eval-export`. Inputs: `tickets/T-F01a.md`, existing contracts/storage. Allowed writes: `tests/evals/test_live_export.py`. Own RED tests; tag ACs; run `.venv/bin/pytest tests/evals/test_live_export.py -q`; sampled behavior is out.
No network/spend/live traffic; no main merge/push; maximum 3 attempts. Output `.tdd-swarm/reports/T-F01a-test.md`. Return four-status contract + one line.
Strict local contract: exact ticket input `tickets/T-F01a.md`; Test Agent owns only the ticket test_scopes; it must prove clean RED before freeze. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F01a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F01a.md` and repository interfaces named by that ticket; exact output: `.tdd-swarm/reports/T-F01a-test.md`.
