# T-F14b Test — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F14b-failure-contracts`. Inputs `tickets/T-F14b.md`, contract registry. Allowed writes `tests/contract/test_failure_contracts.py`. Own/tag RED producer/consumer tests.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F14b-test.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F14b.md`; Test Agent owns only the ticket test_scopes; it must prove clean RED before freeze. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F14b.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F14b.md` and repository interfaces named by that ticket; exact output: `.tdd-swarm/reports/T-F14b-test.md`.
