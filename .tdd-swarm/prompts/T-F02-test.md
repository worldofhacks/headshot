# T-F02 Test — Model: standard
Worktree `<WORKTREE>`; branch `ticket/T-F02-root-contracts`. Inputs: `tickets/T-F02.md`, package schemas. Allowed writes: `tests/contract/test_root_contracts.py`. Own/tag RED tests; run focused pytest.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F02-test.md`. Return `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` + line.
Strict local contract: exact ticket input `tickets/T-F02.md`; Test Agent owns only the ticket test_scopes; it must prove clean RED before freeze. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F02.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F02.md` and repository interfaces named by that ticket; exact output: `.tdd-swarm/reports/T-F02-test.md`.
