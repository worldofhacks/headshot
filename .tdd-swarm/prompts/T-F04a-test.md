# T-F04a Test — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F04a-redteam-code`. Inputs: `tickets/T-F04a.md`, T-F04g-approved persisted T-F04c Red Team configuration, injected T-F04f client, Red Team contracts. Allowed writes: `tests/test_red_team_final.py`. Own/tag RED tests; deterministic injected transport/candidates only; focused pytest.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F04a-test.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F04a.md`; Test Agent owns only the ticket test_scopes; it must prove clean RED before freeze. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F04a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F04a.md` and repository interfaces named by that ticket; exact output: `.tdd-swarm/reports/T-F04a-test.md`.
