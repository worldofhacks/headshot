# T-F03a Test — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F03a-judge-code`. Inputs: `tickets/T-F03a.md`, Judge contracts. Allowed writes: `tests/test_judge_final.py`. Own/tag RED tests; injected transport only; run focused pytest; sampled quality is not mocked.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F03a-test.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F03a.md`; Test Agent owns only the ticket test_scopes; it must prove clean RED before freeze. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F03a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F03a.md` and repository interfaces named by that ticket; exact output: `.tdd-swarm/reports/T-F03a-test.md`.
