# T-F05a Test — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05a-trace-code`. Inputs `tickets/T-F05a.md`, T-F04c persisted configuration/execution references, T-F04h typed manifest contract, T-F04d composition metadata, runtime/store. Allowed writes `tests/test_four_agent_release_evidence.py`. Own/tag RED tests; prove exact immutable configuration-set/version/hash linkage and focused pytest.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F05a-test.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F05a.md`; Test Agent owns only the ticket test_scopes; it must prove clean RED before freeze. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F05a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F05a.md` and repository interfaces named by that ticket; exact output: `.tdd-swarm/reports/T-F05a-test.md`.
