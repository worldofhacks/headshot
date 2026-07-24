# T-F01b Evidence Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F01b-final-reconciliation`. Inputs ticket, owned docs, execute report, all manifests. Allowed write `.tdd-swarm/reports/T-F01b-evidence-review.md`. No test path; rerun named CSV/rg/hash verifiers and verify staging/9-INDETERMINATE honesty.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F01b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F01b.md`, ticket file_scopes, `.tdd-swarm/reports/T-F01b-execute.md`, and named artifact manifests; exact output: `.tdd-swarm/reports/T-F01b-evidence-review.md`.
