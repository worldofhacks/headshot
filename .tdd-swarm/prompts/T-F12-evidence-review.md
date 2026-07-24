# T-F12 Evidence Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F12-architecture-reconciliation`. Inputs ticket/docs/dependency reports/execute report. Allowed write `.tdd-swarm/reports/T-F12-evidence-review.md`. No test path; verify all AI roles, rate/auth/pagination, ADR rows, no undeclared drift.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F12.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F12.md`, ticket file_scopes, `.tdd-swarm/reports/T-F12-execute.md`, and named artifact manifests; exact output: `.tdd-swarm/reports/T-F12-evidence-review.md`.
