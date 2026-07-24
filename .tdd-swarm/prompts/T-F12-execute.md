# T-F12 Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F12-architecture-reconciliation`. Inputs `tickets/T-F12.md`, landed interface/import/contract/evidence reports. Allowed writes `ARCHITECTURE.md`, `docs/adrs/0001-build-vs-configure.md`, `0002-identity-and-access.md`. No test path; verifier is Architecture Reviewer table/hash comparison and `rg` completeness checks. No code.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F12-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F12.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F12.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F12-execute.md`.
