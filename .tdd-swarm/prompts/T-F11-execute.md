# T-F11 Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F11-target-observation`. Inputs `tickets/T-F11.md`, `docs/evidence/authorizations/target-observation.json`, current threat/corpus. Allowed writes `docs/target/observations/**`, `THREAT_MODEL.md`, `docs/evidence/OWASP_COVERAGE_MATRIX.md`, `evals/seeds/**`. No test path; verifier is exact preflight plus corpus commands. Invalid auth => zero calls.
Network/live only within named staging observation scope; no spend/load/PHI/main merge/push; max 3. Output `.tdd-swarm/reports/T-F11-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F11.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F11.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F11-execute.md`.
