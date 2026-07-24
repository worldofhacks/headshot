# T-F10b Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F10b-reports`. Inputs `tickets/T-F10b.md`, confirmed evidence, `docs/evidence/authorizations/reproduction.json` per candidate. Allowed writes `docs/vulnerabilities/**`, `docs/evidence/reproductions/**`. No test path; verifier is packaged vuln-report schema, duplicate check, evidence/reproduction hashes. Invalid auth => zero calls.
Network/spend/live only within exact reproduction auth; no publication/remediation/main merge/push; max 3 per authorized candidate. Output `.tdd-swarm/reports/T-F10b-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F10b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F10b.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F10b-execute.md`.
