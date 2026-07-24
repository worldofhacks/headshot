# T-F07b Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F07b-live-stress`. Inputs `tickets/T-F07b.md`, T-F05b/T-F07a manifests, `docs/evidence/authorizations/live-stress.json`. Allowed writes `docs/performance/live/**`. No test path; verifier requires exactly 100 authorized cases/caps. Invalid => zero calls/exit 4.
Network/spend/live only within named load authorization; no production/PHI/secrets/main merge/push; max 3. Output `.tdd-swarm/reports/T-F07b-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F07b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F07b.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F07b-execute.md`.
