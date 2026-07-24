# T-F06b Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F06b-replay-evidence`. Inputs `tickets/T-F06b.md`, T-F05b/T-F06a manifests, `docs/evidence/authorizations/regression-replay.json` or still-valid exact campaign scope. Allowed writes `docs/evidence/regression/**`. No test path; verifier is preflight plus T-F06a comparator. Invalid => zero calls/exit 4.
Network/spend/live only within named authorization; no main merge/push; max 3 authorized attempts. Output `.tdd-swarm/reports/T-F06b-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F06b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F06b.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F06b-execute.md`.
