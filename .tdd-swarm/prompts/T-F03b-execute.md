# T-F03b Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F03b-judge-evidence`. Inputs `tickets/T-F03b.md`, T-F03a policy, `docs/evidence/authorizations/judge-calibration.json`. Allowed writes `evals/results/calibration/**`, `docs/evidence/calibration/**`. No test path; verifier is T-F03a calibration CLI/policy hash. Invalid auth => zero calls/exit 4.
No target traffic; provider network/spend only within named auth; no main merge/push; max 3 authorized attempts. Output `.tdd-swarm/reports/T-F03b-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F03b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F03b.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F03b-execute.md`.
