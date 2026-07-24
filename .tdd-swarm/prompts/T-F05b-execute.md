# T-F05b Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05b-live-campaign`. Inputs `tickets/T-F05b.md`, dependency manifests, `docs/evidence/authorizations/campaign.json`. Allowed writes `evals/results/live/**`, `docs/evidence/live/**`, `docs/target/live/**`. No test path; verifier is exact preflight plus T-F01a exporter. Invalid => zero calls/exit 4.
Network/spend/live only within named staging authorization; no PHI/secrets/main merge/push; max 3 authorized attempts. Output `.tdd-swarm/reports/T-F05b-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F05b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F05b.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F05b-execute.md`.
