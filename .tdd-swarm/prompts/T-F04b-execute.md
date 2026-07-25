# T-F04b Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F04b-redteam-eval`. Inputs `tickets/T-F04b.md`, persisted T-F04c configuration set, T-F04g preflight, T-F04a policy, `docs/evidence/authorizations/red-team-eval.json`. Allowed writes `evals/results/red-team/**`, `docs/evidence/red-team/**`. No test path; verifier uses T-F04g-approved persisted-record identity plus authorization threshold/policy hashes. Invalid auth/config/identity => zero calls/exit 4.
Provider/target network/spend only within named scope; no main merge/push; max 3 authorized attempts. Output `.tdd-swarm/reports/T-F04b-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F04b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F04b.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F04b-execute.md`.
