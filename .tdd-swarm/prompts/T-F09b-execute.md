# T-F09b Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F09b-drills`. Inputs `tickets/T-F09b.md`, failure schemas, `docs/evidence/authorizations/failure-drill.json` only for external rows. Allowed writes `docs/evidence/failure-drills/**`, `docs/incidents/**`. No test path; verifier is drill matrix expected/actual/recovery/hash check.
Offline by default; external network/spend/live only within named auth; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F09b-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F09b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F09b.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F09b-execute.md`.
