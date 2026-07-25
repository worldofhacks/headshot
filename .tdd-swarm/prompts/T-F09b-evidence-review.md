# T-F09b Evidence Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F09b-drills`. Inputs ticket/drill/postmortem/manifests/execute report. Allowed write `.tdd-swarm/reports/T-F09b-evidence-review.md`. No test path; verify typed errors, expected/actual/recovery, partial evidence, alerts, postmortem hashes.
No network/spend/live traffic in review; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F09b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F09b.md`, ticket file_scopes, `.tdd-swarm/reports/T-F09b-execute.md`, and named artifact manifests; exact output: `.tdd-swarm/reports/T-F09b-evidence-review.md`.
