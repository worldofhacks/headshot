# T-F11 Evidence Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F11-target-observation`. Inputs ticket/auth/observations/threat/coverage/execute report. Allowed write `.tdd-swarm/reports/T-F11-evidence-review.md`. No test path; rerun corpus, verify hashes, six categories, observed/not-exercisable, OWASP gaps, sanitation.
No network/spend/live traffic in review; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F11.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F11.md`, ticket file_scopes, `.tdd-swarm/reports/T-F11-execute.md`, and named artifact manifests; exact output: `.tdd-swarm/reports/T-F11-evidence-review.md`.
