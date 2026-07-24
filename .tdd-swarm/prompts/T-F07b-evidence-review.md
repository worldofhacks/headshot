# T-F07b Evidence Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F07b-live-stress`. Inputs ticket/auth/raw/manifest/execute report. Allowed write `.tdd-swarm/reports/T-F07b-evidence-review.md`. No test path; recompute count, percentiles, caps/abort, costs/hashes/bottleneck.
No network/spend/live traffic in review; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F07b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F07b.md`, ticket file_scopes, `.tdd-swarm/reports/T-F07b-execute.md`, and named artifact manifests; exact output: `.tdd-swarm/reports/T-F07b-evidence-review.md`.
