# T-F13 Evidence Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F13-integration-packet`. Inputs ticket/packet/manifest/contract outputs/execute report. Allowed write `.tdd-swarm/reports/T-F13-evidence-review.md`. No test path; rerun hashes/contracts/isolated import proof; verify current SHA and all diffs/migrations.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F13.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F13.md`, ticket file_scopes, `.tdd-swarm/reports/T-F13-execute.md`, and named artifact manifests; exact output: `.tdd-swarm/reports/T-F13-evidence-review.md`.
