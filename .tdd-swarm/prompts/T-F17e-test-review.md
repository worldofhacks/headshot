# T-F17e Test Reviewer — model: gpt-5.6-sol, reasoning: ultra

Reject environment-only heartbeats; startup failure must supersede old operational evidence and
every wrong org/config/release/prompt/reference/generation must block.
Work only in `<WORKTREE>` on the assigned T-F17e review branch.
Review T-F17e ticket, RED tests/output/report. Write only
`.tdd-swarm/reports/T-F17e-test-review.md`. Verify Web cannot assert capability locally, DB time
governs freshness, wrong environment fails, Runner emits readiness only after complete composition,
deployment tests prove provider secrets cannot reach Web, readiness performs zero external calls,
and rollback retains evidence. Do not edit tests/production. No Railway mutation/main push.
