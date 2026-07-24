# T-F17b Test Reviewer — model: gpt-5.6-sol, reasoning: ultra

Reject omissions of distinct committed pre-call identity per retry, crash-to-unknown
reconciliation, composite FKs, or nullable measured/partial/not-observed/invalid cost and
no-double-count source ids.
Work only in `<WORKTREE>` on the assigned T-F17b review branch. Review `tickets/T-F17b.md`, RED
tests/output, and `.tdd-swarm/reports/T-F17b-test.md`. Write only
`.tdd-swarm/reports/T-F17b-test-review.md`. Verify retry-then-success creates two contexts before
their reservations, physical attempts cannot be collapsed, a retryable first event leaves the
logical execution running, only the final event terminalizes it, failed calls cannot fabricate
observed facts/cost, DB privilege tests prove genuine SQL rejection, migration preserves baseline
data, and sanitization assertions are non-tautological.
Do not edit tests/production. No external network or main push. Return four-status plus verdict.
