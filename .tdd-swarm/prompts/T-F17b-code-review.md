# T-F17b Code Reviewer — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on the assigned T-F17b review branch.
Review T-F17b ticket/diff/frozen tests/gates/report. Write only
`.tdd-swarm/reports/T-F17b-code-review.md`. Verify schema nullability and terminal-state invariants,
per-physical ordering, FKs/indexes, additive migration and rollback, role grants, idempotency, org
scope, exact measurement semantics, and no historical fabrication. Re-run the gate. Findings need
file:line and severity; Critical/Important block. No edits/network/deployment/main push.
