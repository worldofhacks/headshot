# T-F17b Code Reviewer — model: gpt-5.6-sol, reasoning: ultra

Verify unique identity exists before every reservation/network attempt and recovery cannot orphan,
reattribute, duplicate, retry, or zero-price a physical attempt.
Work only in `<WORKTREE>` on the assigned T-F17b review branch.
Review T-F17b ticket/diff/frozen tests/gates/report. Write only
`.tdd-swarm/reports/T-F17b-code-review.md`. Verify schema nullability and terminal-state invariants,
per-physical ordering, two retry contexts, running logical state between attempts, final-only
logical terminalization, FKs/indexes, additive migration and rollback, role grants, idempotency,
org scope, exact measurement semantics, and no historical fabrication. Re-run the gate. Findings need
file:line and severity; Critical/Important block. No edits/network/deployment/main push.
