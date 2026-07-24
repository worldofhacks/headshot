# T-F17f Test Reviewer — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on the assigned T-F17f review branch.
Review T-F17f ticket, RED tests/output/report. Write only
`.tdd-swarm/reports/T-F17f-test-review.md`. Verify tests cannot pass by relabeling configured values
as observed, cover null/unavailable cost and retries, enforce backend prompt permission and org
scope, prove exact-key decoder drift, render prompt/provider text without HTML, and cover
loading/empty/degraded/error/restricted/accessibility states. Freeze clean RED only; no edits/main push.
