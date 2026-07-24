# T-F17d Test Reviewer — model: gpt-5.6-sol, reasoning: ultra

Work only in `<WORKTREE>` on the assigned T-F17d review branch.
Review T-F17d ticket, RED tests/output, and report. Write only
`.tdd-swarm/reports/T-F17d-test-review.md`. Verify real Runner/queue/store/gateway code is exercised,
the fake provider is not called on preflight failure, only one target dispatch is possible,
deterministic evidence and hosted Judge cannot diverge, fallback is impossible, and deterministic
campaign behavior is preserved. Freeze clean RED only. No edits/external network/main push.
