# T-F17c Code Reviewer — model: gpt-5.6-sol, reasoning: ultra

Verify no call lacks durable identity and the 100-case profile reserves 400, reconciles `300+F`,
and disables provider retries.
Work only in `<WORKTREE>` on the assigned T-F17c review branch.
Review T-F17c ticket/diff/frozen tests/gates/report. Write only
`.tdd-swarm/reports/T-F17c-code-review.md`. Verify exact message order/content hash, locked model and
upstream behavior, fallback disabled, token/cost reservation including prompt, callback exactly once
per physical attempt, deterministic precedence unchanged, and real entrypoint reachability for
T-F17d. Re-run gates. Critical/Important block. No edits/live calls/deployment/main push.
