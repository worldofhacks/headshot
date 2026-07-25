# T-F05k Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05k-smart-session-context-loader`. Inputs: ticket, diff, implementation/gate reports, frozen tests, E/J reviews. Write only `.tdd-swarm/reports/T-F05k-code-review.md`; source/tests are read-only. Re-run gates for fixed derivation, dirfd/no-follow/stat/link/size, create-only/fsync/idempotency, startup/post-claim byte+inode pinning, no attempt reload, redaction, cleanup, non-session behavior, and scope separation.

No live filesystem/network/Railway/controller/database/provider/target, secrets/PHI, spend, main merge, or push. Maximum three reviews. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus verdict; full output stays in the report.
