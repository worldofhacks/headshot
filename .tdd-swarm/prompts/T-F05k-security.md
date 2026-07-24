# T-F05k Security Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05k-smart-session-context-loader`. Inputs: ticket, diff, implementation/gate reports, frozen tests/review. Write only `.tdd-swarm/reports/T-F05k-security.md`; all else is read-only. Re-run gates; inspect traversal/symlink/hard-link/TOCTOU/replacement, unsafe owner-mode-link count, partial persistence, inode swap after startup, context disclosure, attacker ref/path, attempt reload, cleanup leak, and fail-open missing file.

No live filesystem/network/Railway/controller/database/provider/target, secrets/PHI, spend, main merge, or push. Maximum three reviews. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus highest severity; full output stays in the report.
