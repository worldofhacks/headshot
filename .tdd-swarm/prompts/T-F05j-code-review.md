# T-F05j Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05j-smart-session-reference`. Inputs: ticket, diff, implementation/gate reports, frozen tests/dependencies. Write only `.tdd-swarm/reports/T-F05j-code-review.md`; implementation/tests are read-only. Re-run gates for strict config/ref grammar, migration/job immutability/idempotency, non-session compatibility, exact safe persisted failure message and separate code/status, raw-detail non-disclosure, and absence of loader/source/provider/Runner scope.

No network/live DB/controller/Railway/provider/target, secrets/PHI, spend, main merge, or push. Maximum three reviews. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus verdict; full output stays in the report.
