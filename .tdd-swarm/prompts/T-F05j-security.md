# T-F05j Security Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05j-smart-session-reference`. Inputs: ticket, diff, implementation/gate reports, frozen tests/review. Write only `.tdd-swarm/reports/T-F05j-security.md`; all else is read-only. Re-run gates; inspect config/ref injection, job/payload confused deputy, mutable ref/idempotency, migration/RBAC, queue-lease ownership, retryable rejection, arbitrary-detail allowlisting or logging, code/status spoofing, disclosure, and fail-open non-session branching.

No network/live DB/controller/Railway/provider/target, secrets/PHI, spend, main merge, or push. Maximum three reviews. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus highest severity; full output stays in the report.
