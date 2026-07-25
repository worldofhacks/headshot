# T-F05i Security Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05i-runner-control-state`. Inputs: ticket, diff, implementation/gate reports, frozen tests/review. Write only `.tdd-swarm/reports/T-F05i-security.md`; all else is read-only. Re-run gates; inspect DB/snapshot/query/signature confusion, caller state, empty-set fail-open, row-identity/lineage ambiguity, job/worker/token substitution, raw token/SQL/DSN disclosure, abort rollback, stale replay, races, and authority fallback.

No network/PostgreSQL/Railway/controller/provider/target, secrets/PHI, spend, main merge, or push. Maximum three reviews. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus highest severity; full output stays in the report.
