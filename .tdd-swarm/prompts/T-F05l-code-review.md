# T-F05l Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05l-controller-observation-source`. Inputs: ticket, diff, implementation/gate reports, frozen tests, H/J reviews. Write only `.tdd-swarm/reports/T-F05l-code-review.md`; source/tests are read-only. Re-run gates for fixed endpoint/no override, path+peer auth, exact request/frame bounds, challenge/signature/binding/freshness/replay/sequence, two-call behavior, single-use receipt, no cache/retry/fallback, redaction, and no projection/provider scope.

No production socket/network/controller/Railway/database/provider/target, secrets/PHI, spend, main merge, or push. Maximum three reviews. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus verdict; full output stays in the report.
