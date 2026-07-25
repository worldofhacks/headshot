# T-F05m Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05m-authenticated-runner-state-provider`. Inputs: ticket, diff, implementation/gate reports, frozen tests, dependency reviews. Write only `.tdd-swarm/reports/T-F05m-code-review.md`; source/tests are read-only. Re-run gates for exact call order, new L challenge and I transaction each call, typed receipt/context/claim, H nonce verification, E sole validation, no caller path/combined state, no cached/partial success, error redaction, and one-concern scope.

No filesystem/network/live controller/database/Railway/provider/target, secrets/PHI, spend, main merge, or push. Maximum three reviews. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus verdict; full output stays in the report.
