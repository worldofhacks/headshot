# T-F05p Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F05p-clinical-copilot-target-catalog`. Inputs: ticket, diff, implementation/gate reports, frozen tests. Write only `.tdd-swarm/reports/T-F05p-code-review.md`; config/source/tests are read-only. Re-run gates for exact target membership, strict non-secret catalog, Web/Runner byte+hash parity, no inline/alternate source, Runner-only resolver boundary, chat-only enablement, exact target/session/patient pinning, disabled surfaces, and no extracted artifact content.

No network/Railway/provider/target, credential/session values, PHI, spend, main merge, or push. Maximum three reviews. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus verdict; full output stays in the report.
