# T-F16f Security Review — Model: gpt-5.6-sol (capable)
Worktree `<WORKTREE>`; branch `ticket/T-F16f-multi-surface-scan`; execution base `1ac3ee0`. Inputs: ticket, diff, implement/gate reports, and frozen tests. Allowed write only: `.tdd-swarm/reports/T-F16f-security.md`. Re-run gates; inspect self-approval/confused deputy, child omission/substitution, queue tampering, TOCTOU/recovery, idempotency replay, cross-target sessions, anonymous credential access, cap bypass, document ordering, RLS/grants, result laundering, and any full-scan implication while documents are inactive.

No external network, credentials, fixtures, target/provider calls, main merge, or push. Maximum three review attempts. Return `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus highest severity.
