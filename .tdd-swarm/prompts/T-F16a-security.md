# T-F16a Security Review — Model: gpt-5.6-sol (capable)
Worktree `<WORKTREE>`; branch `ticket/T-F16a-surface-policy`. Inputs: ticket, diff from `1ac3ee0`, implement/gate reports. Allowed write only `.tdd-swarm/reports/T-F16a-security.md`; tests frozen. Re-run gate; inspect credential-key/placement confusion, evidence secret access, policy/hash substitution, retry understatement, fixture descriptor/path injection, legacy/partial profile downgrade, wildcard/off-host routing, and fail-open parsing.

No network, credentials, owner files, main merge, or push. Maximum three review attempts. Return `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus highest severity.
