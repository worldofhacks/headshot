# T-F16e Security Review — Model: gpt-5.6-sol (capable)
Worktree `<WORKTREE>`; branch `ticket/T-F16e-final-target-composition`. Inputs: ticket, diff, implement/gate reports, and frozen tests. Allowed write only: `.tdd-swarm/reports/T-F16e-security.md`. Re-run gates; inspect catalog authority/environment confusion, anonymous secret resolution, session cross-target/rotation, profile/path downgrade, fixture proof forgery, premature document activation, rollback drift, unsafe catalog data, secret/local-path signatures, and stale-scope activation.

No network, credentials, owner bundle/fixture read, screenshots, target/Railway calls, main merge, or push. Maximum three review attempts. Return `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus highest severity.
