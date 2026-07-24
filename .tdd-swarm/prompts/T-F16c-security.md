# T-F16c Security Review — Model: gpt-5.6-sol (capable)
Worktree `<WORKTREE>`; branch `ticket/T-F16c-evidence-ui-adapters`. Inputs: ticket, diff, implement/gate reports, and frozen tests. Allowed write only: `.tdd-swarm/reports/T-F16c-security.md`. Re-run gates; inspect `sid` leakage/alternate placement, credential-bearing URL retention, redirects/SSRF/subresources, HTML/script execution, response/body logging, limits, schema/correlation confusion, anonymous evidence credential access, and legacy/profile fallback.

No network, credentials, owner bundle read, screenshots, target calls, main merge, or push. Maximum three review attempts. Return `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus highest severity.
