# T-F16d Security Review — Model: gpt-5.6-sol (capable)
Worktree `<WORKTREE>`; branch `ticket/T-F16d-document-workflow`. Inputs: ticket, diff, implement/gate reports, and frozen test. Allowed write only: `.tdd-swarm/reports/T-F16d-security.md`. Re-run gates; inspect symlink/path/device races, hash/MIME confusion, multipart injection, `session_id` leakage, ID traversal/SSRF, redirects, body limits, poll/retry abuse, ambiguous-write duplication, cap bypass, content logging, and post-abort dispatch.

No network, credentials, owner bundle/fixture read, screenshots, target calls, main merge, or push. Maximum three review attempts. Return `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus highest severity.
