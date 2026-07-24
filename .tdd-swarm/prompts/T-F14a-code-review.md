# T-F14a Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F14a-security-tools`. Inputs ticket/diff/reports. Allowed write `.tdd-swarm/reports/T-F14a-code-review.md`. Run wrapper; verify current/historical lineage and only verified signals influence orchestration.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F14a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F14a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F14a.md`, `.tdd-swarm/diffs/T-F14a.patch`, `.tdd-swarm/reports/T-F14a-implement.md`, `.tdd-swarm/reports/T-F14a-gates.md`; exact output: `.tdd-swarm/reports/T-F14a-code-review.md`.
