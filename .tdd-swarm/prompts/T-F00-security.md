# T-F00 Security Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F00-swarm-gates`. Inputs: ticket, `<DIFF_PACKAGE>`, gate report. Allowed write: `.tdd-swarm/reports/T-F00-security.md` only. Named verifier: wrapper plus negative fixtures; review command injection, path traversal, waiver forgery, report overwrite, cycle bypass.
No network/spend/live traffic; no main merge/push; maximum 3 cycles. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` + severity line.
Strict local contract: exact ticket input `tickets/T-F00.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F00.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F00.md`, `.tdd-swarm/diffs/T-F00.patch`, `.tdd-swarm/reports/T-F00-implement.md`, `.tdd-swarm/reports/T-F00-gates.md`; exact output: `.tdd-swarm/reports/T-F00-security.md`.
