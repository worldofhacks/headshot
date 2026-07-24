# T-F04a Code Review — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F04a-redteam-code`. Inputs ticket/diff/implement/gates plus T-F04c/T-F04g/T-F04f contracts. Allowed write `.tdd-swarm/reports/T-F04a-code-review.md`. Run wrapper; verify approved persisted authority/client consumption, deterministic limits/lineage/minimality and no behavior mock or independent env parsing.
No network/spend/live traffic; no main merge/push; max 3. Return four-status contract + verdict.
Strict local contract: exact ticket input `tickets/T-F04a.md`; Ticket tests are frozen; this role must not edit, weaken, skip, or delete them. Named verifier is the focused command above plus `.tdd-swarm/run-local-gates.sh tickets/T-F04a.md <DIFF_BASE>` after implementation. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F04a.md`, `.tdd-swarm/diffs/T-F04a.patch`, `.tdd-swarm/reports/T-F04a-implement.md`, `.tdd-swarm/reports/T-F04a-gates.md`; exact output: `.tdd-swarm/reports/T-F04a-code-review.md`.
