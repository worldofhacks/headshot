# T-F01b Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F01b-final-reconciliation`. Input `tickets/T-F01b.md` plus dependency manifests. Allowed writes are exactly its six doc paths. No test path; verifier: CSV no-blank audit, `rg` conflict audit, and dependency `sha256sum -c`. No production code.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F01b-execute.md`. Return `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` + line.
Strict local contract: exact ticket input `tickets/T-F01b.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F01b.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F01b-execute.md`.
