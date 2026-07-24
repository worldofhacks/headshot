# T-F08 Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F08-cost`. Inputs `tickets/T-F08.md` and immutable dependency manifests. Allowed writes `docs/cost/COST_ANALYSIS.md`, `docs/cost/inputs/**`. No test path; verifier `sha256sum -c docs/cost/inputs/manifest.sha256` plus dimensional recomputation. No production code.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F08-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F08.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F08.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F08-execute.md`.
