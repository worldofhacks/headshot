# T-F15 Execute — Model: standard
Worktree `<WORKTREE>`; branch `ticket/T-F15-project-story`. Inputs `tickets/T-F15.md`, final manifests/git log. Allowed writes `docs/DEVLOG.md`, `docs/PROJECT_STORY.md`. No test path; verifier is evidence-link/`rg` stale-claim audit. No code.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F15-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F15.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F15.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F15-execute.md`.
