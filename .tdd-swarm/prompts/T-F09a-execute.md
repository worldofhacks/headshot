# T-F09a Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F09a-ato`. Inputs `tickets/T-F09a.md` and dependency manifests. Allowed writes `docs/evidence/ato/**`. No test path; verifier required-file matrix plus `sha256sum -c docs/evidence/ato/manifest.sha256`. No production code.
No network/spend/live traffic absent separately named scan authorization; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F09a-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F09a.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F09a.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F09a-execute.md`.
