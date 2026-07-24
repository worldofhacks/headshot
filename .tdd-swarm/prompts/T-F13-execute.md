# T-F13 Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F13-integration-packet`. Inputs `tickets/T-F13.md`, T-F02..T-F06a/T-F14 manifests, live trace. Allowed writes `docs/integration/**`. No test path; verifier is published-contract-only command, both-sided contract tests and `sha256sum -c docs/integration/manifest.sha256`. No code.
No network/spend/live traffic; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F13-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F13.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F13.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F13-execute.md`.
