# T-F10c Execute — Model: standard
Worktree `<WORKTREE>`; branch `ticket/T-F10c-submission`. Inputs `tickets/T-F10c.md`, release/report/cost/ATO manifests, `docs/evidence/authorizations/social-publication.json` only for human post. Allowed writes `docs/demo/**`, `docs/submission/**`. No test path; verifier checks 180–300s metadata, sanitation ledger and requirement→hash checklist. Agent never posts.
No network/spend/live traffic or publication absent named auth; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F10c-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F10c.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F10c.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F10c-execute.md`.
