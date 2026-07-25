# T-F10a Execute — Model: capable
Worktree `<WORKTREE>`; branch `ticket/T-F10a-release`. Inputs `tickets/T-F10a.md`, final manifests, owner-merged SHA and deployment authority. Allowed writes `docs/evidence/release/**`, `README.md`. No test path; verifier is release checklist, read-only dual `ls-remote`, CI/deploy/hash checks. Agent never merges/pushes.
Network only for owner-authorized deployment/read-only verification; no spend/live attack; no main merge/push; max 3. Output `.tdd-swarm/reports/T-F10a-execute.md`. Return four-status contract + line.
Strict local contract: exact ticket input `tickets/T-F10a.md`; there is no test scope and no production-code permission; use only the named mechanical verifier above. Return exactly `DONE | DONE_WITH_CONCERNS | NEEDS_CONTEXT | BLOCKED(reason)` plus one-line summary; full output stays in the declared report path.
No main merge/push.
Exact inputs: `tickets/T-F10a.md` and dependency/authorization artifacts named there; exact output: `.tdd-swarm/reports/T-F10a-execute.md`.
