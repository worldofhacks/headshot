# T-F18 console remediation final pass review

Reviewed console commit: `7bd41fa2f69e16460e4642adfbc03474c93d4e49`
Companion runtime HEAD inspected: `c48892844edd0723ede0315f1eefb99f31f2cf8d`
Verdict: **CHANGES_REQUIRED**

## Closure audit

1. **Dependency cycle and Costs implementability: locally closed.** T-F18j is now a backend-only
   bridge depending on T-F17b/c, T-F17e/f follow it, and T-F18p owns the later Costs
   API/UI/filter/paging work after T-F18b/o and T-F18i
   (`tickets/T-F18j.md:5-15`, `25-28`, `63-65`; `tickets/T-F18p.md:5-21`, `31-54`).
   T-F18k depends on T-F18p. The resulting local graph is acyclic.
2. **Stable Costs database paging: closed.** T-F18p owns PostgreSQL, the API route, frontend path and
   decoder, UI, DB/API/browser tests, composite cursor behavior, authorization-before-query, and
   scoped totals (`tickets/T-F18p.md:8-21`, `43-54`).
3. **Real producer-event scopes: closed for the cited gap.** T-F19e now includes the security-tool
   repository, both component heartbeat writers, a migration, and focused tests; its acceptance and
   review prompts require real write paths and transactional event behavior
   (`tickets/T-F19e.md:8-25`, `37-50`).
4. **Deterministic/production evidence overlap: closed.** T-F18l owns only
   `docs/evidence/console/deterministic/**`, T-F18n owns
   `docs/evidence/console/production/**`, and T-F19f owns
   `docs/evidence/final-target-runs/**` (`tickets/T-F18l.md:8-17`;
   `tickets/T-F18n.md:8-10`; `tickets/T-F19f.md:8-10`). These scopes are disjoint.
5. **Final 100-case/tool-plan run ownership: closed.** T-F19f is a mechanically ordered operational
   execute/evidence/security-review ticket after the deterministic, runtime, tool-event, and
   production-console gates. It binds both targets to distinct approval, exact-SHA deployment,
   worker/rate/request/timeout/abort limits, all four hosted roles, complete Tool ScanPlans,
   reconciliation, redaction, and immutable reports (`tickets/T-F19f.md:5-15`, `18-57`).

No new cycle or concurrent write-scope overlap was found in the repaired console ticket graph.
Overlapping implementation files between the early bridge and later Costs ticket, and between
runtime/event/console tickets, are serialized by direct or transitive dependencies.

## Exact blocker

The cross-worktree source of truth is still not dispatchable as one committed ticket graph.
The companion runtime worktree is dirty: its T-F17/T-F18j graph repair and T-F18j ticket are
uncommitted at runtime HEAD `c48892844edd0723ede0315f1eefb99f31f2cf8d`. More importantly, it
defines T-F18j as branch `ticket/T-F18j-cost-accounting-truth`
(`/Users/quietguy/Documents/Dev/Gauntlet/wt-agent-runtime-plan/TICKETS.md:150`;
`/Users/quietguy/Documents/Dev/Gauntlet/wt-agent-runtime-plan/tickets/T-F18j.md:2-7`;
`/Users/quietguy/Documents/Dev/Gauntlet/wt-agent-runtime-plan/.tdd-swarm/prompts/T-F18j-test.md:1-2`),
while the reviewed console commit defines the same ticket ID as
`ticket/T-F18j-accounting-unknown-bridge` (`tickets/T-F18j.md:2-7`;
`.tdd-swarm/prompts/T-F18j-test.md:1-2`). The two ticket copies also have different titles and AC-1/
AC-6 contracts.

Required repair: choose one canonical T-F18j branch, title, acceptance contract, ticket body, and
prompt set; make both planning worktrees byte-consistent for that ticket; commit the acyclic runtime
graph repair; then identify the exact integration commit containing both accepted planning changes.
Until then, a dispatcher can create two different branches and frozen suites for the same ticket ID,
so the prior mechanical-order finding is not fully closed.
