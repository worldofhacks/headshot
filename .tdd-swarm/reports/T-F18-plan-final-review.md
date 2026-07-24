# T-F18 console remediation plan final review

Reviewed commit: `a4e9612c30fca593a19d8c932bf879dda0dece56`
Verdict: **CHANGES_REQUIRED**

The repaired plan closes the page-inventory, five-state Tooling, material-command, and conceptual
deterministic/production-evidence findings. It also adds a concrete per-tool ScanPlan workstream and
splits the collection seam from residual database pagination. The plan is not dispatch-safe yet:
the combined T-F17/T-F18 graph remains cyclic, the early Costs ticket cannot implement its own
pagination criteria, real event-producer scopes are incomplete, and the evidence scopes still
overlap.

## Previous-finding closure audit

| Previous finding | Status | Result |
|---|---|---|
| 1. Per-tool ScanPlan/fanout ownership | **Closed** | T-F19a-e now own a versioned persisted plan, pinned brokers, separately authorized passive ZAP, fanout, reconciliation, and resource-event recovery; T-F18d/e/k/l depend on that workstream. |
| 2. Mechanical T-F16/T-F17 integration order | **Open** | The console graph and runtime planning sources disagree, producing a dependency cycle described below. |
| 3. Full Config/Audit inventory | **Closed** | T-F18m owns Configuration truth and permission-gated embedded Audit; the page registry must inventory both. |
| 4. Five independent tool states | **Closed** | The plan and T-F18d require installed, configured, generated, executed, and evidenced/adjudicated states plus negative implication tests. |
| 5. Database paging | **Open** | T-F18o is a valid residual paging owner, but T-F18j requires cost paging before the shared request seam and without an API route/path scope. |
| 6. All material confirmations | **Closed** | T-F18g owns the exhaustive command registry, all call sites, cancel/double-submit/idempotency/reason fidelity, and material command classes. |
| 7. Real producer events | **Open** | T-F19e requires real same-transaction events but excludes real tool and component producer write paths. |
| 8. Deterministic versus production evidence | **Open** | The tickets are conceptually split, but T-F18l's recursive evidence scope contains T-F18n's production scope. |

## Blocking findings

### 1. Critical — the combined runtime/console dependency graph is cyclic

The console plan schedules T-F18j before T-F17e/f and then schedules T-F18i later
(`docs/planning/console-pages-remediation.md:129-151`; `TICKETS.md:145-167`). The companion runtime
sources still declare T-F18j dependent on accepted T-F18i
(`/Users/quietguy/Documents/Dev/Gauntlet/wt-agent-runtime-plan/TICKETS.md:150-158`;
`/Users/quietguy/Documents/Dev/Gauntlet/wt-agent-runtime-plan/docs/planning/agent-runtime-provenance.md:279-287`).
The actual runtime tickets then require T-F18j for T-F17e and T-F17e for T-F17f
(`/Users/quietguy/Documents/Dev/Gauntlet/wt-agent-runtime-plan/tickets/T-F17e.md:5-6`;
`/Users/quietguy/Documents/Dev/Gauntlet/wt-agent-runtime-plan/tickets/T-F17f.md:5-6`), while console
T-F18i requires T-F17f. The result is:

`T-F17f -> T-F18i -> T-F18j -> T-F17e -> T-F17f`

Removing the dependency only from T-F18j's local frontmatter does not repair the contradictory
runtime source of truth, and it makes the early ticket unimplementable: T-F18j owns the complete
Costs UI and requires filters plus stable cursor paging (`tickets/T-F18j.md:8-24`, `55-59`), but the
shared collection seam does not land until T-F18b at wave 37 and residual DB paging does not land
until T-F18o at wave 38.

Required repair: split T-F18j into:

1. an early backend-only accounting/Birdseye unknown-usage bridge depending on T-F17b/c;
2. T-F17e depending on that bridge, then T-F17f;
3. a later full Costs UI/filter/paging ticket depending on T-F17f, T-F18b/T-F18o, T-F18i, and the
   bridge; and
4. T-F18k depending on the later Costs ticket.

Update both runtime planning sources, both ticket frontmatters, the console plan, TICKETS, and prompts
to the same acyclic graph.

### 2. Important — T-F19e cannot instrument all required real event producers

T-F19e AC-1 requires campaign, attempt, tool, agent, finding, approval, and component events in the
same transaction as authoritative state, and its test plan says to exercise every real write path
(`tickets/T-F19e.md:25-40`). Its production scope is limited to control-plane and API files
(`tickets/T-F19e.md:8-17`).

Real tool evidence is written directly in
`src/agentforge/security_tools/repository.py:90-148`, and real component heartbeats are written
directly in `src/agentforge/telemetry/outbound.py:420-440` and
`src/agentforge/scheduler.py:173-190`. Those files, their focused tests, and any required event-schema
migration are excluded. The ticket can therefore pass only a partial or synthetic producer test
while leaving Tooling/Live without real tool/component events.

Required repair: add every authoritative producer write path and migration/test scope to T-F19e, or
create serialized producer tickets for security-tool evidence and runtime-component heartbeat writes
and make T-F19e/T-F18k depend on them.

### 3. Important — deterministic and operational evidence scopes still overlap

T-F18l may write `docs/evidence/console/**` (`tickets/T-F18l.md:8-17`), which recursively includes
T-F18n's supposedly exclusive `docs/evidence/console/production/**` scope
(`tickets/T-F18n.md:8-10`). The deterministic implementation agent can therefore create or modify
production evidence despite the stated separation and its own prohibition on production claims.

Required repair: narrow T-F18l to a non-overlapping path such as
`docs/evidence/console/deterministic/**`; keep
`docs/evidence/console/production/**` exclusive to T-F18n.

### 4. Important — the required final 100-case/tool run has no executable ticket

The final plan requires a sequential 100-case run per target with the complete applicable tool plan
and immutable reports (`docs/planning/full-console-remediation.md:187-200`), but this is only Wave E
prose. T-F19b explicitly excludes an actual production run (`tickets/T-F19b.md:43-44`), T-F19d
excludes performing a live target run (`tickets/T-F19d.md:42-46`), T-F19e excludes production run
evidence, and T-F18n says no campaign/tool run occurs unless separately approved
(`tickets/T-F18n.md:29-34`).

Required repair: add a named operational execute/evidence/security-review ticket after T-F19e and
the runtime/adapters, bound to exact target authorization, distinct approval, worker/rate/request
limits, exact-SHA deployment, abort behavior, and immutable 100-case plus complete-tool-plan
reconciliation. It may truthfully remain `BLOCKED` until owner-controlled prerequisites exist, but
the required run cannot remain unowned prose.

## Re-review gate

Re-review after the same acyclic dependency graph is committed in both worktrees, T-F18j is split
into implementable scopes, T-F19e covers real producer writes, evidence globs are disjoint, and the
final authorized operational run has a mechanically ordered ticket.
