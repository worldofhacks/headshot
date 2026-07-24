# T-F18 console remediation plan review

Reviewed commit: `250d95cc3474e0313357a60209a7e78b99144691`
Verdict: **CHANGES_REQUIRED**

The plan correctly keeps Coverage, merges resilience-over-time and regression truth into
**Coverage & Regression**, removes the standalone Resilience navigation/page with a compatibility
replace-redirect, fixes Birdseye never-run/false-complete semantics, requires complete stored
vulnerability reports, preserves two-person launch authorization, and separates observed cost/model
facts from configuration. Those decisions match the Week 3 PRD.

## Findings

1. **Critical - no ticket owns the tool fanout that Tooling and Live depend on.** The plan says it
   consumes a ScanPlan from a separate tool-orchestration workstream
   (`docs/planning/console-pages-remediation.md:73-92`, `159-166`), while T-F18d expressly cannot add
   schedulers or execute tools (`tickets/T-F18d.md:28-31`, `55-64`;
   `.tdd-swarm/prompts/T-F18d-implement.md:2-4`). No dependency names an implementing ticket.
   T-F16f's `final_target_scan_plan` is a target/surface-child contract, not the required per-tool
   plan: its fields and children contain no tool identity, process run, artifact, candidate-review,
   static-release evidence, or separate ZAP authorization
   (`tickets/T-F16f.md:29-44` in the T-F16 worktree). As written, all-tools launch can remain
   permanently `blocked: scan_plan_not_persisted` while every T-F18 ticket passes. Add a versioned
   tool-plan/orchestration/persistence ticket (or explicitly extend T-F16f) that owns applicable-tool
   fanout, brokers, retained events/artifacts, separate authorization, and reconciliation; make
   T-F18d/e/k/l depend on its exact ID.

2. **Important - cross-plan dependencies and write collisions are prose-only.** T-F18h declares only
   `T-F18g` despite requiring the T-F16 catalog (`tickets/T-F18h.md:5-6`, `48-55`); T-F18i declares
   only T-F18b/h despite requiring T-F17 lineage (`tickets/T-F18i.md:5-6`, `49-56`); T-F18l depends
   only on T-F18 tickets (`tickets/T-F18l.md:5-6`). T-F17f writes the same API/TypeScript projection
   files as T-F18b-d/f-i and the same AgentTool screen as T-F18d
   (`tickets/T-F17f.md:8-21` in the T-F17 worktree). The local Wave 1-11 addendum also collides with
   the repository's global waves and cannot enforce merge order (`TICKETS.md:143-163`). Replace
   wildcard/prose prerequisites with exact ticket IDs and a single global sequence or explicit
   rebase point. T-F18l must wait for T-F16, T-F17f, and the tool-plan producer before it can certify
   the whole console. Also land the currently missing trace target
   `docs/planning/full-console-remediation.md`, referenced by `tickets/T-F18d.md:22-25`, before RED.

3. **Important - this is not yet a full page/module inventory.** The route decision table omits
   `/config` and has no remediation ticket for Configuration
   (`docs/planning/console-pages-remediation.md:18-36`). The current projection unconditionally labels
   that snapshot `operational and evidenced` while mixing constructor booleans and catalog records
   (`src/agentforge/api/postgres.py:573-617`), which is one of the known truth defects. `/audit` is an
   authenticated API resource with no route decision (`src/agentforge/api/router.py:450-452`).
   T-F18l says its checker rejects orphaned resources/commands but is forbidden from page-specific
   fixes (`tickets/T-F18l.md:31-45`; `.tdd-swarm/prompts/T-F18l-implement.md:2-4`). Add a Config truth
   ticket, explicitly decide whether Audit is a page or is subsumed by Traces, and include Agents
   via the exact T-F17f dependency.

4. **Important - Tooling does not explicitly preserve the five different facts requested.**
   T-F18d defines plan execution statuses and one capability-versus-execution distinction
   (`tickets/T-F18d.md:33-52`), but it does not require independent
   `installed`, `configured`, `generated`, `executed`, and `evidenced/adjudicated` states. A tool can
   therefore still inherit a collapsed catalog label or make candidate generation look like target
   execution. Add these independent dimensions, their authoritative sources/freshness, and negative
   fixtures proving that none implies another.

5. **Important - T-F18b cannot prove database pagination within its write/test scope.** AC-1 promises
   bounded defaults and rejection before querying, but `src/agentforge/api/postgres.py` and all
   page-specific SQL are excluded (`tickets/T-F18b.md:8-22`, `30-37`, `62-63`). Its test plan also
   promises an E2E keyboard/retry flow without declaring a browser test scope
   (`tickets/T-F18b.md:48-52`). Split this into an atomic page-request/envelope seam plus serialized
   page query tickets, or include the concrete backend and stable-sort/cursor migrations. Declare a
   disjoint browser test file. Otherwise the release gate that every list endpoint is bounded and
   stably pageable (`docs/planning/console-pages-remediation.md:140-147`) is not reachable.

6. **Important - material-command confirmation coverage is narrower than the plan invariant.**
   The invariant covers all spend-causing/destructive commands
   (`docs/planning/console-pages-remediation.md:66-68`), but T-F18g names only approve, deny, launch,
   abort, publish, and resolve and cannot edit AgentToolScreens
   (`tickets/T-F18g.md:8-19`, `39-50`). Target/version/surface/lifecycle mutations, configuration
   publication, agent configuration, and authorization requests are not mechanically inventoried.
   Require a command registry with exact resource/effect/confirmation metadata for every material
   route, update all call sites (including the Agents/Configuration owners), and test cancel,
   double-submit, changed-command idempotency, and server-reason preservation per command class.

7. **Important - the SSE ticket can pass against events production does not emit.** T-F18k assumes
   campaign/attempt/tool/agent/finding/approval/component events, tests a mocked stream, and makes
   event production and tool fanout out of scope (`tickets/T-F18k.md:25-48`, `57-58`). Add an
   event-producer contract/integration prerequisite for every mapped resource, or a bounded
   authoritative polling/reconciliation fallback. Tests must prove a real persisted tool/agent event
   reaches the stream; a synthetic event-to-resource unit test is insufficient.

8. **Important - T-F18l mixes deterministic implementation with operational release evidence.**
   AC-5 requires authenticated production URL evidence (`tickets/T-F18l.md:43-45`) while the
   implementation prompt forbids deployment/live action and the DoD records owner verification
   separately (`.tdd-swarm/prompts/T-F18l-implement.md:2-4`; `tickets/T-F18l.md:53-62`). Split the
   deterministic page registry/accessibility matrix from a final operational evidence/reviewer
   ticket, or move production verification wholly into the release gate. The operational task must
   depend on exact-SHA dual CI, owner deployment, Headshot authentication, and all external runtime
   prerequisites.

## Required re-review inputs

- Revised plan, tickets, prompts, and TICKETS dependency graph covering all findings above.
- A committed, versioned per-tool ScanPlan producer contract or an exact dependency on its ticket.
- An explicit integration order for T-F16, T-F17, T-F18, and the operational release proof.
