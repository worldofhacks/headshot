---
id: T-F17b
title: Persist append-only physical provider-call lineage
status: backlog
wave: 26
depends_on: [T-F00]
branch: ticket/T-F17b-provider-call-lineage
file_scopes:
  - src/agentforge/providers/lineage.py
  - src/agentforge/storage/models.py
  - src/agentforge/control_plane/store.py
  - migrations/versions/*_provider_call_lineage.py
  - docs/integration/migrations/provider-call-lineage-v1.md
test_scopes:
  - tests/test_provider_call_lineage.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf observability, cost, order, lineage, migrations
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-25, OPT-04, OPT-15, LEAD-05
  - docs/planning/agent-runtime-provenance.md Durable provider-call lineage
---

## Context
This deterministic Wave-26 ticket defines and persists the provider observation contract that
T-F17c emits and T-F17f reads. It supplements logical `agent_executions`; it must not reinterpret
configured assignment fields as observed provider facts. T-F00 supplies gate/spec-lint behavior.

## Acceptance Criteria
- **AC-1**: Given a successful physical provider attempt, when the Runner records it, then one
  append-only event durably binds organization/campaign/logical execution/role/attempt order to
  requested model, provider-confirmed returned model/upstream/request id, prompt and configuration
  hashes, input/output/reasoning tokens, measured cost, timestamps, and success status.
- **AC-2**: Given a timeout, retryable response, terminal response, model/provider mismatch,
  invalid usage, or invalid structured output, when recorded, then the event has a bounded typed
  error and explicit unavailable measurement state without fabricated identity, tokens, or zero cost.
- **AC-3**: Given a transient retry followed by success, when queried, then both physical events
  remain ordered and independently attributable to one logical agent execution.
- **AC-4**: Given a non-Runner database role or any role attempting UPDATE, DELETE, or TRUNCATE,
  when it touches provider-call events, then PostgreSQL rejects it; authenticated Web/Runner reads
  retain organization scoping.
- **AC-5**: Given baseline data, when the additive migration upgrades and downgrades an isolated
  copy, then existing `agent_executions` remain lossless and indexes support organization/role/time,
  campaign order, provider request id, and logical execution lookups.
- **AC-6**: Given credential-, session-, prompt-, hostile-evidence-, or provider-key-shaped input,
  when a lineage event is validated, then values are rejected/redacted and raw content is absent
  from persisted/audit output.

## Test Plan
- Unit: immutable contract, status/measurement shapes, bounds, error taxonomy, secret rejection.
- PostgreSQL integration: insert/query ordering, FKs/uniqueness/checks, role grants, append-only,
  migration round trip and indexes.
- E2E/eval: none; transport emission belongs to T-F17c.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged RED and Test Reviewer froze it.
- [ ] Migration note declares additive compatibility and rollback semantics.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F17b.md <DIFF_BASE>` exits 0 with live Postgres tests.
- [ ] Migration, role-grant, diff, and secret scans pass.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No OpenRouter request, Runner composition, API projection, console rendering, or historical
backfill that invents provider observations.
