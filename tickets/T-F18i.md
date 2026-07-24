---
id: T-F18i
title: Unify target, agent, provider, and handoff trace lineage
status: backlog
wave: 45
depends_on: [T-F18b, T-F18h, T-F17f]
branch: ticket/T-F18i-trace-lineage
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/screens/ObservabilityScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - tests/test_outbound_telemetry.py
  - console/tests/observability.test.ts
  - console/tests/read-models.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Observability Layer
  - Week_3_AgentForge.pdf Observability Strategy appendix
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-25, OPT-09, LEAD-05
  - T-F17 provider lineage contract
---

## Context
Trace summaries currently filter to physical HTTP requests even though the projection also appends
agent rows. The final view must preserve span kind and parent lineage for target requests, agent
executions, provider calls, handoffs, and historical summaries.

## Acceptance Criteria
- **AC-1**: Given one four-role campaign, when traces are read, then each row has an explicit span
  kind, durable ID, parent ID, campaign/attempt, role/tool, requested/returned provider model,
  provider request ID when observed, timestamps, status/error, and evidence references.
- **AC-2**: Given target and hosted-provider outbound calls, when displayed, then physical-request
  metrics are computed per span kind; agent/provider spans are visible and never discarded by the
  physical-target predicate.
- **AC-3**: Given campaign, attempt, role, tool, span-kind, status, or time filters and a cursor, when
  queried, then results are organization-scoped, stable, bounded, newest-first, and carry filter state
  across pagination.
- **AC-4**: Given missing provider lineage, legacy traces, or an unobserved parent, when shown, then
  fields say `not_observed`/`historical_not_instrumented`; no fake link or request count is inferred.
- **AC-5**: Given hostile previews or locators, when rendered, then bounded redacted text and hashes
  are shown without credentials or active markup.
- **AC-6**: Given trace filters and cursor paging, when queried, then PostgreSQL uses a stable
  started-at/span-kind/durable-ID order and never duplicates or omits rows across pages.

## Test Plan
- Integration: complete chain, missing parent, provider call, legacy row, org isolation, paging.
- Frontend: span-kind filters, all-spans summary, bounded hostile preview.
- Contract: consume T-F17 persisted provider lineage; do not duplicate its storage fields.
- Eval: none.

## Definition of Done
- [ ] T-F17 provider lineage prerequisite is merged before GREEN integration.
- [ ] Independent Test Agent records RED and Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without test edits.
- [ ] Orchestrator reruns telemetry/API/console/typecheck/browser gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Sending provider calls, changing telemetry export, or inventing lineage for historical records.
