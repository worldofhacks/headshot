---
id: T-F18p
title: Complete the Costs UI with stable filters and database paging
status: backlog
wave: 46
depends_on: [T-F18j, T-F17f, T-F18b, T-F18o, T-F18i]
branch: ticket/T-F18p-costs-ui-paging
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - src/agentforge/api/router.py
  - console/src/types.ts
  - console/src/api/paths.ts
  - console/src/api/read-models.ts
  - console/src/screens/ObservabilityScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - tests/test_api_integration.py
  - console/tests/observability.test.ts
  - console/tests/read-models.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Cost, Scale, & Model Constraints
  - Week_3_AgentForge.pdf Observability Layer
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-25, PRD-33, LEAD-05
  - T-F18j backend accounting bridge
---

## Context
T-F18j preserves early backend unknown/partial accounting. After T-F17f, the shared collection seam,
residual paging, and unified trace lineage land, this ticket owns the complete Costs route/read model
and browser experience.

## Acceptance Criteria
- **AC-1**: Costs separately displays logical cases, target physical requests, provider calls, agent
  executions, token kinds, measured currency cost, budget caps, elapsed time, and source lineage.
- **AC-2**: Known, partial, and not-observed usage from T-F18j render per field; unknown values never
  become zero and token-times-price is never substituted for measured provider cost.
- **AC-3**: Currency mismatch, duplicate accounting identity, negative value, or ledger/summary
  disagreement renders a bounded degraded reason and delta rather than force-balancing.
- **AC-4**: Campaign, provider, role, and time filters are typed, URL-stable, and apply to both rows
  and scoped totals.
- **AC-5**: PostgreSQL pages cost rows by recorded-at/accounting-ID composite cursor with a bounded
  limit; concurrent inserts, ties, and page transitions cannot duplicate or omit snapshot rows.
- **AC-6**: API route/path contracts preserve correlation, authorization-before-query, invalid/
  foreign cursor denial, and exact-decimal/currency values through strict TypeScript decoding.
- **AC-7**: Retries, timeout-after-send, and mixed known/unknown calls reconcile with Traces and
  Birdseye without double counting.

## Test Plan
Database/API tests for authorization, filters, composite cursor, ties, inserts, totals, decimals,
currency, and reconciliation; frontend/browser tests for known/partial/unknown and error states.

## Definition of Done
- [ ] Independent RED/review/freeze/GREEN/code/security sequence passes.
- [ ] Orchestrator reruns accounting, API, console, typecheck, bundle, and browser gates.

## Out of Scope
Provider calls, price estimation, deployment, or changing T-F18j's early backend contract.
