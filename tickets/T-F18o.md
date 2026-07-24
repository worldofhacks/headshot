---
id: T-F18o
title: Add backend-stable pagination for remaining console resources
status: backlog
wave: 38
depends_on: [T-F18b, T-F17f, T-F19e]
branch: ticket/T-F18o-console-db-pagination
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - src/agentforge/api/router.py
test_scopes:
  - tests/test_postgres_api_m1d.py
  - tests/test_api_integration.py
  - tests/test_api_authorization_order.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Observability Layer
  - docs/planning/full-console-remediation.md Shared interaction quality
---

## Context
T-F18b owns the browser collection seam. This ticket owns database pagination for remaining shared
campaign, attempt, approval, component, agent, activity, and audit resources.

## Acceptance Criteria
- **AC-1**: Every residual list endpoint uses a stable composite cursor and deterministic tie-breaker.
- **AC-2**: Filters persist across pages; concurrent inserts cannot duplicate or omit snapshot rows.
- **AC-3**: Organization and permission checks occur before database query execution.
- **AC-4**: Invalid/foreign cursors fail closed; page size is bounded at 200.
- **AC-5**: Existing single-page clients remain backward compatible while totals and continuation
  metadata stay scoped.

## Test Plan
PostgreSQL and API integration tests for authorization order, ties, inserts, filters, and bad cursors.

## Definition of Done
- [ ] Independent RED/review/freeze/GREEN/code/security sequence passes.

## Out of Scope
Page-specific coverage, tooling, findings, trace, cost, and Config/Audit projections.
