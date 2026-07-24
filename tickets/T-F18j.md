---
id: T-F18j
title: Reconcile measured target and provider accounting on Costs
status: backlog
wave: 9
depends_on: [T-F18i]
branch: ticket/T-F18j-cost-accounting-truth
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/screens/ObservabilityScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - tests/test_work_unit_accounting.py
  - console/tests/observability.test.ts
  - console/tests/read-models.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Cost, Scale, & Model Constraints
  - Week_3_AgentForge.pdf Observability Layer
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-25, PRD-33, LEAD-05
  - T-F17 provider accounting contract
---

## Context
Costs currently mixes campaign summaries and agent spans, sets provider request count to zero, and
shows unconditional prose claiming token usage is unavailable. It must reconcile observed target and
provider accounting while leaving genuinely absent values unknown.

## Acceptance Criteria
- **AC-1**: Given a campaign, when Costs loads, then target physical requests, provider calls, agent
  executions, logical cases, tokens by kind, measured currency cost, budget caps, and elapsed time are
  separate observed fields with source lineage.
- **AC-2**: Given provider-confirmed usage, when aggregated, then input/output/reasoning tokens and
  measured cost reconcile to provider call records; token-times-price is never substituted for
  measured cost.
- **AC-3**: Given missing usage or cost, when displayed, then that field is `not_observed`; observed
  target and provider data elsewhere remains visible and no page-wide false claim hides it.
- **AC-4**: Given mismatched currency, duplicate accounting IDs, negative values, or summary/ledger
  disagreement, when projected, then state is degraded with an explicit delta/reason rather than
  force-balanced.
- **AC-5**: Given campaign/provider/role/time filters and cursor paging, when used, then totals apply
  to the selected authoritative scope and filters remain stable.

## Test Plan
- Integration: full observed accounting, partial usage, mismatch, duplicate, multi-currency, paging.
- Frontend: conditional unknown labels, reconciliation deltas, filters.
- Contract: consume T-F17 accounting fields and preserve exact decimals/currency.
- Eval: none.

## Definition of Done
- [ ] T-F17 accounting prerequisite is merged before GREEN integration.
- [ ] Independent Test Agent records RED and Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without test edits.
- [ ] Orchestrator reruns accounting/API/console/typecheck/browser gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Cost projections at 1K/10K/100K, provider billing reconciliation outside persisted evidence, or new
provider calls.
