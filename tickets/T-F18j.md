---
id: T-F18j
title: Preserve unknown and partial provider accounting in backend projections
status: backlog
wave: 29
depends_on: [T-F17b, T-F17c]
branch: ticket/T-F18j-accounting-unknown-bridge
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - src/agentforge/api/birdseye.py
test_scopes:
  - tests/test_postgres_api_m1d.py
  - tests/test_work_unit_accounting.py
  - tests/test_birdseye_api.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Cost, Scale, & Model Constraints
  - Week_3_AgentForge.pdf Observability Layer
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-25, PRD-33, LEAD-05
  - T-F17 provider accounting contract
---

## Context
This early backend-only bridge prevents T-F17e deployment projections from coercing absent provider
usage to zero. It lands before T-F17f and deliberately owns no Costs UI, filter, route, or paging
work; T-F18p owns those after the shared collection and trace contracts land.

## Acceptance Criteria
- **AC-1**: Given full, partial, or absent provider observations, when backend campaign and Birdseye
  projections aggregate them, then known values remain measured, missing values remain
  `not_observed`, and completeness is exactly complete, partial, or not_observed.
- **AC-2**: Given provider-confirmed usage, when aggregated, then input/output/reasoning tokens and
  measured cost reconcile to provider call records; token-times-price is never substituted for
  measured cost.
- **AC-3**: Given missing usage or cost, when projected, then that field is `not_observed`; known
  values elsewhere remain visible and no default, constructor value, or serialization coerces it to
  zero.
- **AC-4**: Given mismatched currency, duplicate accounting IDs, negative values, or summary/ledger
  disagreement, when projected, then state is degraded with an explicit delta/reason rather than
  force-balanced.
- **AC-5**: Given partial usage, timeout-after-send, retries, or mixed known/unknown physical calls,
  when campaign totals and Birdseye are projected, then known subtotals and unknown counts remain
  separate and provider/campaign summaries are not double counted.
- **AC-6**: Given T-F17e's deployment accounting gate, when these backend projections fail any
  full/partial/unknown or no-double-count case, then hosted deployment remains blocked.

## Test Plan
- Integration: full/partial observed accounting, timeout-after-send, mixed known/unknown, mismatch,
  duplicate, no-double-count, multi-currency, and Birdseye/campaign totals.
- Contract: consume T-F17 accounting fields and preserve exact decimals/currency.
- Eval: none.

## Definition of Done
- [ ] T-F17b/T-F17c provider-lineage prerequisites are merged before GREEN integration; T-F17e
  deployment capability remains blocked until this ticket passes.
- [ ] Independent Test Agent records RED and Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without test edits.
- [ ] Orchestrator reruns accounting, API, and Birdseye backend gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Costs UI, routes, filters, paging, cost projections at 1K/10K/100K, provider billing reconciliation
outside persisted evidence, or new provider calls. T-F18p owns the later full Costs page.
