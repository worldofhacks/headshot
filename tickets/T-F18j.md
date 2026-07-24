---
id: T-F18j
title: Reconcile measured target and provider accounting in backend read models
status: backlog
wave: 29
depends_on: [T-F17b, T-F17c]
branch: ticket/T-F18j-cost-accounting-truth
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
Backend accounting currently mixes campaign summaries and agent spans and sets provider request
count to zero. This early bridge must make PostgreSQL, shared read models, campaign totals, and
Birdseye preserve observed/unknown provider facts before hosted deployment. It is backend-only;
T-F18p owns the later full Costs UI after T-F17f, T-F18b/T-F18o, and T-F18i.

## Acceptance Criteria
- **AC-1**: Given a campaign, when Costs loads, then target physical requests, provider calls, agent
  executions, logical cases, tokens by kind, measured currency cost, budget caps, and elapsed time are
  separate observed fields with source lineage.
- **AC-2**: Given provider-confirmed usage, when aggregated, then input/output/reasoning tokens and
  measured cost reconcile to provider call records; token-times-price is never substituted for
  measured cost.
- **AC-3**: Given missing usage or cost, when projected, then that field is `not_observed`; observed
  target and provider data elsewhere remains present in the backend contract.
- **AC-4**: Given mismatched currency, duplicate accounting IDs, negative values, or summary/ledger
  disagreement, when projected, then state is degraded with an explicit delta/reason rather than
  force-balanced.
- **AC-5**: Given partial usage, timeout-after-send, or mixed known/unknown physical calls, when
  campaign totals and Birdseye are projected, then known totals remain measured, unknown portions
  remain `not_observed`, completeness is `partial`, and retries/provider/campaign summaries are not
  double counted.
- **AC-6**: Given the same authoritative campaign scope, when PostgreSQL, campaign totals, and
  Birdseye are projected, then their known sums, measured counts, and unknown counts reconcile
  without frontend transformation.

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
- [ ] Orchestrator reruns backend accounting/API/Birdseye gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Costs UI, frontend decoders/rendering/filtering/paging, cost projections at 1K/10K/100K, provider
billing reconciliation outside persisted evidence, or new provider calls. Those UI concerns remain
in T-F18p after T-F17f/T-F18b/T-F18o/T-F18i.
