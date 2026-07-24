---
id: T-F19f
title: Execute and evidence the separately approved final target runs
status: backlog
wave: 51
depends_on: [T-F16f, T-F17f, T-F19e, T-F18n]
branch: ticket/T-F19f-final-target-runs
file_scopes:
  - docs/evidence/final-target-runs/**
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Final Submission and Performance Baseline
  - docs/planning/full-console-remediation.md Wave E
---

## Context
This operational ticket owns the required final run; deterministic tool tickets and console evidence
cannot substitute for live, separately authorized results. It changes no product or tests and may
truthfully remain `BLOCKED` until every owner-controlled prerequisite exists.

## Acceptance Criteria
- **AC-1**: The exact release SHA is equal and green on GitHub/GitLab, deployed as the same reviewed
  Web/Runner image with current migration, health, rollback, and authenticated preflight evidence.
- **AC-2**: Each final target has its own exact target/version/surface/session/synthetic-patient/
  corpus authorization and distinct human approver; missing, stale, mismatched, or revoked authority
  produces zero tool, provider, upload, or target calls and a bounded `BLOCKED` record.
- **AC-3**: Week 1 and Week 2 run sequentially with one target worker, no more than three total
  workers, exactly 100 immutable logical cases per target, no target retry, at most the separately
  authorized physical-request cap, at most 0.5 request/second per origin, two-hour timeout, and
  immediate policy/budget/rate/abort enforcement.
- **AC-4**: Every applicable Tool ScanPlan item is represented; pinned repository/offline generators
  run first, independently reviewed accepted hashes bind the 100-case manifest, live cases pass only
  through Policy Gateway, and passive ZAP runs only under its separate exact bounded permit.
- **AC-5**: All four locked hosted roles record prompt/configuration hashes, requested and returned
  models, upstream, physical provider calls, tokens, measured/unknown cost, latency, parentage, Judge
  verdict, report, and error evidence without inferred success.
- **AC-6**: Immutable reconciliation accounts for every plan item, process, artifact, candidate,
  review, logical case, physical request, provider call, adjudication, finding, abort, and failure.
  Fewer than three genuine independently reproduced findings remains explicitly incomplete.
- **AC-7**: The final evidence package contains redacted performance, bottleneck, coverage, cost,
  pass/fail, reproducibility, and complete-tool-plan reports per target, signed to exact SHA; it
  contains no SID, bearer credential, secret, real PHI, or extracted-bundle bytes.
- **AC-8**: Week 2 document uploads occur only under their separate authorization and exact bounded
  synthetic-document rules; absent Runner-private fixture authority leaves that portion BLOCKED.

## Test Plan
Operational execute, independent evidence review, and independent security review; no implementation.

## Definition of Done
- [ ] Distinct approvals and all exact-SHA deployment/runtime/tool gates are recorded before execute.
- [ ] Independent Evidence and Security reviewers reconcile raw artifacts to reports and pass.

## Out of Scope
Product/test changes, self-approval, infrastructure mutation, credential rotation, load/DoS testing,
real PHI, or runs against any target outside the two authorized final targets.
