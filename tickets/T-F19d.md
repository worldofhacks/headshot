---
id: T-F19d
title: Fan out and reconcile every applicable Tool ScanPlan item
status: backlog
wave: 35
depends_on: [T-F19c]
branch: ticket/T-F19d-tool-fanout-reconciliation
file_scopes:
  - src/agentforge/security_tools/coordinator.py
  - src/agentforge/security_tools/runner.py
  - src/agentforge/security_tools/recorder.py
  - src/agentforge/api/security_tools.py
test_scopes:
  - tests/security_tools/test_coordinator.py
  - tests/security_tools/test_runner.py
  - tests/security_tools/test_reconciliation.py
  - tests/test_security_tools_api.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Multi-agent and Tooling
  - docs/planning/full-console-remediation.md Tool execution model
---

## Context
T-F16f owns surface fanout. This ticket separately owns per-tool fanout and exact reconciliation.

## Acceptance Criteria
- **AC-1**: Every applicable plan item is scheduled exactly once; inapplicable, blocked, failed, and
  skipped items remain represented with reasons.
- **AC-2**: Generated candidates require independent review and accepted hashes bind the immutable
  100-case manifest before Policy Gateway live dispatch.
- **AC-3**: Live attempts only pass through Policy Gateway and bind permit, case, physical request,
  Judge, finding, report, and evidence lineage.
- **AC-4**: At most three workers exist globally and one target worker runs sequentially.
- **AC-5**: Reconciliation compares planned items, processes, artifacts, candidates, attempts,
  requests, adjudications, failures, and aborts; incomplete work never reports complete.

## Test Plan
Fanout/idempotency, review gate, worker bounds, gateway-only dispatch, abort, and reconciliation.

## Definition of Done
- [ ] Independent RED/review/freeze/GREEN/code/security sequence passes.

## Out of Scope
Performing a live target run or presenting console read models.
