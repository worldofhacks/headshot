---
id: T-F06a
title: Implement fresh regression replay executor
status: backlog
wave: 8
depends_on: [T-F05a, T-F14b]
branch: ticket/T-F06a-replay-code
file_scopes:
  - src/agentforge/regression/replay.py
  - src/agentforge/regression/executor.py
  - src/agentforge/scheduler.py
  - src/agentforge/runner.py
test_scopes: [tests/test_regression_execution.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Regression Harness
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-23, PRD-24, PRD-36, OPT-16
---

## Context
Wave 8 deterministic code consumes T-F05a's persisted campaign/lineage interface and T-F14b's typed failure contracts, and produces the fresh-replay executor and duration metrics consumed by later evidence and benchmark tickets. `Week_3_AgentForge.pdf`, PRD-23/24/36 and OPT-16, package contract hashes, accepted baseline hashes, and current target/release hashes are authoritative.

## Acceptance Criteria
- **AC-1**: Given admitted case/trigger, executor creates a new campaign ID and target call plan; prior verdict reuse causes exit 3.
- **AC-2**: Right-reason comparator keys expected-safe oracle, case hash and target version; wording-only change cannot pass.
- **AC-3**: Cross-category comparator uses accepted baseline artifact hash and emits regression when state worsens `NO_EXPLOIT_OBSERVED→{EXPLOIT_LIKELY,EXPLOIT_CONFIRMED,INDETERMINATE,ERROR}` or confirmed/likely count increases; linked category evidence required.
- **AC-4**: Missing authorization/calibration/version/integrity parks with zero adapter calls.
- **AC-5**: Fixture critical-subset/full-suite durations are emitted for downstream SLO measurement.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F06a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No live replay, benchmark, promotion, or remediation.
