---
id: T-F19b
title: Execute pinned offline and repository tool brokers
status: backlog
wave: 33
depends_on: [T-F19a]
branch: ticket/T-F19b-tool-brokers
file_scopes:
  - src/agentforge/security_tools/brokers/**
  - src/agentforge/security_tools/catalog.py
  - src/agentforge/security_tools/runner.py
  - security-tools/**
  - scripts/security-tools/**
test_scopes:
  - tests/security_tools/test_brokers.py
  - tests/security_tools/test_security_tools.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Optional Engineering Deliverables
  - docs/planning/full-console-remediation.md Tool execution model
---

## Context
Capability labels are not executions. This ticket owns bounded process brokers and artifacts for
offline candidate generation and exact-SHA repository assurance.

## Acceptance Criteria
- **AC-1**: Garak, PyRIT, Giskard, and Promptfoo run pinned, bounded brokers that persist process,
  config, candidate, review, and artifact lineage without target traffic.
- **AC-2**: Semgrep, pip-audit, npm-audit, and Gitleaks bind signed results to the exact release SHA.
- **AC-3**: Installed, configured, generated, executed, and evidenced/adjudicated remain independent.
- **AC-4**: Timeout, malformed output, missing executable, and nonzero exit become explicit terminal
  events; no broker can silently pass.
- **AC-5**: Arguments, paths, output, and artifacts are allowlisted and redacted.

## Test Plan
Hermetic fake-process broker tests plus artifact, timeout, error, and redaction cases.

## Definition of Done
- [ ] Independent RED/review/freeze/GREEN/code/security sequence passes.

## Out of Scope
ZAP, live campaign dispatch, UI projection, and an actual production run.
