---
id: T-F19c
title: Add separately authorized passive ZAP execution
status: backlog
wave: 34
depends_on: [T-F19b]
branch: ticket/T-F19c-passive-zap
file_scopes:
  - src/agentforge/security_tools/authorization.py
  - src/agentforge/security_tools/zap.py
  - src/agentforge/security_tools/coordinator.py
  - src/agentforge/control_plane/**
test_scopes:
  - tests/security_tools/test_zap.py
  - tests/security_tools/test_authorization.py
  - tests/test_control_plane_api.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Human-in-the-loop and Tooling
  - docs/planning/full-console-remediation.md Tool execution model
---

## Context
Passive web scanning is materially different from chat dispatch and requires its own exact permit.

## Acceptance Criteria
- **AC-1**: ZAP requires a separate two-person permit bound to exact origin, target version, surface,
  release SHA, five-minute cap, depth five, and at most ten children.
- **AC-2**: Session credentials are never supplied to ZAP and active attacks are disabled.
- **AC-3**: Missing, expired, mismatched, or revoked authorization causes zero process/network calls.
- **AC-4**: Permit, process, passive findings, artifact, and terminal events are append-only.
- **AC-5**: Abort and timeout stop work and reconcile partial evidence truthfully.

## Test Plan
Zero-call denial matrix, bounded passive profile, abort, timeout, artifact, and redaction tests.

## Definition of Done
- [ ] Independent RED/review/freeze/GREEN/code/security sequence passes.

## Out of Scope
Active ZAP attacks, credentialed crawling, live execution, and UI projection.
