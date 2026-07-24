---
id: T-F18n
title: Record authenticated exact-SHA production console evidence
status: backlog
wave: 50
depends_on: [T-F16f, T-F17f, T-F19e, T-F18l]
branch: ticket/T-F18n-production-console-evidence
file_scopes:
  - docs/evidence/console/production/**
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Submission Requirements
  - docs/planning/full-console-remediation.md Current blockers requiring owner/external state
---

## Context
Deterministic route checks cannot prove production authentication, deployment, or live data. This
operational ticket records that evidence only after owner-controlled release gates.

## Acceptance Criteria
- **AC-1**: GitHub and GitLab main resolve to the same exact SHA with both CI systems green.
- **AC-2**: Owner deployment grant, Railway release receipt, health, environment, and rollback
  binding identify that SHA.
- **AC-3**: An authenticated Headshot organization principal traverses every retained route at
  desktop/mobile widths and records redacted screenshots/results for live, empty, stale, degraded,
  forbidden, retry, command-confirmation, and keyboard behavior.
- **AC-4**: Evidence verifies page fields against authenticated API responses without credentials,
  session IDs, secrets, or synthetic patient payloads.
- **AC-5**: No campaign or tool run occurs unless separately approved; absence is recorded BLOCKED.

## Test Plan
Operational execution, evidence review, and security review; no implementation.

## Definition of Done
- [ ] Owner deployment, Clerk authentication, dual-CI, and rollback gates are evidenced.
- [ ] Independent evidence and security reviewers pass the redacted package.

## Out of Scope
Product changes, self-approval, or an implicitly authorized live scan.
