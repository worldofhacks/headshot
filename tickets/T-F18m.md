---
id: T-F18m
title: Make Configuration and embedded Audit truthful
status: backlog
wave: 47
depends_on: [T-F18k, T-F18o, T-F17f, T-F19e]
branch: ticket/T-F18m-config-audit-truth
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/screens/ConsoleScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - console/tests/read-models.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Configuration and Audit requirements
  - docs/planning/full-console-remediation.md Configuration and Audit
---

## Context
Configuration currently risks turning static booleans into runtime truth. Audit remains available
inside Configuration rather than becoming another navigation page.

## Acceptance Criteria
- **AC-1**: Package installation, catalog configuration, activation, current heartbeat, execution,
  and evidence are separate sourced and fresh facts.
- **AC-2**: Constructor/default booleans never imply readiness or execution; unknown stays unknown.
- **AC-3**: Configuration shows release SHA, environment, deployment, provider, tool, and policy
  lineage with stale/degraded/unavailable states.
- **AC-4**: Embedded Audit is append-only, permission-gated in the backend, stably paged/filtered, and
  links bounded correlation IDs without rendering secrets.
- **AC-5**: Empty/error/forbidden states are actionable and truthful.

## Test Plan
Projection and browser tests for false-ready negatives, freshness, RBAC, pagination, and redaction.

## Definition of Done
- [ ] Independent RED/review/freeze/GREEN/code/security sequence passes.

## Out of Scope
A standalone Audit navigation destination or changing runtime configuration.
