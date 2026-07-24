---
id: T-F18h
title: Enforce canonical target identity and enabled-surface launch readiness
status: backlog
wave: 44
depends_on: [T-F18g, T-F16f]
branch: ticket/T-F18h-target-registry-truth
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/screens/ConsoleScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - tests/target/test_target_registry.py
  - console/tests/read-models.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live-system hard gate and trust boundaries
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-09, LEAD-09
  - T-F16f canonical final-target catalog and surface-fanout contract
---

## Context
The production catalog may contain canonical IDs and aliases for the same final target, and campaign
template construction can select the first surface even when disabled. T-F16 owns adapter/catalog
correction. This ticket makes the API and console fail closed if those invariants are not true.

## Acceptance Criteria
- **AC-1**: Given multiple rows that resolve to one canonical final target/version/origin, when the
  registry is projected, then the response is degraded with `duplicate_target_alias`; it does not
  silently choose or display duplicates as independent targets.
- **AC-2**: Given target surfaces, when a campaign template is exposed, then it binds one explicitly
  enabled, adapter-ready surface; disabled, draft, uncredentialed, or unavailable surfaces cannot
  produce a launchable template.
- **AC-3**: Given the two canonical final targets, when rendered, then exact identity, lifecycle,
  environment, adapter readiness, enabled surfaces, auth posture, and logical/physical/retry/rate/
  timeout caps are visible without revealing credential references.
- **AC-4**: Given list refresh/pagination, when a target is selected, then selection is retained by
  canonical target+version ID and resolves to the new record; stale object state cannot authorize a
  request.
- **AC-5**: Given duplicate or no-ready-surface state, when launch controls render, then they are
  blocked with the server reason and no authorization command is sent.

## Test Plan
- Integration: duplicate alias, disabled-first surface, no ready surface, two canonical targets.
- Frontend: durable selection, explicit readiness/caps, no credential leakage.
- Contract: T-F16 canonical catalog fixture consumed without modifying adapter code.
- Eval: none.

## Definition of Done
- [ ] T-F16 canonical catalog prerequisite is merged before GREEN integration.
- [ ] Independent Test Agent records RED and Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without test edits.
- [ ] Orchestrator reruns target/API/console/typecheck/browser gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Choosing canonical aliases, changing adapters, or provisioning credentials.
