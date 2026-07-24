---
id: T-F18g
title: Require launch preflight, preserve reasons, and confirm material commands
status: backlog
wave: 43
depends_on: [T-F18b, T-F18f, T-F17f]
branch: ticket/T-F18g-approval-preflight
file_scopes:
  - src/agentforge/api/read_models.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/api/paths.ts
  - console/src/commands/registry.ts
  - console/src/components/CommandButton.tsx
  - console/src/screens/ConsoleScreens.tsx
  - console/src/screens/AgentToolScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - console/tests/command-button.test.tsx
  - console/tests/read-models.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Discovery, Remediation, & Trust
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-27, USR-04, USR-07, LEAD-09
---

## Context
The server already has a network-free campaign authorization preflight route, but Approvals does not
call it. CommandButton discards server reason codes and does not confirm launch/approval/denial.
Frontend permission checks remain courtesy controls; backend authorization stays authoritative.

## Acceptance Criteria
- **AC-1**: Given a selected approved request, when Approval detail loads, then a typed, authenticated
  preflight is fetched and exact scope, caps, runtime/config/credential-reference readiness, zero-call
  counters, `ok`, blockers, `reason_code`, and freshness are displayed.
- **AC-2**: Given failed, unavailable, stale, or scope-mismatched preflight, when launch is considered,
  then Launch is disabled and no command is sent; passing preflight never substitutes for distinct
  human approval.
- **AC-3**: Given approve, deny, launch, abort, publish, or resolve, when clicked, then an explicit
  confirmation names the exact resource and material effect before the first command request.
- **AC-4**: Given the versioned command registry, when checked, then every authorization request,
  approval/denial, campaign launch/abort, finding decision/publication/resolution, target/version/
  surface/lifecycle mutation, configuration validation/publication/activation, and agent
  configuration command has exact resource/effect/spend/destructive/confirmation metadata and every
  rendered material command consumes that registry.
- **AC-5**: Given unavailable/conflict/error acknowledgement, when returned, then bounded
  `reason_code`, acknowledgement/resource ID, and correlation context are retained for the operator
  and retry reuses the same idempotency key only for the unchanged command.
- **AC-6**: Given confirmation cancel, double-submit, or payload/path change after a prior failure,
  when handled, then cancel sends zero calls, one confirmed action sends once, concurrent duplicates
  are blocked, and a changed command receives a fresh idempotency identity.
- **AC-7**: Given launcher equals approver or permissions are absent, when controls render, then
  backend-derived denial remains visible and no client manipulation enables the command.

## Test Plan
- API/read-model: typed preflight pass/block/stale and zero-call guarantees.
- Frontend: exhaustive command-registry parity, confirmation cancel/accept, double-submit,
  changed-command idempotency, reason fidelity, self-approval denial.
- E2E: two-role fixture flow through request, approve, preflight, and launch-ready state without
  making target/provider calls.
- Eval: none.

## Definition of Done
- [ ] Independent Test Agent records RED and Test Reviewer freezes corrected tests.
- [ ] Separate Implementation Agent reaches GREEN without test changes.
- [ ] Orchestrator reruns API/auth, console, typecheck, bundle, and browser gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Creating a real approval, launching a campaign, or weakening two-person control. T-F17f must land
before this ticket because both own `AgentToolScreens.tsx`.
