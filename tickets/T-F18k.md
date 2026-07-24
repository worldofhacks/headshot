---
id: T-F18k
title: Stabilize Live selection and target event-driven reconciliation
status: backlog
wave: 10
depends_on: [T-F18d, T-F18e, T-F18g, T-F18h, T-F18j]
branch: ticket/T-F18k-live-event-reconciliation
file_scopes:
  - console/src/App.tsx
  - console/src/screens/ConsoleScreens.tsx
  - console/src/hooks/useConsoleEvents.ts
  - console/src/api/stream.ts
test_scopes:
  - console/tests/console-events.test.tsx
  - console/tests/stream.test.ts
  - console/tests/read-models.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Visibility & Observability
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-25, PRD-26, OPT-12
---

## Context
Live stores a whole campaign object, so selection can become stale after refresh. Every non-heartbeat
SSE event currently schedules one callback that refreshes campaigns, components, targets, and
Birdseye together. Reconciliation must be durable-ID-based, bounded, and resource-specific.

## Acceptance Criteria
- **AC-1**: Given a selected campaign and a refreshed collection, when record fields change or the
  record disappears, then the screen resolves by durable run ID, updates to the new record, or
  explicitly clears selection; it never launches from a stale object.
- **AC-2**: Given ordered campaign/attempt/tool/agent/finding/approval/component events, when received,
  then a bounded event-to-resource map coalesces refreshes and only invalidates affected projections.
- **AC-3**: Given burst, reconnect, duplicate, gap, or out-of-order events, when reconciled, then each
  resource has at most one pending refresh, gaps force one authoritative re-read, and cursor
  correctness is preserved.
- **AC-4**: Given a selected run, when Live renders, then exact target/surface, ScanPlan states,
  logical/physical progress, preflight/approval, agents, costs, caps, and abort state link to the
  authoritative page contracts without duplicating their calculations.
- **AC-5**: Given an abort/rerun command, when state changes, then confirmation/reason behavior from
  T-F18g applies and selection remains consistent with the acknowledged server resource ID.

## Test Plan
- Unit: event classification, coalescing, gaps, stable ID resolution.
- Integration: mocked authenticated SSE plus changed server projections, without optimistic rows.
- E2E: select campaign, receive partial/final events, preserve correct selected run.
- Eval: none.

## Definition of Done
- [ ] Independent Test Agent records RED and Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without test edits.
- [ ] Orchestrator reruns stream, console, typecheck, bundle, and browser gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Changing event production, campaign scheduling, tool fanout, or target adapters.
