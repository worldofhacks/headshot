---
id: T-F18k
title: Stabilize Live selection and target event-driven reconciliation
status: backlog
wave: 47
depends_on: [T-F18d, T-F18e, T-F18g, T-F18h, T-F18i, T-F18p, T-F19e]
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
- **AC-3**: Given one real persisted event for every mapped resource class, when T-F19e publishes it,
  then the authenticated production event route delivers it with ordered cursor and the affected
  projection is re-read; tool and agent coverage cannot be proved by a hand-constructed browser event.
- **AC-4**: Given a producer class that is unavailable or an event gap/reconnect, when Live runs, then
  bounded authenticated polling re-reads the authoritative resource until producer health returns;
  absence of an event never freezes state indefinitely.
- **AC-5**: Given burst, reconnect, duplicate, gap, or out-of-order events, when reconciled, then each
  resource has at most one pending refresh, gaps force one authoritative re-read, and cursor
  correctness is preserved.
- **AC-6**: Given a selected run, when Live renders, then exact target/surface, ScanPlan states,
  logical/physical progress, preflight/approval, agents, costs, caps, and abort state link to the
  authoritative page contracts without duplicating their calculations.
- **AC-7**: Given an abort/rerun command, when state changes, then confirmation/reason behavior from
  T-F18g applies and selection remains consistent with the acknowledged server resource ID.

## Test Plan
- Unit: event classification, coalescing, gaps, stable ID resolution.
- Integration: real persisted T-F19e event for every mapped resource plus changed server projections,
  producer-unavailable polling fallback, and no optimistic rows.
- E2E: select campaign, receive partial/final events, preserve correct selected run.
- Eval: none.

## Definition of Done
- [ ] Independent Test Agent records RED and Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without test edits.
- [ ] Orchestrator reruns stream, console, typecheck, bundle, and browser gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Changing event production, campaign scheduling, tool fanout, or target adapters. Event production is
owned and frozen by T-F19e before this consumer ticket begins.
