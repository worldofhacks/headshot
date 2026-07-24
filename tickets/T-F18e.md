---
id: T-F18e
title: Make Birdseye runtime and handoff state evidence-derived
status: backlog
wave: 41
depends_on: [T-F18d, T-F19e]
branch: ticket/T-F18e-birdseye-truth
file_scopes:
  - src/agentforge/api/birdseye.py
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/components/Birdseye.tsx
test_scopes:
  - tests/test_birdseye_api.py
  - tests/test_postgres_api_m1d.py
  - console/tests/birdseye.test.tsx
  - console/tests/read-models.test.tsx
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Visibility & Observability
  - Week_3_AgentForge.pdf Observability Layer
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-25, PRD-26, LEAD-05
---

## Context
Birdseye currently gives configured, never-executed agents operational availability and can mark
edges complete from a latest attempt rather than an observed parent/child handoff. It must also show
the selected campaign's ScanPlan fanout without treating capability as execution.

## Acceptance Criteria
- **AC-1**: Given no fresh heartbeat or execution for a component/agent, when projected, then state is
  `never_observed` or `stale`, healthy instances is zero, and detail distinguishes configuration from
  observed readiness.
- **AC-2**: Given agent and outbound records, when edges are projected, then active/complete requires
  persisted source-to-child lineage for that campaign/attempt; unrelated latest attempts cannot
  complete an edge.
- **AC-3**: Given a running campaign and ScanPlan, when Birdseye renders, then target/surface, logical
  cases, physical requests, plan-item states, agents, budget, abort state, and evidence freshness are
  visible and reconcile with Tooling.
- **AC-4**: Given missing plan/agent/tool evidence or a failed handoff, when summarized, then system
  state is degraded/blocked/error as appropriate and never nominal by configured-node count.
- **AC-5**: Given a never-run, partial, and complete campaign fixture, when decoded/rendered, then no
  false ready/healthy/complete language appears and attention routes retain exact durable IDs.

## Test Plan
- Unit: runtime-state and edge-lineage state table.
- Integration: unrelated attempts, missing heartbeat, partial fanout, and reconciliation.
- Frontend: never-observed visual state, fanout status, attention navigation.
- Eval: none.

## Definition of Done
- [ ] Independent Test Agent produces RED and Test Reviewer freezes corrected tests.
- [ ] Separate Implementation Agent reaches GREEN without editing tests.
- [ ] Orchestrator reruns Birdseye API/UI, full console, typecheck, and bundle gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Changing agent models, prompts, execution composition, or tool scheduling.
