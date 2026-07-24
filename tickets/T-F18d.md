---
id: T-F18d
title: Rebuild Tooling around exact ScanPlan execution evidence
status: backlog
wave: 40
depends_on: [T-F18c, T-F19e]
branch: ticket/T-F18d-tooling-scan-plan
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/screens/AgentToolScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - tests/security_tools/test_security_tools.py
  - console/tests/read-models.test.tsx
  - console/tests/observability.test.ts
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf build-versus-configure and observability requirements
  - docs/requirements/REQUIREMENTS_MATRIX.csv LEAD-03, PRD-25
  - docs/planning/full-console-remediation.md Tool execution model
---

## Context
Current tool metrics are aggregated across the organization and copied onto every target/surface
card. The page must consume a persisted ScanPlan from the tool-orchestration workstream and fail
closed if it does not exist. This ticket observes fanout; it does not execute tools.

## Acceptance Criteria
- **AC-1**: Given evidence for two targets, surfaces, campaigns, or plans, when one scope is selected,
  then only matching tool runs, artifacts, candidates, attempts, findings, and timestamps appear.
- **AC-2**: Given a ScanPlan item, when shown, then status is exactly `planned`, `running`, `complete`,
  `skipped`, `not_applicable`, `blocked`, or `failed`, with applicability/reason, tool/config version,
  authorization mode, process/run identity, and artifact lineage.
- **AC-3**: Given any tool, when projected, then `installed`, `configured`, `generated`, `executed`,
  and `evidenced/adjudicated` are independent typed facts with authoritative source and freshness;
  none implies another.
- **AC-4**: Given no persisted ScanPlan, when Tooling loads, then it reports
  `blocked: scan_plan_not_persisted`; catalog capability and static CI evidence are never presented as
  target execution.
- **AC-5**: Given all applicable plan items, when the summary is computed, then `complete` requires
  every item terminal plus reconciled candidate/live-attempt/physical-request counts; separate
  authorization and not-applicable states remain visible.
- **AC-6**: Given installed-only, configured-only, generated-only, executed-without-artifact, and
  evidenced-without-adjudication records, when rendered, then each missing next dimension remains
  visibly false/not observed and the page cannot call the tool complete.
- **AC-7**: Given a target/surface/campaign selector, when data refreshes or pages, then selection is
  by durable identity, filters remain stable, and freshness/artifact links are bounded and sanitized.

## Test Plan
- Integration: cross-scope bleed, no-plan, partial-plan, five-dimension negative matrix, failed,
  blocked, reconciled-complete, and stable paging DB cases.
- Frontend: status vocabulary, durable selection, capability-versus-evidence labels, pagination.
- Security: artifact locator allowlist/redaction and organization isolation.
- Eval: none.

## Definition of Done
- [ ] Independent Test Agent records clean RED and independent Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without test edits.
- [ ] Orchestrator reruns API, security-tools, console, typecheck, bundle, and browser gates.
- [ ] Architecture drift confirms the ticket consumes, but does not invent, ScanPlan execution.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Tool brokers, scheduling/fanout, provider or target traffic, ZAP authorization, and candidate review.
Those are owned by T-F19a through T-F19e; absence is a truthful blocked state.
