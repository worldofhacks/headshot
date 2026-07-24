---
id: T-F18l
title: Gate every console page with an auditable route and accessibility manifest
status: backlog
wave: 11
depends_on: [T-F18a, T-F18b, T-F18c, T-F18d, T-F18e, T-F18f, T-F18g, T-F18h, T-F18i, T-F18j, T-F18k]
branch: ticket/T-F18l-console-release-audit
file_scopes:
  - console/src/page-registry.ts
  - console/src/App.tsx
  - console/scripts/check-page-registry.mjs
  - console/package.json
  - docs/evidence/console/**
test_scopes:
  - console/tests/page-registry.test.ts
  - console/tests/production-policy.test.ts
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Observability Layer
  - Week_3_AgentForge.pdf Submission Requirements
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-25, PRD-34, LEAD-10
---

## Context
The final pass needs a mechanical inventory proving that every retained page has a requirement,
authoritative resource states, permissions, commands, keyboard path, and production browser check.
A registry prevents a route from silently escaping review while remaining the navigation source.

## Acceptance Criteria
- **AC-1**: Given the production page registry, when checked, then every retained route declares one
  canonical path, title, PRD trace, required permission, data resources, material commands, empty/
  unavailable/stale/error behavior, and browser scenario; Resilience is redirect-only.
- **AC-2**: Given application navigation and route switching, when built, then both derive from the
  registry and the checker fails on orphaned screen components, paths, resources, or commands.
- **AC-3**: Given an authenticated Headshot test principal, when Playwright visits every route at
  desktop and mobile widths, then landmark/name/focus/keyboard/table/form/dialog checks pass and no
  console error, failed request, forbidden language, horizontal page overflow, or secret appears.
- **AC-4**: Given ready, empty, unavailable, stale, degraded, error, permission-denied, and expired
  command states, when the route matrix runs, then every page renders a truthful recovery path and
  never displays fixture/sample data as live.
- **AC-5**: Given the exact release SHA, when release evidence is produced, then unit/API/browser/
  bundle/secret-scan commands, result counts, authenticated production URL checks, and unresolved
  external blockers are recorded without credentials or target data.

## Test Plan
- Unit: registry completeness and orphan detection.
- E2E: route/state/viewport/keyboard/accessibility matrix.
- Release: exact-SHA production bundle, forbidden-language, and secret scan.
- Eval: none.

## Definition of Done
- [ ] Independent Test Agent creates the missing-registry RED; Test Reviewer freezes corrected tests.
- [ ] Separate Implementation Agent reaches GREEN without changing tests.
- [ ] Orchestrator runs the complete console and affected Python gate suite from a clean install.
- [ ] Independent whole-branch Code, Security, accessibility, and architecture-drift reviews pass.
- [ ] GitHub and GitLab CI are green for the same SHA; owner deployment and authenticated browser
  verification are recorded separately.

## Out of Scope
Self-approving deployment, performing a live scan, recording credentials, or concealing blockers.
