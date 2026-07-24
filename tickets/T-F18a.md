---
id: T-F18a
title: Canonicalize console navigation and retire the Resilience page
status: backlog
wave: 37
depends_on: [T-F16f, T-F17f, T-F19e]
branch: ticket/T-F18a-console-navigation
file_scopes:
  - console/src/router.ts
  - console/src/App.tsx
test_scopes:
  - console/tests/router.test.ts
  - console/tests/contracts.test.ts
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Evaluation & Regression
  - Week_3_AgentForge.pdf Observability Layer
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-23, PRD-25
---

## Context
Coverage, pass/fail by version, resilience-over-time, and regression state are required, but they do
not require two competing navigation destinations. The retained destination is `/coverage`, labeled
`Coverage & Regression`. `/resilience` is a temporary compatibility redirect, not a screen. RED
begins only from the integration commit containing T-F16f, T-F17f, and T-F19e.

## Acceptance Criteria
- **AC-1**: Given desktop or mobile navigation, when rendered, then exactly one
  `Coverage & Regression` item targets `/coverage` and no Resilience item is present.
- **AC-2**: Given `/resilience` with any query/hash, when routed, then history is replaced with the
  canonical `/coverage` URL and Coverage renders without adding a back-stack loop.
- **AC-3**: Given an unknown, malformed, extra-segment, or entity-on-unsupported-screen path, when
  routed, then the URL is replace-normalized to `/live` rather than silently rendering Live under
  the invalid URL.
- **AC-4**: Given valid encoded Live, Findings, or Approval entity links, when routed, then their
  identity round-trip remains unchanged and no open redirect or path traversal is possible.

## Test Plan
- Unit: criterion-tagged canonical route, redirect, malformed escape, entity, and encoding tests.
- Integration: navigation registry contains no Resilience entry and one Coverage entry.
- E2E: direct `/resilience` and invalid-route replace navigation.
- Eval: none.

## Definition of Done
- [ ] Independent Test Agent records clean RED for AC-1 through AC-4.
- [ ] Independent Test Reviewer closes lazy-route and history-loop gaps; the reviewed tests freeze.
- [ ] Separate Implementation Agent reaches GREEN without editing tests.
- [ ] Orchestrator reruns console unit, typecheck, production bundle, and affected browser gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Coverage/regression data modeling and page contents are T-F18c. No API deletion or regression-data
deletion.
