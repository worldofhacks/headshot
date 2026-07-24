---
id: T-F18b
title: Add bounded collection, retry, filter, and keyboard-selection primitives
status: backlog
wave: 1
depends_on: []
branch: ticket/T-F18b-console-collection-controls
file_scopes:
  - src/agentforge/api/schemas.py
  - src/agentforge/api/router.py
  - src/agentforge/api/backend.py
  - console/src/api/client.ts
  - console/src/api/contracts.ts
  - console/src/hooks/useResource.ts
  - console/src/components/ResourceView.tsx
  - console/src/styles/console.css
test_scopes:
  - tests/test_web_m1d.py
  - tests/auth/test_m1d_api.py
  - console/tests/api-client.test.ts
  - console/tests/read-models.test.tsx
  - console/tests/adversarial-text.test.tsx
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf pagination, rate limits, and auth requirements
  - docs/requirements/REQUIREMENTS_MATRIX.csv OPT-12
---

## Context
High-volume lists currently use hard-coded SQL limits and the browser has no cursor, filter, or retry
contract. Row click handlers are not keyboard-operable. This ticket creates the shared, default-deny
substrate; page tickets bind their own allowlisted filters and stable sort keys.

## Acceptance Criteria
- **AC-1**: Given a collection read, when no page request is supplied, then the server applies a
  bounded default; limits above 200, malformed cursors, and unknown filters fail before querying.
- **AC-2**: Given a ready collection page, when decoded, then it carries an optional opaque next
  cursor, bounded limit, and `has_more`; event-stream integer cursors remain a separate contract.
- **AC-3**: Given a transient failed/stale/unavailable read, when the operator chooses Retry, then one
  abortable authenticated request is made and stale data is never relabeled ready.
- **AC-4**: Given a selectable record row, when focused and activated by Enter or Space, then it
  performs the same action as click with visible focus and correct table/button semantics.
- **AC-5**: Given a filter or cursor, when the client builds the request, then values are
  percent-encoded through a structured API and credentials, absolute URLs, fragments, dot segments,
  or arbitrary raw query strings are rejected.

## Test Plan
- Unit: envelope/query/cursor bounds, API URL rejection, retry state, keyboard semantics.
- Integration: auth executes before paged reads and invalid paging performs no repository query.
- E2E: keyboard-select and recoverable retry flow.
- Eval: none.

## Definition of Done
- [ ] Independent Test Agent records clean RED for every AC and a Test Reviewer freezes the corrected
  suite.
- [ ] Separate Implementation Agent reaches GREEN without test changes.
- [ ] Orchestrator reruns Python API/auth, console unit, typecheck, and accessibility smoke gates.
- [ ] Compatibility review confirms optional paging metadata does not break existing v1 consumers.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Page-specific SQL/filter semantics, infinite scrolling, or automatic retry storms.
