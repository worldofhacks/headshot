---
id: T-F18c
title: Merge distinct-case coverage and versioned regression truth
status: backlog
wave: 2
depends_on: [T-F18a, T-F18b]
branch: ticket/T-F18c-coverage-regression
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/api/paths.ts
  - console/src/screens/ConsoleScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - console/tests/read-models.test.tsx
  - console/tests/analytics.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Evaluation & Regression
  - Week_3_AgentForge.pdf Regression & Validation Harness
  - Week_3_AgentForge.pdf Observability Layer
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-23, PRD-24, PRD-25, LEAD-05
---

## Context
The existing Coverage page derives a case ceiling from attempt counts and the separate Resilience
page lists regression attempts without deterministic disposition or version-comparison truth. One
authoritative projection must keep logical cases, attempts, physical requests, verdicts, and
right-reason regression validation distinct.

## Acceptance Criteria
- **AC-1**: Given retries or multi-request cases, when coverage is projected, then distinct
  authorized `case_id` count drives coverage while attempt and physical-request counts remain
  separate and cannot inflate it.
- **AC-2**: Given boundary/invariant/regression cases, when grouped by exact target and version, then
  category, OWASP Web/LLM, verdict, and provenance counts include only integrity-valid,
  synthetic-data-attested records.
- **AC-3**: Given regression dispositions across two target versions, when projected, then the page
  shows reappeared/held/indeterminate/right-reason state, current-versus-previous deltas, and does not
  call an unvalidated behavior change a pass.
- **AC-4**: Given `/coverage`, when rendered, then its heading is `Coverage & Regression` and it
  contains coverage, pass/fail, version activity, regression timeline, and authoritative ledger;
  the browser makes no `/resilience` resource request.
- **AC-5**: Given missing comparison data or integrity failure, when rendered, then the exact
  unavailable/indeterminate reason is visible and no improving/degrading claim is synthesized.

## Test Plan
- Unit: decoder rejects attempt-as-case and missing disposition fields.
- Integration: seeded duplicate attempts, invalid evidence, two versions, and reappearance query.
- E2E: merged page renders required PRD answers and no standalone Resilience request.
- Eval: none; regression correctness is deterministic.

## Definition of Done
- [ ] Independent Test Agent produces criterion-tagged RED; independent Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without modifying tests.
- [ ] Orchestrator reruns API/read-model, console, typecheck, bundle, and browser gates.
- [ ] API compatibility/migration-note review is complete for changed v1 fields.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
Executing regression replays or modifying Judge behavior.
