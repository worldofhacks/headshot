---
id: T-F18f
title: Expose complete schema-validated vulnerability reports
status: backlog
wave: 5
depends_on: [T-F18b, T-F18e]
branch: ticket/T-F18f-vulnerability-report-ui
file_scopes:
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - src/agentforge/api/router.py
  - console/src/types.ts
  - console/src/api/read-models.ts
  - console/src/api/paths.ts
  - console/src/screens/ConsoleScreens.tsx
test_scopes:
  - tests/test_postgres_api_m1d.py
  - tests/test_documentation_storage.py
  - console/tests/read-models.test.tsx
  - console/tests/adversarial-text.test.tsx
  - console/tests/browser/console.spec.ts
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Documentation Agent
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-20, PRD-21, PRD-22, PRD-27
---

## Context
The database stores validated `vuln_reports.contract_payload`, but Finding detail exposes only a
summary and decision history. The full report must be readable without weakening draft-only
publication and evidence-integrity controls.

## Acceptance Criteria
- **AC-1**: Given a report linked to a finding, when read, then the API returns report/finding IDs,
  severity, description, clinical impact, minimal reproduction, observed/expected behavior,
  remediation, status, fix validation, reproduction hash, publication state, and created time from
  the validated stored contract.
- **AC-2**: Given a report, when detailed, then campaign, attempt, evidence hash, trace, agent/model,
  tool, and regression-disposition links are exposed when observed and explicitly `not_observed`
  otherwise.
- **AC-3**: Given contract/hash/link mismatch, cross-organization access, or hostile report text,
  when read/rendered, then the response fails closed or safely renders inert text without leaking
  secrets, markup execution, or another organization.
- **AC-4**: Given a security-tool finding without a Documentation Agent report, when opened, then it
  is labeled `normalized scan finding — full report not generated`; missing fields are not invented.
- **AC-5**: Given critical/draft content, when displayed, then publication/remediation controls remain
  human-gated and the UI never describes the report as published without persisted approval state.

## Test Plan
- Integration: valid report round-trip, corrupt payload/hash/link, org isolation, tool-only finding.
- Frontend: all required fields, long hostile text, missing lineage, publication state.
- Contract: stored payload conforms to `contracts/v1/vuln_report.json`.
- Eval: none; report-quality evaluation remains separate.

## Definition of Done
- [ ] Independent Test Agent records correct RED and Test Reviewer freezes it.
- [ ] Separate Implementation Agent reaches GREEN without test edits.
- [ ] Orchestrator reruns documentation, API, console, typecheck, bundle, and browser gates.
- [ ] Independent Code and Security reviews have no Critical/Important findings.

## Out of Scope
Generating, publishing, reproducing, or remediating a vulnerability.
