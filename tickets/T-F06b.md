---
id: T-F06b
title: Execute authorized regression replay evidence
status: backlog
wave: 6
depends_on: [T-F05b, T-F06a]
branch: ticket/T-F06b-replay-evidence
file_scopes: [docs/evidence/regression/**]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf regression reappearance/cross-category proof
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-23, PRD-24, PRD-36
---

## Context
Wave 6 authorized operational evidence consumes T-F05b's current-SHA campaign manifest and T-F06a's fresh-replay/right-reason interfaces, producing `docs/evidence/regression/<run>/manifest.json`. `Week_3_AgentForge.pdf`, PRD-23/24/36, and the bound target, case, release, baseline, verdict, and artifact hashes are authoritative. The owner-supplied campaign scope or `docs/evidence/authorizations/regression-replay.json` is read-only; if neither is valid, status is `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: Given still-valid campaign scope or `docs/evidence/authorizations/regression-replay.json`, preflight binds case/target/release/caps and exits 0; otherwise exit 4/zero calls.
- **AC-2**: Fresh replay writes new campaign/verdict/right-reason/baseline/cross-category artifact hashes to `docs/evidence/regression/<run>/manifest.json`.
- **AC-3**: Evidence Reviewer recomputes target/case/baseline hashes and state comparator; mismatch blocks approval.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No authorization inference, regression promotion, or remediation.
