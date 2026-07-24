---
id: T-F06b
title: Execute authorized regression replay evidence
status: backlog
wave: 19
depends_on: [T-F05b, T-F05d, T-F05e, T-F05f, T-F05g, T-F05h, T-F05i, T-F05j, T-F05k, T-F05l, T-F05m, T-F05n, T-F05o, T-F05p, T-F06a]
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
Wave 19 authorized operational evidence consumes T-F05b/T-F06a and the landed T-F05d through
T-F05o fixture/source/context/config/loader/provider/Runner/ordered-rotation chain, producing
`docs/evidence/regression/<run>/manifest.json`. The
replay authorization must bind the identical T-F05d identity and T-F05e context hash used by the
campaign; if no exact valid authority exists, status is `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: Given still-valid campaign scope or `docs/evidence/authorizations/regression-replay.json`, preflight binds case/target/release/caps, the identical T-F05d fixture identity/manifest hash, immutable T-F05e context/policy/source-trust binding, and fresh independently authenticated T-F05h/T-F05i state through the shared validators; otherwise exit 4/zero calls.
- **AC-2**: Fresh replay writes new campaign/verdict/right-reason/baseline/cross-category artifact hashes to `docs/evidence/regression/<run>/manifest.json`.
- **AC-3**: Evidence Reviewer recomputes target/case/baseline hashes and state comparator; mismatch blocks approval.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No authorization inference, regression promotion, or remediation.
