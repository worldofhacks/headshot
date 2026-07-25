---
id: T-F03b
title: Execute bounded independent Judge calibration
status: backlog
wave: 5
depends_on: [T-F03a]
branch: ticket/T-F03b-judge-evidence
file_scopes: [evals/results/calibration/**, docs/evidence/calibration/**]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Judge consistency/drift/ground truth
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-18, OPT-08
---

## Context
Wave 5 authorized evidence consumes T-F03a's strict Judge adapter/calibration CLI and the exact T-F04c configuration-set hash accepted by T-F04g read-only preflight. The owner Judge artifact is read-only and must bind that exact Judge configuration/identity; invalid means `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: Given `docs/evidence/authorizations/judge-calibration.json` with configuration-set/version hash, requested/expected-returned/expected-upstream Judge identity, prompt/rubric/criteria/policy/ground-truth hashes, caps, expiry, approver and no target scope, zero-call persisted-record preflight exits 0; absent/invalid exits 4 with zero provider calls.
- **AC-2**: Given valid authorization, bounded dual judging writes category metrics, requested/returned/actual-upstream identity, credential-reference/configuration/prompt/rubric/criteria/policy/ground-truth hashes and physical usage/cost to `evals/results/calibration/<run>/manifest.json`.
- **AC-3**: Given thresholds from the landed T-F03a calibration-policy hash, runtime enablement is true only when the verifier exits 0; otherwise blocked with exact breach reasons.
- **AC-4**: Evidence Reviewer independently recomputes metrics/hashes and records APPROVED; sampled outputs remain graded, not mocked.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No target traffic, threshold relaxation, or production credential.
