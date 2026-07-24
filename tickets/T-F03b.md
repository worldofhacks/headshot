---
id: T-F03b
title: Execute bounded independent Judge calibration
status: backlog
wave: 4
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
Wave 4 authorized operational evidence consumes T-F03a's calibration CLI and `.tdd-swarm/judge-calibration-policy.json`, producing `evals/results/calibration/<run>/manifest.json`. `Week_3_AgentForge.pdf`, PRD-18/OPT-08, and the landed policy/ground-truth/provider identity hashes are authoritative. The owner-supplied `docs/evidence/authorizations/judge-calibration.json` is read-only; if absent or invalid, status is `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: Given `docs/evidence/authorizations/judge-calibration.json` with provider/model identities, max calls, USD cap, expiry, approver and no target scope, zero-call preflight exits 0; absent/invalid artifact exits 4 with zero provider calls.
- **AC-2**: Given valid authorization, bounded dual judging writes category metrics, identity/policy/ground-truth hashes and usage/cost to `evals/results/calibration/<run>/manifest.json`.
- **AC-3**: Given thresholds from the landed T-F03a calibration-policy hash, runtime enablement is true only when the verifier exits 0; otherwise blocked with exact breach reasons.
- **AC-4**: Evidence Reviewer independently recomputes metrics/hashes and records APPROVED; sampled outputs remain graded, not mocked.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No target traffic, threshold relaxation, or production credential.
