---
id: T-F09b
title: Execute failure drills and sample postmortem
status: backlog
wave: 11
depends_on: [T-F05b, T-F06b, T-F14b]
branch: ticket/T-F09b-drills
file_scopes: [docs/evidence/failure-drills/**, docs/incidents/**]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf failure drills and sample incident/postmortem
  - docs/requirements/REQUIREMENTS_MATRIX.csv OPT-04, OPT-07, LEAD-06
---

## Context
Wave 11 authorized operational evidence consumes T-F05b's campaign manifest, T-F06b's replay manifest, and T-F14b's typed failure/drill schemas, producing drill manifests and `docs/incidents/**`. `Week_3_AgentForge.pdf`, OPT-04/07 and LEAD-06, package schema hashes, and dependency artifact hashes are authoritative. The owner-supplied authorization artifact for any external drill, `docs/evidence/authorizations/failure-drill.json`, is read-only; if absent, that drill is `BLOCKED` with zero calls while offline drills remain eligible.

## Acceptance Criteria
- **AC-1**: Versioned drill matrix covers provider timeout, Judge disagreement/calibration invalidity, recorder/DB/observability failure, lease/target expiry, scanner-version mismatch and hard abort; each row has injection command, expected typed error/state, actual exit, artifact hash, recovery check.
- **AC-2**: Offline drills run without network; external staging drill requires `docs/evidence/authorizations/failure-drill.json`, else exit 4/zero calls.
- **AC-3**: One sample postmortem includes timeline/impact/detection/root cause/controls/actions/owners/validation and links immutable drill hashes.
- **AC-4**: Security Reviewer reruns safe mechanical checks, verifies partial evidence/alerts/recovery and signs manifest.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No destructive production drill, real incident fabrication, or application fix.
