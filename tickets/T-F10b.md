---
id: T-F10b
title: Produce genuine independently reproduced reports
status: backlog
wave: 8
depends_on: [T-F05b, T-F06b]
branch: ticket/T-F10b-reports
file_scopes: [docs/vulnerabilities/**, docs/evidence/reproductions/**]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Vulnerability Reports and Documentation quality
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-22, PRD-27, PRD-32
---

## Context
Wave 8 authorized operational evidence consumes T-F05b confirmed-exploit recorder/verdict hashes and T-F06b fresh replay evidence, producing schema-valid reports and `docs/evidence/reproductions/**`. `Week_3_AgentForge.pdf`, PRD-22/27/32, the packaged `vuln_report` contract hash, and exact target/release/artifact hashes are authoritative. The owner-supplied exact reproduction authorization artifact is read-only; if absent, status is `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: Candidate must reference `EXPLOIT_CONFIRMED`, recorder/evidence hashes and exact target/release; `INDETERMINATE`, simulated or duplicate candidates are rejected.
- **AC-2**: Report validates against packaged `vuln_report` schema and contains every PRD field; verifier exit 0 and report SHA are retained.
- **AC-3**: Independent reproduction requires exact authorization artifact and writes expected/observed/result/reviewer hashes; absent authorization means BLOCKED/zero calls.
- **AC-4**: Three reports complete PRD-32 only if three distinct reports/reproductions verify; fewer stays explicitly incomplete. Critical publication requires distinct approval and is not implied by draft.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No invented report, unauthorized reproduction, publication, or remediation.
