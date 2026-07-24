---
id: T-F09a
title: Assemble current-SHA ATO evidence packet
status: backlog
wave: 8
depends_on: [T-F08, T-F09b, T-F11, T-F12, T-F13, T-F14a, T-F14b]
branch: ticket/T-F09a-ato
file_scopes: [docs/evidence/ato/**]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf ATO evidence packet
  - docs/requirements/REQUIREMENTS_MATRIX.csv OPT-07, OPT-15, LEAD-03
---

## Context
Wave 8 documentation-only assembly consumes T-F08 cost evidence, T-F09b drill evidence, T-F11/T-F12/T-F13 architecture and integration packets, and T-F14a/T-F14b security/failure contracts into `docs/evidence/ato/manifest.sha256`. `Week_3_AgentForge.pdf`, OPT-07/15 and LEAD-03, dependency artifact hashes, tool-version hashes, and the bound release/environment SHA are authoritative.

## Acceptance Criteria
- **AC-1**: `docs/evidence/ato/manifest.sha256` covers architecture/data-flow, human/workload auth matrices, lineage/access/environment, dependency/SBOM, scans, evals, tests/deploy/cost; `sha256sum -c` exits 0.
- **AC-2**: Dependency/scanner evidence records tool/version/command/date/SHA/disposition for Semgrep, pip/npm audit, gitleaks, ZAP and offline LLM tools; absent command is BLOCKED, not green.
- **AC-3**: Every claim binds release SHA/environment/evidence reviewer; staging/test configuration cannot yield production ATO status.
- **AC-4**: Security Evidence Reviewer checks required-file matrix and hashes and records APPROVED.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No failure drills/postmortem, production ATO, remediation, or new scan execution without approval.
