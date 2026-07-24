---
id: T-F14b
title: Complete typed failure contracts
status: backlog
wave: 2
depends_on: [T-F00, T-F02]
branch: ticket/T-F14b-failure-contracts
file_scopes:
  - src/agentforge/contracts/v1/errors.json
  - src/agentforge/contracts/v1/failure_drill.json
  - contracts/**
test_scopes: [tests/contract/test_failure_contracts.py]
model_hint: capable
attempts: 0
traces_to:
  - docs/requirements/REQUIREMENTS_MATRIX.csv OPT-04, OPT-11, LEAD-06
  - Week_3_AgentForge.pdf explicit error schemas/failure drills
---

## Context
Wave 2 deterministic code consumes T-F00's local-gate interface and T-F02's package-authority/root-parity contract, and produces versioned `errors.json` and `failure_drill.json` schemas for later replay and drill consumers. `Week_3_AgentForge.pdf`, OPT-04/11 and LEAD-06, package schema hashes, parity-manifest hashes, and migration evidence are authoritative.

## Acceptance Criteria
- **AC-1**: Typed schemas cover target-version-mid-run, recorder/DB/observability failure, Judge disagreement/abstention/calibration invalidity, scanner-version mismatch, abort/partial evidence.
- **AC-2**: Producer/consumer fixtures validate; unknown reason/version exits non-zero and cannot become safe/success.
- **AC-3**: Package-authority→root sync/parity from T-F02 exits 0; breaking change needs version/migration evidence.
- **AC-4**: Failure-drill schema requires injection/expected/actual/recovery/artifact hashes and sanitation status.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F14b.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No drill execution, provider/target call, or silent schema compatibility waiver.
