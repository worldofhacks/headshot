---
id: T-F05d
title: Publish the target-session synthetic patient fixture manifest
status: backlog
wave: 7
depends_on: [T-F04h]
branch: ticket/T-F05d-target-session-fixture
file_scopes:
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/target_session_synthetic_patient_fixture_manifest.json
  - contracts/v1/target_session_synthetic_patient_fixture_manifest.json
  - evals/fixtures/target-session-synthetic-patient-v1.json
  - evals/fixtures/target-session-synthetic-patient-v1.manifest.json
  - evals/fixtures/target-session-synthetic-patient-v1.manifest.sha256
  - scripts/verify_target_session_fixture_manifest.py
test_scopes: [tests/test_target_session_fixture_manifest.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate and synthetic-only fixture requirement
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-lease-scope-review.md C1
---

## Context
[locked-decision] This deterministic ticket creates the one fixture authority for a SMART target
session. It is separate from T-F04h's target-free OpenRouter smoke fixture. Every later lease,
`campaign.json`, campaign, replay, and stress artifact must use the exact identity and canonical
manifest SHA-256 published here; no downstream ticket may substitute another synthetic manifest.

## Acceptance Criteria
- **AC-1**: The strict `agentforge.target-session-synthetic-patient-fixture-manifest` schema version `1` rejects unknown, missing, duplicate, or malformed fields and contains exactly the fixture ID/version/content SHA-256, synthetic patient ID, synthetic context ID, `synthetic_only:true`, synthetic-only attestation reference/SHA-256, and exact target ID/version plus surface ID/version.
- **AC-2**: `evals/fixtures/target-session-synthetic-patient-v1.manifest.json` is RFC 8785 canonical JSON encoded as UTF-8 with no BOM or trailing newline; its detached `.sha256` contains exactly 64 lowercase ASCII hex characters followed by one LF and names no file. That digest is the SHA-256 of the exact manifest bytes, and the manifest binds the byte hash of the versioned synthetic fixture rather than T-F04h's smoke fixture.
- **AC-3**: `python scripts/verify_target_session_fixture_manifest.py --fixture evals/fixtures/target-session-synthetic-patient-v1.json --manifest evals/fixtures/target-session-synthetic-patient-v1.manifest.json --digest evals/fixtures/target-session-synthetic-patient-v1.manifest.sha256` exits 0 only for schema-valid canonical bytes, matching fixture/attestation/target identities and hashes, and a synthetic-only patient/context; each one-field substitution exits 4 without network or mutation.
- **AC-4**: The fixture and manifest contain only synthetic values and non-secret references. The verifier never accepts a caller-supplied expected manifest hash, and registry/root/package parity classifies this schema as an operational contract rather than a success schema.
- **AC-5**: The published identity tuple is exactly `(fixture_id, fixture_version, fixture_sha256, synthetic_patient_id, synthetic_context_id, attestation_ref, attestation_sha256, target_id, target_version, surface_id, surface_version, manifest_sha256)`. It is the sole named target-session fixture input exposed to T-F05h/T-F05e/T-F05c/T-F05b/T-F06a/T-F06b/T-F07b; no shorter tuple is called complete.

## Test Plan
- Unit (deterministic): strict schema, duplicate/unknown fields, canonical bytes, detached hash, one-field identity/hash/synthetic mutations.
- Integration (deterministic): exact offline verifier command and registry/root/package parity.
- Eval/E2E: none; no network or target/provider action.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05d.md <DIFF_BASE>` exits 0.
- [ ] One versioned content-addressed target-session fixture manifest is published and independently reviewed.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No SMART lease/context, raw session value, resolver, Runner dispatch, grant, Railway action, live
observation, provider/target call, spend, or authorization.
