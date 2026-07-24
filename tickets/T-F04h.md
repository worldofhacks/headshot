---
id: T-F04h
title: Publish smoke contracts fixture and offline verifier
status: backlog
wave: 5
depends_on: [T-F02, T-F03a, T-F04a, T-F04f, T-F14b]
branch: ticket/T-F04h-smoke-contracts
file_scopes:
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/openrouter_smoke_authorization.json
  - src/agentforge/contracts/v1/openrouter_smoke_fixture.json
  - src/agentforge/contracts/v1/openrouter_smoke_manifest.json
  - src/agentforge/contracts/v1/openrouter_smoke_review.json
  - contracts/v1/openrouter_smoke_authorization.json
  - contracts/v1/openrouter_smoke_fixture.json
  - contracts/v1/openrouter_smoke_manifest.json
  - contracts/v1/openrouter_smoke_review.json
  - evals/fixtures/openrouter-four-role-smoke-v1.json
  - scripts/verify_openrouter_four_role_smoke.py
test_scopes:
  - tests/test_openrouter_smoke_contracts.py
  - tests/contract/test_conformance.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf versioned contracts, four-agent evidence, and synthetic fixtures
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-13, PRD-25, PRD-26, OPT-06, OPT-08, OPT-09
  - .tdd-swarm/reports/openrouter-scope-review.md I1 and M1
---

## Context
[locked-decision] Wave 5 owns only smoke schemas, root/package parity, content-addressed synthetic fixture, registry classification, generic conformance, and offline manifest/review verification. These four schemas are repository **operational contracts**, explicitly enumerated in a new `OPERATIONAL_SCHEMAS` registry group and excluded from `SUCCESS_SCHEMAS`; generic registry/wheel conformance covers both groups.

## Acceptance Criteria
- **AC-1**: Given package/root registries, when enumerated, then all four smoke schemas appear exactly once in `OPERATIONAL_SCHEMAS`, never `SUCCESS_SCHEMAS`, have byte-identical root publications, validate installed-wheel lookup, and pass generic conformance/compatibility rules.
- **AC-2**: Given `evals/fixtures/openrouter-four-role-smoke-v1.json`, when validated/hashed, then it fixes bounded OrchestrationSnapshot, Red Team seed/directive, deterministic confirmed EvidenceEnvelope, sanitized DocumentationInput, expected parent chain, and output contract mapping; authorization binds its canonical SHA-256.
- **AC-3**: Given local negative fixture mutations, when verified, then INDETERMINATE Judge blocks Documentation, unsanitized Documentation rejects, and cap-expanding Orchestrator advice fails without provider calls; these are invariant checks, not behavior-quality evidence.
- **AC-4**: Given a smoke manifest, when `python scripts/verify_openrouter_four_role_smoke.py manifest --authorization <AUTHORIZATION> --configuration-set-sha256 <CONFIGURATION_SET_SHA256> --fixture <FIXTURE> --manifest <MANIFEST>` runs, then exact contracts/hashes/identities/lineage/reservations/reconciliation/caps/zero-target state validate offline.
- **AC-5**: Given create-only Evidence/Security records, when `reviews` verification runs with expected unequal record hashes, then schema, canonical hashes, distinct identities/dispositions/timestamps, manifest/release/configuration/fixture/verifier provenance validate; mismatch is non-zero.

## Test Plan
- Unit (deterministic): four schemas, classification, fixture hash/negative semantics, manifest/review verifier cases.
- Integration (deterministic): root/package/installed-wheel registry conformance and exact offline CLI commands.
- Eval: none.
- E2E: no network; fixture→manifest/review verification using local artifacts.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F04h.md <DIFF_BASE>` and root/package/wheel conformance exit 0.
- [ ] `OPERATIONAL_SCHEMAS` classification is explicit and reviewed.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No hosted role adapters/composition/dispatch, configuration staging/preflight, provider transport/spend, target traffic, or review execution.
