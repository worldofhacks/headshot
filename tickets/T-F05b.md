---
id: T-F05b
title: Execute fresh current-SHA staging campaign
status: backlog
wave: 9
depends_on: [T-F01a, T-F03b, T-F04b, T-F04e, T-F05a, T-F05c, T-F11]
branch: ticket/T-F05b-live-campaign
file_scopes: [evals/results/live/**, docs/evidence/live/**, docs/target/live/**]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate and Stage 3
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34, USR-04, USR-07, LEAD-09
---

## Context
Wave 9 authorized operational evidence consumes T-F01a export, T-F03b/T-F04b role evidence, T-F04e's immutable smoke manifest plus two distinct APPROVED review records, T-F05a lineage, T-F05c's additive public live preflight, and T-F11 target observation. `docs/evidence/authorizations/campaign.json` is a read-only grant; provider approval and reviewed target-free smoke never imply target authorization. Any grant, Policy Gateway, lease, review, or current-state mismatch means `BLOCKED`, exit 4, with zero secret/provider/target actions.

## Acceptance Criteria
- **AC-1**: Before any database mutation, credential resolution, adapter/SDK construction, provider call, target call, or spend, the executor runs exactly `python scripts/preflight_live_campaign.py --authorization docs/evidence/authorizations/campaign.json --target-observation <TARGET_OBSERVATION> --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --corpus-manifest <CORPUS_MANIFEST> --synthetic-fixture-manifest <SYNTHETIC_FIXTURE_MANIFEST> --configuration-projection <HOSTED_CONFIGURATION_PROJECTION> --smoke-manifest <SMOKE_MANIFEST> --evidence-review <EVIDENCE_REVIEW> --security-review <SECURITY_REVIEW> --smart-lease-metadata <SMART_LEASE_METADATA> --launcher-ref <LAUNCHER_REF> --check-only`; any non-zero result makes the ticket `BLOCKED`, exit 4, with every outbound/action count zero.
- **AC-2**: The named verifier reads `campaign.json` itself and mechanically proves exact staging target ID/adapter surface/scheme-host-port/exact allowlist+hash, corpus ID/hash, synthetic fixture IDs/hashes and `synthetic_only:true`, release SHA/current deployment manifest+hash/deployed release+target version, T-F04g current provider-role configuration/projection/prompt/rubric/criteria/policy/catalog/data-policy hashes, and the canonical T-F04e manifest hash plus unequal immutable Evidence/Security review hashes and distinct APPROVED identities. These expected values may not come only from free CLI substitutions.
- **AC-3**: The same zero-call preflight proves aggregate/per-role physical call/retry/input/output/reasoning-token/USD/rate/concurrency/timeout/wall-clock/abort caps, grant expiry, operation hash/nonce, launcher and distinct approver permissions, SMART credential-reference hash and exact session lease generation/not-before/expiry/target binding. It composes the existing campaign authorization/binding/caps/target-preflight/Policy-Gateway checks; the smoke-review gate is additive and cannot replace allowlist, synthetic-data, budget/rate, abort, or lease enforcement.
- **AC-4**: Given valid staging authorization and a still-valid Policy Gateway decision immediately before each physical dispatch, completion/abort writes recorder/verdict/four-agent/cost artifacts and T-F01a manifest with SHA-256 list under `docs/evidence/live/<campaign>/`; every physical request count equals recorder rows, and cap/lease/abort/calibration/version drift terminates and preserves partial evidence.
- **AC-5**: Reviewer reruns the exact T-F05c public preflight without network, recomputes authorization/target/deploy/corpus/fixture/configuration/smoke/review/cap/lease hashes, trace parent graph and physical counts, and labels environment `staging`; secrets, PHI, and session values are absent.

## Definition of Done
- [ ] Exact T-F05c campaign-grant preflight and artifact-hash checks have expected exits before any outbound action.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No production campaign, load test, report publication, or guaranteed finding.
