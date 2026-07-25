---
id: T-F05b
title: Execute fresh current-SHA staging campaign
status: backlog
wave: 18
depends_on: [T-F01a, T-F03b, T-F04b, T-F04e, T-F05a, T-F05c, T-F05d, T-F05e, T-F05f, T-F05g, T-F05h, T-F05i, T-F05j, T-F05k, T-F05l, T-F05m, T-F05n, T-F05o, T-F05p, T-F11]
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
Wave 18 authorized operational evidence consumes T-F01a export, T-F03b/T-F04b role evidence,
T-F04e reviews, T-F05a lineage, the complete T-F05d through T-F05p
lease/source/config/loader/provider/Runner/ordered-rotation chain, T-F05c public preflight, and
T-F11 observation. `campaign.json` binds the exact T-F05d manifest
identity and T-F05e context hash; provider approval and smoke never imply target authorization.

## Acceptance Criteria
- **AC-1**: Before any database mutation, credential resolution, adapter/SDK construction, provider call, target call, or spend, the executor runs the exact T-F05c public command with fresh current deployment/control states plus all five separate T-F05n chain inputs: start control, terminal control, zero deployment, activation event, and final deployment. Any omitted/aliased/single-snapshot/combined input or other non-zero result makes the ticket `BLOCKED`, exit 4, with every outbound/action count zero.
- **AC-2**: The named verifier reads `campaign.json` itself and mechanically proves exact staging target ID/adapter surface/scheme-host-port/exact allowlist+hash, corpus ID/hash, synthetic fixture IDs/hashes and `synthetic_only:true`, release SHA/current deployment manifest+hash/deployed release+target version, T-F04g current provider-role configuration/projection/prompt/rubric/criteria/policy/catalog/data-policy hashes, and the canonical T-F04e manifest hash plus unequal immutable Evidence/Security review hashes and distinct APPROVED identities. These expected values may not come only from free CLI substitutions.
- **AC-3**: The same gate proves exactly one T-F05p target, one enabled chat surface, one session/credential generation, identical Web/Runner catalog hash, Runner-only resolution, pinned T-F05d patient identity, caps/grant/principals, immutable T-F05e context, fresh T-F05h/T-F05i current state, and complete T-F05o/T-F05n ordered rotation. Disabled UI/evidence/upload surfaces cannot be selected. The smoke gate cannot replace allowlist, synthetic-data, budget/rate, abort, lease, source-acquisition, or rotation-history enforcement.
- **AC-4**: Given valid staging authorization and still-valid Policy Gateway/T-F05e/T-F05f/T-F05g state immediately before each physical dispatch, T-F05m acquires a new signed T-F05l observation and fresh T-F05i transaction; completion/abort writes recorder/verdict/four-agent/cost artifacts and T-F01a manifest. Fixture/context/source-trust/cap/time/release drift or unavailable/replayed/partial refresh terminates and preserves partial evidence without another resolution, context reload, cached observation, or in-place rotation.
- **AC-5**: Reviewer reruns the exact T-F05c public preflight without network, recomputes authorization/target/deploy/corpus/fixture/configuration/smoke/review/cap/lease hashes, trace parent graph and physical counts, and labels environment `staging`; secrets, PHI, and session values are absent.

## Definition of Done
- [ ] Exact T-F05c campaign-grant preflight and artifact-hash checks have expected exits before any outbound action.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No production campaign, load test, report publication, or guaranteed finding.
