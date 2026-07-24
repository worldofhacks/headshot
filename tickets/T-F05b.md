---
id: T-F05b
title: Execute fresh current-SHA staging campaign
status: backlog
wave: 5
depends_on: [T-F01a, T-F03b, T-F04b, T-F05a, T-F11]
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
Wave 5 authorized operational evidence consumes T-F01a's live-export manifest, T-F03b/T-F04b reviewed provider evidence, T-F05a's four-agent lineage interface, and T-F11's target-observation packet, producing `docs/evidence/live/<campaign>/` and its manifest. `Week_3_AgentForge.pdf`, the current release SHA, and the bound target/corpus/provider/policy/artifact hashes are authoritative. The owner-supplied `docs/evidence/authorizations/campaign.json` is read-only; if absent or mismatched, status is `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: Given `docs/evidence/authorizations/campaign.json` binding release/target/surface/corpus/provider-policy/caps/lease-generation/expiry/launcher/distinct approver, preflight exits 0; absent/mismatch exits 4 and outbound count is zero.
- **AC-2**: Given valid staging authorization, completion/abort writes recorder/verdict/four-agent/cost artifacts and T-F01a manifest with SHA-256 list under `docs/evidence/live/<campaign>/`.
- **AC-3**: Every physical request count equals recorder rows; cap/lease/abort/calibration breach terminates and preserves partial evidence.
- **AC-4**: Reviewer recomputes artifact hashes, trace parent graph and counts and labels environment `staging`; secrets/PHI/session values are absent.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No production campaign, load test, report publication, or guaranteed finding.
