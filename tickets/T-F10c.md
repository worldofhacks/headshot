---
id: T-F10c
title: Record demo and prepare social submission package
status: backlog
wave: 14
depends_on: [T-F10a, T-F10b]
branch: ticket/T-F10c-submission
file_scopes: [docs/demo/**, docs/submission/**]
test_scopes: []
model_hint: standard
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Demo Video, Social Post, Submission
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-31, PRD-35, LEAD-07, LEAD-10
---

## Context
Wave 14 documentation-only packaging consumes T-F10a's reviewed release manifest and T-F10b's genuine-report/reproduction manifests into `docs/demo/**` and `docs/submission/**`. `Week_3_AgentForge.pdf`, PRD-31/35 and LEAD-07/10, release/campaign/report hashes, and the sanitation review are authoritative. The owner-supplied `docs/evidence/authorizations/social-publication.json` is read-only; if absent, publication is `BLOCKED` with zero posting calls and the agent only prepares drafts.

## Acceptance Criteria
- **AC-1**: Video metadata records duration 180–300 seconds, release/campaign hashes and sanitation reviewer; demo shows authorized staging, four-agent trace, safeguards, honest results, regression/performance/cost/limits.
- **AC-2**: Frame/transcript review records zero tokens/sessions/canaries/private IDs/credentials/PHI; any hit blocks publication.
- **AC-3**: Submission checklist maps every PDF/matrix requirement to artifact hash or explicit P1/P2 blocker, including genuine report count.
- **AC-4**: Social draft accurately describes/shows project and tags `@GauntletAI`; `docs/evidence/authorizations/social-publication.json` is required before human publication. Agent never posts.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No fabricated demo, auto-post, production claim, or hidden blocker.
