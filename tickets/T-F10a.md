---
id: T-F10a
title: Verify owner-merged dual-remote staging release
status: backlog
wave: 13
depends_on: [T-F08, T-F09a, T-F09b, T-F13]
branch: ticket/T-F10a-release
file_scopes: [docs/evidence/release/**, README.md]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Repository and Deployed Application
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-29, PRD-34, LEAD-08, LEAD-10
  - AGENTS.md dual-remote law
---

## Context
Wave 13 authorized operational evidence consumes T-F08/T-F09a/T-F09b/T-F13 reviewed manifests and verifies the owner-merged release through `docs/evidence/release/**` without performing a swarm merge or deployment mutation. `Week_3_AgentForge.pdf`, `AGENTS.md` dual-remote law, the release commit SHA, CI/deploy outputs, and the release manifest hash are authoritative. The owner-supplied release authorization/evidence artifact is read-only; if absent, status is `BLOCKED` with zero remote or deployment calls.

## Acceptance Criteria
- **AC-1**: Owner-merged release records commit/deploy/migration/health/readiness/auth/private-topology/rollback outputs and SHA-256 manifest; any failed check blocks release.
- **AC-2**: Read-only remote check proves `origin/main == gitlab/main == release SHA`; GitHub and GitLab CI URLs/statuses are success for that SHA.
- **AC-3**: README labels staging/test Clerk honestly; absent isolated production evidence forbids production claim.
- **AC-4**: Release/Security Reviewers verify manifest, dual remotes, CI, deployment and sanitation; no swarm merge/force push.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No production isolation invention, report/demo/social, or autonomous merge.
