---
id: T-F16h
title: Deploy and verify final-target adapters
status: backlog
wave: 23
depends_on: [T-F16g]
branch: ticket/T-F16h-final-target-deploy
file_scopes:
  - docs/evidence/final-target-adapters/**
  - docs/deployment/final-target-adapters/**
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate and reproducible evidence
  - AGENTS.md Railway topology, authorization, and dual-remote law
  - docs/planning/final-target-adapters.md deployment and rollback
---

## Context
[locked-decision] Operational execution starts only after T-F16g accepts the exact grant and fresh trusted state attestation. Raw sessions and owner bundle/environment files are never read by agents or logged. Every transition is followed by a new read-only observation and preflight before the next mutation/call. Staging Runner precedes Web; document-capable `2.1.0` remains inactive unless the deployed Runner proves its private fixture binding; production needs a distinct promotion grant.

## Acceptance Criteria
- **AC-1**: Before every mutation/call, executor runs `python3 scripts/observe_final_target_state.py --authorization docs/evidence/authorizations/final-target-adapters.json --environment <ENVIRONMENT> --transition <TRANSITION> --output <ATTESTATION> --read-only`, obtains a distinct-approver immutable transition-grant version binding that attestation hash, then runs `python3 scripts/preflight_final_target_adapters.py --authorization docs/evidence/authorizations/final-target-adapters.json --release-manifest <RELEASE> --state-attestation <ATTESTATION> --catalog-manifest config/live-target-catalog-manifest.json --scan-plan <SCAN_PLAN> --rollback-manifest <ROLLBACK> --check-only`. Executor never creates/edits grants. Missing authority or nonzero is `BLOCKED` with zero next action; authorization/attestation/bootstrap hashes are recorded.
- **AC-2**: Staging Runner rolls out first. A newly observed signed attestation proves its monotonic deployment/readiness/migration/catalog/session state. The deployed Runner then performs the authorized zero-target-call fixture open/no-follow/hash/length/media/doc-type/workflow check; a second new signed attestation binds that result and passes preflight before Web.
- **AC-3**: After Web, refresh/verify the attestation and within-Staging parity. Activate `2.0.0`, refresh/verify, then stage/enable `2.1.0` documents while draft only with the fresh post-deploy fixture proof; refresh/verify after each state event. Failure leaves `2.0.0` chat/evidence/UI unchanged.
- **AC-4**: Scan verification starts through the real T-F16f API request, distinct parent/eight-child approvals, launch, durable queue, and Runner path. All eight declared child records are present. Full-target evidence requires `declared_scope_complete=true`; `active_surface_scan_complete=true` with inactive documents is explicitly incomplete and the unsupported `full_surface_scan` field is absent.
- **AC-5**: One sequential bounded scan verifies retry-inclusive counts, then sanitized Bruno runs as independent oracle. No credential URL, screenshot, HTML/PDF/image body, local path, or patient content enters evidence.
- **AC-6**: Any signature/freshness/provenance/bootstrap/gate/count/redaction/session/fixture/health failure stops the next action, appends rollback events, restores last-known-good release/catalog, refreshes and verifies a post-rollback attestation, preserves sanitized partial evidence, and sends no unauthorized production change.
- **AC-7**: After distinct Evidence/Security approvals, separately authorized production promotion deploys the same release Runner then Web with production-specific grant/observer/attestations and repeats every transition gate. Final evidence distinguishes adapter/scan smoke from the 100-case campaign.

## Test Plan
- Deterministic prerequisite: exact T-F16g observer/verifier and T-F16e/f gates.
- Operational: one-worker observe -> preflight -> transition -> fresh-observe loop, real API scan launch, Bruno, review, rollback; production only with separate grant.
- Eval: none.
- E2E: authorized live target; never more than three workers overall.

## Definition of Done
- [ ] Commands/exits/hashes and rollback evidence retained.
- [ ] Every transition has a fresh trusted attestation and matching preflight record.
- [ ] Evidence/Security reviewers are distinct from executor and have no Critical/Important findings.
- [ ] Dual remote release/CI facts are green and equal.
- [ ] No secret, PHI, bundle, fixture body, or screenshot is committed/uploaded.
- [ ] Production is separately authorized or honestly blocked.

## Out of Scope
No OAuth/credential rotation, arbitrary upload, destructive/load/DoS, 100-case claim, publication/remediation, provider model change, or swarm main merge.
