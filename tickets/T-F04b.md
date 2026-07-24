---
id: T-F04b
title: Execute bounded Red Team provider evaluation
status: backlog
wave: 5
depends_on: [T-F04a]
branch: ticket/T-F04b-redteam-eval
file_scopes: [evals/results/red-team/**, docs/evidence/red-team/**]
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf novel mutation/refusal/model selection
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-16, PRD-17
---

## Context
Wave 5 authorized evidence consumes T-F04a runtime/policy and the exact T-F04c configuration-set hash accepted by T-F04g read-only preflight. The owner Red Team artifact is read-only and binds the exact Red Team configuration/identity; invalid means `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: Given `docs/evidence/authorizations/red-team-eval.json` with configuration-set/version hash, requested/expected-returned/expected-upstream Red Team identity, credential-reference/prompt/policy/catalog/data-policy hashes, caps, expiry, thresholds, approver and `target_scope:none|authorized-staging`, persisted-record preflight exits 0; absent/invalid exits 4 with zero calls.
- **AC-2**: A bounded run writes requested/returned/actual-upstream identity, configuration/case/output/lineage/prompt/policy hashes, refusal/canonical novelty/deterministic reproduction rates, physical usage and measured cost to `evals/results/red-team/<run>/manifest.json`.
- **AC-3**: Pass/fail uses the exact threshold set/hash in the authorization artifact; no threshold means BLOCKED, not an inferred pass.
- **AC-4**: Evidence Reviewer recomputes rates/hashes and confirms target traffic count matches scope; sampled output is graded, not exact-mocked.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No campaign authorization reuse, unbounded spend, or vulnerability claim.
