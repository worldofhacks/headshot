---
id: T-F04b
title: Execute bounded Red Team provider evaluation
status: backlog
wave: 4
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
Wave 4 authorized operational evidence consumes T-F04a's provider runtime and `.tdd-swarm/red-team-eval-policy.json`, producing `evals/results/red-team/<run>/manifest.json`. `Week_3_AgentForge.pdf`, PRD-16/17, and the authorization threshold, policy, output, and lineage hashes are authoritative. The owner-supplied `docs/evidence/authorizations/red-team-eval.json` is read-only; if absent or invalid, status is `BLOCKED` with zero calls.

## Acceptance Criteria
- **AC-1**: Given `docs/evidence/authorizations/red-team-eval.json` with provider/model, max calls/USD, expiry, threshold set, approver and explicit `target_scope:none|authorized-staging`, preflight exits 0; absent/invalid exits 4 with zero calls.
- **AC-2**: A bounded run writes case/output/lineage hashes, refusal rate, canonical novelty rate, deterministic reproduction rate, usage and cost to `evals/results/red-team/<run>/manifest.json`.
- **AC-3**: Pass/fail uses the exact threshold set/hash in the authorization artifact; no threshold means BLOCKED, not an inferred pass.
- **AC-4**: Evidence Reviewer recomputes rates/hashes and confirms target traffic count matches scope; sampled output is graded, not exact-mocked.

## Definition of Done
- [ ] Named mechanical verifier and artifact-hash checks have expected exits.
- [ ] Independent Evidence/Security reviewer records APPROVED, or ticket remains honestly BLOCKED.
- [ ] No production code was changed; external action used only the named authorization artifact.

## Out of Scope
No campaign authorization reuse, unbounded spend, or vulnerability claim.
