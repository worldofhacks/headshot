---
id: T-F04e
title: Execute and independently review four-role OpenRouter smoke
status: backlog
wave: 8
depends_on: [T-F03b, T-F04b, T-F04d, T-F04h, T-F05a]
branch: ticket/T-F04e-openrouter-smoke
file_scopes:
  - evals/results/openrouter-smoke/**
  - docs/evidence/openrouter-smoke/**
test_scopes: []
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf four-agent operation, Judge independence, observability, and cost
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-13, PRD-15, PRD-16, PRD-25, PRD-26, PRD-33, OPT-08
  - .tdd-swarm/reports/openrouter-scope-review.md I1 and I3
  - .tdd-swarm/reports/openrouter-scope-review-final.md I1
---

## Context
[locked-decision] Wave 8 operational evidence invokes only T-F04d's exact target-free command with reviewed T-F03b/T-F04b evidence and T-F05a lineage. `docs/evidence/authorizations/openrouter-four-role-smoke.json` is read-only and binds the persisted configuration-set SHA-256, exact identities/hashes/caps, and T-F04h fixture hash with `target_scope:none`. Execution, Evidence Review, and Security Review are three distinct principals/prompts. Invalid authority means `BLOCKED`, exit 4, and zero provider/target calls.

## Acceptance Criteria
- **AC-1**: Given the named authorization and fixture, when the T-F04g check-only command runs, then it validates release/configuration/requested+expected identity/credential-reference/schema/prompt/rubric/criteria/policy/catalog/data-policy/fixture/caps/expiry/approver/`target_scope:none`; mismatch exits 4 before secret resolution or transport.
- **AC-2**: Given valid authority, when `python scripts/run_openrouter_four_role_smoke.py execute --authorization <AUTHORIZATION> --configuration-set-sha256 <CONFIGURATION_SET_SHA256> --fixture <FIXTURE> --result-output evals/results/openrouter-smoke/<RUN_ID>/manifest.json --evidence-output docs/evidence/openrouter-smoke/<RUN_ID>/manifest.json` runs, then exactly four bounded hosted logical dispatches use the authorized identities and shared caps/abort, every role output passes its strict repository contract, lineage is typed/content-addressed, and target-adapter/target-call count is zero.
- **AC-3**: Both manifest paths must be new absent regular-file leaves under fixed roots and are published by T-F04d only through create-exclusive/no-follow same-directory temp writes, full fsyncs, no-replace dual commit, and recoverable transaction semantics. Existing file/symlink/path escape/reused run ID or injected crash/partial publication fails without overwrite; success requires byte-identical durable files, one canonical SHA-256, and a committed pair. The executor never copies/replaces either file after publication.
- **AC-4**: Given the committed pair, when the exact T-F04h offline `manifest` verifier runs against the evidence path, then requested equals returned for each role, all four model/reference identities are pairwise distinct, Judge and Red Team prompt/rubric/family/actual upstream identities are distinct, physical calls/retries/tokens/measured USD/wall-clock are within exact reservations and caps, and fallback/collision/negative semantic breach cannot pass.
- **AC-5**: An Evidence Reviewer may read only the durably committed evidence manifest whose bytes/hash equal the immutable result manifest. Its create-only `evidence-review.json` binds canonical review-record SHA-256 plus manifest/release/configuration/policy/catalog/data-policy/fixture/verifier-output hashes, reviewer identity distinct from executor, disposition, and timestamp; an existing review path or uncommitted/mismatched manifest pair blocks without overwrite.
- **AC-6**: A separately assigned Security Reviewer may read only the same committed immutable manifest pair. Its create-only `security-review.json` binds a distinct canonical review-record SHA-256, the same dependencies, reviewer identity distinct from executor and Evidence Reviewer, disposition, timestamp, and secret/PHI/injection/fallback/cap/abort/path-publication findings; any Critical/Important finding blocks approval.
- **AC-7**: Before T-F04h review verification, the executor/review precondition independently blocks an uncommitted or unequal manifest pair. Given the committed pair and both review records, T-F04h offline `reviews` verification makes missing/equal review hashes, duplicate/self reviewer identity, non-APPROVED disposition, stale timestamp, record/hash mismatch, or different manifest/release/configuration/fixture non-zero; T-F04e is APPROVED only when both layers pass.

## Test Plan
- Unit: none; deterministic contracts/verifier are frozen in T-F04h and composed CLI in T-F04d.
- Integration (operational): one authorized target-free dual-manifest create-only execution plus two no-network independent review passes over the committed immutable pair.
- Eval: sampled provider output is graded by exact bound policies/invariants, never exact-mocked.
- E2E: four provider identities only; no target adapter/live target.

## Definition of Done
- [ ] Exact dual-output execute plus T-F04h manifest/reviews verification commands and artifact hashes have expected exits.
- [ ] Pre-existing path, symlink, path escape, reused run ID, crash, partial publish, and unequal-byte cases cannot yield a reviewable manifest.
- [ ] Distinct Evidence and Security reviewers each write one immutable typed APPROVED record, or ticket remains honestly BLOCKED.
- [ ] No production/test code, owner authorization, credential, target, deployment, or prior record is changed.
- [ ] Provider spend occurs only inside the named cap; reviews are no-network.

## Out of Scope
No replacement for Judge calibration or Red Team evaluation, no target/campaign traffic, vulnerability claim, model default, Railway change, publication, remediation, or reviewer self-approval.
