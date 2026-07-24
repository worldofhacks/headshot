---
id: T-F16e
title: Migrate immutable environment catalogs and compose per-surface adapters
status: backlog
wave: 20
depends_on: [T-F05a, T-F06a, T-F16c, T-F16d]
branch: ticket/T-F16e-final-target-composition
file_scopes:
  - src/agentforge/runner.py
  - src/agentforge/target/catalog.py
  - config/live-target-catalog.staging.json
  - config/live-target-catalog.production.json
  - config/live-target-catalog.staging.document-enabled.json
  - config/live-target-catalog.production.document-enabled.json
  - config/live-target-catalog.staging.v1.rollback.json
  - config/live-target-catalog.production.v1.rollback.json
  - config/live-target-catalog-manifest.json
  - docs/migrations/final-target-catalog-v2.md
test_scopes:
  - tests/test_final_target_adapter_integration.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, versioned contracts, auth/rate documentation
  - AGENTS.md Railway environment isolation and exact target authorization
  - integration baseline 1ac3ee0 environment catalogs and Runner partial profiles
  - docs/planning/final-target-adapters.md
---

## Context
[locked-decision] This ticket hardens/replaces `1ac3ee0` Runner/catalog changes. It owns per-surface adapter construction and immutable environment-specific definitions, not a seven-surface scan. Old version `1.0.0` snapshots remain rollback/history; duplicate `copilot-*` aliases are removed. New versions are staged while draft, activated by state/lifecycle events, and never mutated in place.

## Acceptance Criteria
- **AC-1**: Staging and production each have a secret-free canonical catalog containing only `clinical-copilot-week1/week2`, with environment-specific credential refs, ownership/promotion refs, policy/fixture-binding hashes, and target/surface version `2.0.0`; Web/Runner parity is required within an environment and cross-environment byte equality is forbidden.
- **AC-2**: `2.0.0` enables chat/evidence/UI and keeps documents disabled. Separate Staging/production `2.1.0` document-enabled catalogs are hash-bound candidates only; they cannot be selected until T-F16g validates the environment's fresh trusted post-deploy Runner fixture-check attestation.
- **AC-3**: Synchronization creates new draft target/surface snapshots, is idempotent for identical environment/version/input hashes, conflicts on changed input, then uses append-only state/lifecycle events to validate/ready/activate. Old `1.0.0` definitions/approvals remain immutable and fail against v2 policy hashes.
- **AC-4**: If fixture proof fails, `2.1.0` receives no activation event and active `2.0.0` chat/evidence/UI remain unchanged. If proof passes, document is enabled while `2.1.0` is draft before validating/ready; rollback events restore the recorded prior target/catalog.
- **AC-5**: Runner resolves profile only from the authorization-bound surface policy/hash. Anonymous evidence performs no lease/secret resolution; authenticated chat/UI/document require the exact target session generation and cannot rotate or cross targets.
- **AC-6**: Per-surface injected execution proves exact adapter construction and physical count/redaction behavior. Existing chat, lineage, replay, `1ac3ee0` live-100 work-unit, target-catalog, and Policy Gateway suites remain green; no claim of user-launched multi-surface fanout is made.

## Test Plan
- Unit: catalog structure/hash/environment separation, alias rejection, v1->v2 immutability, sync/activation/rollback idempotency, document proof gate, exact Runner profile/credential selection.
- Integration: injected per-surface execution plus existing chat/lineage/replay/work-unit regressions.
- Eval/E2E: none; no network.

## Definition of Done
- [ ] Reviewed criterion-tagged RED is frozen against `1ac3ee0`.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F16e.md <DIFF_BASE>` exits 0.
- [ ] Secret/catalog/migration/rollback validators pass.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No scan fanout, grant verifier, Railway mutation, fixture provisioning, live call, provider/model change, or deployment.
