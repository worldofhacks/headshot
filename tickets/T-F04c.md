---
id: T-F04c
title: Atomically stage versioned hosted role configurations
status: backlog
wave: 1
depends_on: [T-F00]
branch: ticket/T-F04c-hosted-role-staging
file_scopes:
  - src/agentforge/config.py
  - src/agentforge/agents/runtime.py
  - src/agentforge/control_plane/store.py
  - src/agentforge/storage/models.py
  - migrations/versions/0014_hosted_role_configuration.py
  - scripts/stage_openrouter_role_configurations.py
  - .env.example
test_scopes: [tests/test_hosted_role_configuration_staging.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf four-agent model use, independence, authorization, and observability
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-13, PRD-15, PRD-16, PRD-25, PRD-26, OPT-08
  - .tdd-swarm/reports/openrouter-scope-review.md C1 and I1
  - .tdd-swarm/reports/openrouter-scope-review-final.md M1
---

## Context
[locked-decision] Wave 1 owns only the versioned configuration domain, canonical no-default settings, migration, append-only persistence, and reachable create-only zero-external-network staging command. `HostedRoleConfiguration` stores sealed reference identifiers, never secrets. The staging command parses the four role settings once, validates the complete set, persists all four versions atomically, remains staged/inactive, and emits only the canonical configuration-set SHA-256. Read-only preflight/projection/drift is T-F04g; provider transport is T-F04f.

## Acceptance Criteria
- **AC-1**: Given canonical `HEADSHOT_<ROLE>_*` settings, when parsed once, then each role record contains provider `openrouter`, requested/expected-returned model, sealed credential-reference ID, expected upstream provider/endpoint, repository schema ID, prompt/rubric/criteria/policy/catalog/data-policy hashes, authorization-bound catalog input/output/reasoning price vector and `max_price`, base URL, max input/output/reasoning tokens, and per-role/global call/token/USD/wall-clock/rate/retry/concurrency limits; any missing/blank/unknown field exits 4 without defaults.
- **AC-2**: Given four proposed records, when set validation runs, then model/reference IDs are pairwise distinct and Judge versus Red Team prompt/rubric-or-criteria/family/upstream identities are distinct; raw credential-shaped values, mutable locators, invalid price/cap units, unsupported schema IDs, and collisions are rejected.
- **AC-3**: Given `python scripts/stage_openrouter_role_configurations.py --release-sha <RELEASE_SHA> --actor-ref <ACTOR_REF> --hash-only`, when invoked through its public CLI with a staging-authorized workload DB identity, then it computes `FULL_FOUR_ROLE_INPUT_SHA256` over the schema-versioned canonical serialization of all four complete role inputs sorted by role (excluding actor/audit metadata) and the idempotency identity `SHA256("hosted-role-stage-v1" || RELEASE_SHA || FULL_FOUR_ROLE_INPUT_SHA256)`. One transaction inserts exactly four append-only versions plus one canonical set record, returns only `<CONFIGURATION_SET_SHA256>`, performs no secret resolution/provider/target call, and leaves activation staged.
- **AC-4**: Given any validation/insert failure, when staging runs, then the transaction persists zero of four records. The actor reference is audit metadata and never part of idempotency. The same release SHA plus the same full-input hash returns the original set hash without new rows even for a retried actor/session; the same release SHA plus changed canonical full-role input conflicts without mutation or reuse. A legitimate later staged version requires a different release SHA and receives a new identity.
- **AC-5**: Given migration/store tests, when assignment and execution rows reference hosted authority, then they bind role version/hash and configuration-set SHA-256 through integrity constraints; upgrade/downgrade, uniqueness, append-only triggers/RBAC, and orphan rejection pass.

## Test Plan
- Unit (deterministic): complete settings/domain validation, price/token units, collision/raw-secret rejection, canonical full-input/idempotency/set hashes, actor exclusion, hash-only stdout.
- Integration (deterministic): invoke public stage CLI with injected repository/transaction; prove four-or-zero atomicity, same-release/same-input retry across actor/session, same-release/changed-input conflict, new-release/new-identity staging, staged state, migration round-trip, assignment/execution references.
- Eval: none.
- E2E: zero external network; resolver/provider/target constructors patched to fail.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F04c.md <DIFF_BASE>` exits 0 and migration/CLI reachability evidence is retained.
- [ ] Staging outputs only the set hash and cannot activate or expose/resolve secrets.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No read-only preflight/projection/drift, provider transport/accounting, role behavior, fixture/contracts, smoke composition, provider/target call, credential creation, or authorization creation.
