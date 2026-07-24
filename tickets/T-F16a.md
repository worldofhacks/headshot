---
id: T-F16a
title: Harden surface-specific transport and credential policy
status: backlog
wave: 17
depends_on: [T-F00]
branch: ticket/T-F16a-surface-policy
file_scopes:
  - src/agentforge/target/spec.py
  - src/agentforge/target/catalog.py
  - src/agentforge/target/registry.py
  - src/agentforge/control_plane/serialization.py
  - docs/migrations/final-target-surface-policy-v2.md
test_scopes:
  - tests/test_final_target_surface_policy.py
  - tests/target/test_relative_path_parameters.py
  - tests/target/test_target_spec.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live-target hard gate and versioned-interface requirements
  - AGENTS.md exact authorization, synthetic-data, budget/rate, and abort gates
  - integration baseline 1ac3ee0 including partial adapter commit 54b3a4d
  - docs/planning/final-target-adapters.md
---

## Context
[locked-decision] RED begins against integration commit `1ac3ee0`. Its target-wide profile set and path-derived Runner behavior are partial code to harden/replace. The final contract must distinguish chat JSON `session_id`, UI query `sid`, anonymous evidence, document multipart/query `session_id`, retry policy, and complete fixture identity in one canonical per-surface authorization hash.

## Acceptance Criteria
- **AC-1**: Given a catalog with multiple surfaces, each enabled surface resolves exactly one immutable policy binding adapter profile, credential placement and exact field name, request/response types, methods, limits, redirect rule, operation templates, retry count per operation class, maximum logical operations, retry-inclusive physical maximum, fixture descriptors, and canonical policy SHA-256; missing/duplicate/target-wide ambiguity fails closed.
- **AC-2**: Evidence scope binds `auth_mode=none`, `explicit_no_auth=true`, no credential ref/field; UI binds query field exactly `sid`; chat binds JSON field exactly `session_id`; document upload/read bind multipart/query field exactly `session_id`. Any alternate query/header/cookie/body placement changes the hash and fails resolution.
- **AC-3**: Each fixture descriptor binds exactly `{opaque_ref, sha256, byte_length, media_type, doc_type, workflow_id}`. Arbitrary paths, mutable locators, incomplete descriptors, duplicate refs, or upload policy without a complete descriptor fail before resolution.
- **AC-4**: Each operation class binds a finite nonnegative retry count and derived physical maximum. State-changing document upload retries are zero; poll/read retries are at most one; nonfinite/unbounded/understated maxima fail closed.
- **AC-5**: Registry resolution compares exact surface policy/hash/auth/field/retry/fixture/method/path facts from the canonical scope. Any drift after approval fails before secret/fixture resolution or adapter construction; no path heuristic or target-level auth fallback passes.
- **AC-6**: Legacy single-profile chat/synthetic definitions remain compatible; mixed-shape legacy and `54b3a4d` target-wide `payload_profiles` cannot authorize new surfaces. The migration note identifies the v2 hash break, old-approval invalidation, staged activation, and rollback.

## Test Plan
- Unit: canonical policy/hash, exact credential-key table, retry/physical arithmetic, complete fixture descriptors, hostile combinations, legacy compatibility.
- Integration: catalog -> registry -> canonical scope for all final surfaces against `1ac3ee0`; mutations fail before side effects.
- Eval/E2E: none; no network.

## Definition of Done
- [ ] Independent Test Agent produces clean criterion-tagged RED against `1ac3ee0`; Test Reviewer freezes it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F16a.md <DIFF_BASE>` exits 0.
- [ ] Existing chat/session/patient gates remain unchanged or stricter.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No adapter transport, workflow, Runner composition, catalog activation, credential/fixture read, live call, or deploy.
