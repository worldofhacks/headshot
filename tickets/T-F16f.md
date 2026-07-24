---
id: T-F16f
title: Orchestrate one authorized multi-surface scan
status: backlog
wave: 21
depends_on: [T-F16e]
branch: ticket/T-F16f-multi-surface-scan
file_scopes:
  - src/agentforge/control_plane/records.py
  - src/agentforge/control_plane/serialization.py
  - src/agentforge/control_plane/store.py
  - src/agentforge/control_plane/__init__.py
  - src/agentforge/api/router.py
  - src/agentforge/api/postgres.py
  - src/agentforge/api/read_models.py
  - src/agentforge/storage/models.py
  - migrations/versions/0016_final_target_scan_authorization.py
  - src/agentforge/campaign/surface_scan.py
  - src/agentforge/campaign/scan_coordinator.py
  - src/agentforge/campaign/__init__.py
  - src/agentforge/runner.py
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/final_target_scan_authorization_request.json
  - src/agentforge/contracts/v1/final_target_scan_authorization_decision.json
  - src/agentforge/contracts/v1/final_target_scan_queue_payload.json
  - src/agentforge/contracts/v1/final_target_scan_plan.json
  - src/agentforge/contracts/v1/final_target_scan_result.json
  - contracts/v1/final_target_scan_authorization_request.json
  - contracts/v1/final_target_scan_authorization_decision.json
  - contracts/v1/final_target_scan_queue_payload.json
  - contracts/v1/final_target_scan_plan.json
  - contracts/v1/final_target_scan_result.json
  - docs/migrations/final-target-scan-v1.md
test_scopes:
  - tests/test_final_target_scan_launch.py
  - tests/control_plane/test_store.py
  - tests/test_postgres_api_m1d.py
  - tests/test_migrations.py
  - tests/test_multi_surface_scan.py
  - tests/contract/test_conformance.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf multi-agent orchestration, full surface, cost, observability, and versioned contracts
  - User requirement that a launched scan uses every available tool/surface fully
  - docs/planning/final-target-adapters.md multi-surface scan semantics
---

## Context
[locked-decision] One current authorization/campaign owns one surface. Runner-only fanout would be an authority escalation. This ticket owns the real API/control-plane/store/migration/queue path from a user request through distinct parent and child decisions to a content-addressed queued plan, recovery, Runner fanout, and sanitized aggregate.

## Acceptance Criteria
- **AC-1**: `POST /final-target-scan-authorization-requests` validates and atomically persists one immutable parent request/ScanPlan plus the fixed ordered eight-child declared scope. Plan and children bind target/surface/version/policy/scope hashes, corpus/workflow/fixture refs, retry-inclusive maxima, per-child/global caps, session-generation refs, failure policy, release/catalog hashes, launcher/session, expiry, and canonical hashes.
- **AC-2**: `POST /final-target-scan-authorization-requests/{request_id}/decisions` and `POST /final-target-scan-authorization-requests/{request_id}/children/{child_id}/decisions` create distinct append-only parent/child records. Approver user/session must differ from launcher; launch requires an approved unexpired parent decision and a separately approved exact-hash decision for all eight children. Rejection/missing/self-approval/hash drift blocks atomically.
- **AC-3**: `POST /final-target-scans` atomically consumes the approved request once, persists run/plan/child links, and enqueues a versioned payload containing only IDs/hashes. Idempotent same-key request/decision/launch returns the original record; changed input conflicts. Queue redelivery/recovery reloads the authoritative records and never treats payload fields as authority.
- **AC-4**: Runner revalidates every persisted decision/scope/policy/session/expiry and reserves the sum of all retry-inclusive child maxima before the first child. Any authorization/hash/lease/cap/abort/integrity mismatch produces zero child calls. Cross-target children retain distinct gateways/counters/credentials; evidence is anonymous and documents run last.
- **AC-5**: Result schema always records all eight declared children. Lab/intake under v2.0, failed fixture proof, or partial v2.1 are `inactive_fixture_unproved`; `declared_scope_complete=false`. The schema rejects `full_surface_scan`; `active_surface_scan_complete=true` is allowed only when all active children succeeded and never implies declared-scope completeness.
- **AC-6**: Global failure terminates the parent and later children. A typed target/application failure terminates that child, may continue only separately approved independent children, and keeps `declared_scope_complete=false`. Counts, states, trace/evidence hashes, and omission reasons are durable and sanitized.
- **AC-7**: Tests begin at the real API, exercise two-person parent/eight-child decisions, commit and reload from the store/queue, then drive Runner. Migration upgrade/downgrade, crash recovery, abort, retry reconciliation, session pinning, repeated delivery/idempotency, and existing single-surface compatibility are covered.

## Test Plan
- Unit: schemas, fixed child derivation/order, decisions, aggregate reservations, failure matrix, session/anonymous separation, declared-scope completeness.
- Integration: real API -> durable request/parent+child approvals -> launch -> queue reload -> injected Runner fanout, including v2.0/failed fixture/partial v2.1, recovery, partial failures, abort, retries, and exact count/trace parity.
- Migration: durable tables/constraints/RLS/grants/queue version and downgrade safety.
- Eval: none.
- E2E: no network.

## Definition of Done
- [ ] Reviewed criterion-tagged RED is frozen.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F16f.md <DIFF_BASE>` and root/package contract conformance exit 0.
- [ ] Existing single-surface flow remains green.
- [ ] A user-launched run cannot reach Runner unless every child has a persisted distinct approval.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No deployment grant, Railway action, fixture provisioning, live run, load/100-case claim, or publication.
