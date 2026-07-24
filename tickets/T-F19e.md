---
id: T-F19e
title: Persist truthful producer events for console live refresh
status: backlog
wave: 36
depends_on: [T-F19d]
branch: ticket/T-F19e-console-event-producers
file_scopes:
  - src/agentforge/control_plane/events.py
  - src/agentforge/control_plane/store.py
  - src/agentforge/api/events.py
  - src/agentforge/api/postgres.py
  - src/agentforge/api/router.py
  - src/agentforge/security_tools/repository.py
  - src/agentforge/telemetry/outbound.py
  - src/agentforge/scheduler.py
  - migrations/versions/*_console_resource_events.py
test_scopes:
  - tests/test_control_plane_events.py
  - tests/test_postgres_api_m1d.py
  - tests/test_api_integration.py
  - tests/security_tools/test_security_tools.py
  - tests/test_outbound_telemetry.py
  - tests/test_scheduler_regression.py
  - tests/test_migrations.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Observability Layer
  - docs/planning/full-console-remediation.md Shared interaction quality
---

## Context
SSE is useful only if real transactions emit durable events. This ticket owns producers and a
bounded authoritative polling projection; T-F18k owns browser consumption.

## Acceptance Criteria
- **AC-1**: Real campaign, attempt, tool, agent, finding, approval, and component transitions persist
  organization-scoped events in the same transaction as authoritative state, including direct
  security-tool repository writes plus outbound and scheduler heartbeat writes.
- **AC-2**: Events have stable resource identity, kind, monotonic cursor, correlation, and timestamp;
  replay is ordered, idempotent, bounded, and permission checked.
- **AC-3**: Failed state writes emit no ghost event and failed event persistence fails the transaction.
- **AC-4**: Authenticated polling exposes the same resource revisions as event delivery so consumers
  can recover after disconnect or producer degradation.
- **AC-5**: Producer health/freshness is observable without exposing payload secrets.

## Test Plan
Exercise real control-plane, security-tool repository, outbound telemetry, and scheduler write paths
for every event class, migration/grant behavior, rollback/ghost-event tests, replay, and polling.

## Definition of Done
- [ ] Independent RED/review/freeze/GREEN/code/security sequence passes.

## Out of Scope
Browser SSE selection logic and production run evidence.
