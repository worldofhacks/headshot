---
id: T-F16b
title: Meter retry-inclusive gateway-owned physical operations
status: backlog
wave: 18
depends_on: [T-F16a]
branch: ticket/T-F16b-physical-operation-gateway
file_scopes:
  - src/agentforge/target/base.py
  - src/agentforge/policy/gateway.py
  - src/agentforge/campaign/coordinator.py
test_scopes:
  - tests/test_surface_operation_gateway.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf cost, rate, repeatability, and failure-recovery requirements
  - AGENTS.md exact live-run budget/rate/abort gates
  - integration baseline 1ac3ee0 physical-work-unit changes
  - docs/planning/final-target-adapters.md
---

## Context
[locked-decision] `1ac3ee0` improves per-turn/retry work-unit persistence but still exposes one `adapter.send()` boundary. A response-driven document workflow must not hide upload, polling, or retrieval calls. The Policy Gateway owns the sole one-operation sender and reserves the complete retry-inclusive physical maximum before any write.

## Acceptance Criteria
- **AC-1**: Given a finite operation flow, preflight derives physical maximum as the sum of `1 + max_retries` for every possible operation, and reserves attempts, projected cost, minimum rate-window time, authorization/lease time, run timeout, and trace capacity before the first state-changing operation; insufficient capacity sends zero requests.
- **AC-2**: Immediately before each physical attempt/retry, the gateway revalidates authorization, abort, lease, policy hash, method/path/template, destination, response limit, remaining capacity, rate, and timeout, then records/charges exactly one physical unit on success or failure.
- **AC-3**: Only typed next operations allowed by the bound policy may follow a response. Dynamic segments use a closed grammar and cannot add host/query/traversal/encoding/method or exceed the declared flow/retry maximum.
- **AC-4**: Upload operations with `max_retries=0` never retry after timeout/unknown outcome. A generic test policy with two retries proves fail-twice/succeed-third uses three reserved physical units; document poll/read policies stop after the configured second attempt.
- **AC-5**: Timeout, invalid transition, poll exhaustion, lease/cap/abort/integrity failure prevents later operations, preserves immutable completed physical rows, and returns bounded terminal reason plus count/trace references without secret/body leakage.
- **AC-6**: An adapter cannot access transport outside the injected one-operation sender or understate its plan. Existing atomic, sequential chat, retry, typed error, no-fallback, and `1ac3ee0` work-unit invariants stay green.

## Test Plan
- Unit: retry-inclusive capacity, fail-twice/succeed-third, zero-retry ambiguous write, underdeclared flow, path/transition/abort ordering.
- Integration: injected atomic/chat/workflow transports; physical attempts equal reservations, accounting, observations, and traces on success/failure.
- Eval/E2E: none; no sockets.

## Definition of Done
- [ ] Reviewed criterion-tagged RED is frozen against `1ac3ee0`.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F16b.md <DIFF_BASE>` exits 0.
- [ ] Existing chat/session/patient gates remain unchanged or stricter.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No Co-Pilot payload, fixture resolver, scan fanout, catalog change, live call, or deploy.
