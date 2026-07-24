---
id: T-F16d
title: Replace partial Week 2 document profiles with a bounded workflow
status: backlog
wave: 19
depends_on: [T-F16a, T-F16b]
branch: ticket/T-F16d-document-workflow
file_scopes:
  - src/agentforge/target/private_fixtures.py
  - src/agentforge/target/document_workflow_adapter.py
test_scopes:
  - tests/test_document_workflow_adapter.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf uploaded-content, indirect-injection, cost, and recovery requirements
  - sanitized owner document contracts in docs/planning/final-target-adapters.md
  - integration baseline 1ac3ee0 / partial commit 54b3a4d
---

## Context
[locked-decision] T-F16c removes the reachable partial document branches from `OpenEmrAdapter`; this disjoint ticket provides the replacement pure state machine over T-F16b. It accepts only the two authorization-bound complete fixture descriptors and cannot own a network client or arbitrary path.

## Acceptance Criteria
- **AC-1**: Resolver accepts only the two complete bound descriptors and a Runner-only no-follow regular file matching ref/hash/length/media/doc type/workflow. Arbitrary/relative/symlink/device/changed/missing paths fail before secret or target action.
- **AC-2**: Lab starts with one multipart `POST /documents` using exact form key `session_id`, fixed `doc_type=lab_pdf`, verified PDF, and zero retries; 200/202 must yield one bounded document ID and exact relative status URL.
- **AC-3**: Lab emits at most thirty status operations, each with exact query key `session_id` and at most one retry. It accepts only the closed state vocabulary/matching ID, stops on `failed`, and retrieves nothing before `complete`.
- **AC-4**: Completion performs one extraction report, page-1 PNG, and readback operation in order, each with at most one retry; validates grounded/unsupported redaction, private/no-store PNG metadata/limit, and source/artifact SHA verification without persisting bodies.
- **AC-5**: Intake performs exactly one zero-retry upload plus one zero-retry duplicate check using the same bytes and document ID; ambiguous timeout dispatches no retry.
- **AC-6**: Lab declares 34 logical operations and retry-inclusive maximum 67; intake declares 2/2. Full thirty-poll and partial-failure tests prove gateway reservation/account/trace equality; capacity 66 refuses lab before upload with zero calls.
- **AC-7**: Malformed ID/status URL/redirect/content/status/state/session expiry/poll exhaustion fails closed with no later operation and no session/path/PDF/image/extracted-content leakage.

## Test Plan
- Unit: test-owned fixture descriptors/bytes, no-follow safety, multipart/query keys, state machine, 30-poll/67-physical limit, zero-retry ambiguous upload, dynamic-ID grammar, redaction.
- Integration: injected gateway drives complete, duplicate, retry, timeout, failure, and insufficient-capacity flows.
- Eval: uploaded-content behavior remains separately authorized.
- E2E: no network and no owner fixture read.

## Definition of Done
- [ ] Reviewed criterion-tagged RED is frozen against the landed partial baseline.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F16d.md <DIFF_BASE>` exits 0.
- [ ] Every physical operation is gateway-owned/countable.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No Railway fixture provisioning, arbitrary upload, OCR, Runner/catalog, scan fanout, live call, or deploy.
