---
id: T-F19a
title: Persist the versioned authorization-bound Tool ScanPlan
status: backlog
wave: 32
depends_on: [T-F16f, T-F17f]
branch: ticket/T-F19a-tool-scan-plan-contract
file_scopes:
  - src/agentforge/contracts/v1/tool_scan_plan.json
  - src/agentforge/contracts/v1/tool_plan_item.json
  - src/agentforge/contracts/v1/tool_run_event.json
  - src/agentforge/contracts/v1/tool_candidate_review.json
  - src/agentforge/contracts/v1/tool_reconciliation.json
  - contracts/v1/tool_scan_plan.json
  - contracts/v1/tool_plan_item.json
  - contracts/v1/tool_run_event.json
  - contracts/v1/tool_candidate_review.json
  - contracts/v1/tool_reconciliation.json
  - src/agentforge/contracts/registry.py
  - src/agentforge/storage/models.py
  - migrations/versions/*_tool_scan_plan.py
  - docs/migrations/tool-scan-plan-v1.md
test_scopes:
  - tests/test_contract_schemas.py
  - tests/test_migrations.py
  - tests/security_tools/test_scan_plan_storage.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf Tooling and Observability
  - docs/planning/full-console-remediation.md Tool execution model
---

## Context
T-F16f fans out target surfaces; it does not plan tool work. This ticket creates the immutable
per-tool plan and persistence boundary consumed by execution and the console.

## Acceptance Criteria
- **AC-1**: A versioned plan binds organization, campaign, release SHA, target/version/surface,
  corpus, authorization, and one item for every catalog tool with applicability and reason.
- **AC-2**: Each item independently records installed, configured, generated, executed, and
  evidenced/adjudicated facts; no fact implies another.
- **AC-3**: Plans, reviews, events, and reconciliations are append-only, organization-isolated,
  idempotent, and reject mutable identity or conflicting replay.
- **AC-4**: Status is limited to planned, running, complete, skipped, not_applicable, blocked, or
  failed; completion is impossible while an applicable item or reconciliation is incomplete.
- **AC-5**: Package and root schemas remain byte-equivalent and registry-valid.

## Test Plan
Contract, migration, RLS, idempotency, immutability, completeness, and negative-state tests.

## Definition of Done
- [ ] T-F16f/T-F17f completion commits and the full-console rebase point are recorded before RED.
- [ ] Independent RED/review/freeze/GREEN/code/security sequence passes.

## Out of Scope
Starting tools, target traffic, UI projection, or production evidence.
