---
id: T-F05a
title: Persist durable four-agent release lineage
status: backlog
wave: 7
depends_on: [T-F03a, T-F04a, T-F04c, T-F04d, T-F04h]
branch: ticket/T-F05a-trace-code
file_scopes:
  - src/agentforge/agents/runtime.py
  - src/agentforge/runner.py
  - src/agentforge/control_plane/store.py
  - src/agentforge/api/birdseye.py
test_scopes: [tests/test_four_agent_release_evidence.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf multi-agent requirement and Observability
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-13, PRD-25, PRD-26, LEAD-01
---

## Context
Wave 7 deterministic code consumes T-F04c's immutable configuration-set/execution references, T-F03a's Judge result, T-F04a's Red Team lineage, T-F04h's typed manifest contract, and T-F04d's composed execution metadata, then exposes durable lineage through runner/store/Birdseye. It must consume the persisted `HostedRoleConfiguration`; independent environment/artifact reparsing is forbidden.

## Acceptance Criteria
- **AC-1**: Given an offline or injected-transport four-role run, each started execution references the immutable T-F04c role-version/configuration-set hash and persists role/parent/phase/times/status/correlation/release SHA/target, requested and exact returned model/provider/endpoint identity, prompt/rubric/criteria/policy/catalog/data-policy/fixture hashes, input-output hashes, tokens, measured cost, trace ID, and cost provenance.
- **AC-2**: Given abort after role N, completed rows are immutable, interrupted role is terminal, later roles are explicitly omitted; verifier exits 0 only when parent graph is acyclic and complete for started roles.
- **AC-3**: Given forged/hash-invalid/orphan execution, Birdseye marks degraded/excludes proof; never synthesizes a missing role.
- **AC-4**: Given current-release query, all returned executions bind the same release SHA and campaign ID or verifier exits 3.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05a.md <DIFF_BASE>` exits 0 and report hashes are retained.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No live campaign, evidence docs, or provider/target request.
