---
id: T-F17a
title: Version and package the exact four-role system prompts
status: backlog
wave: 26
depends_on: [T-F00]
branch: ticket/T-F17a-agent-prompt-registry
file_scopes:
  - src/agentforge/agents/prompts/**
  - pyproject.toml
  - docs/integration/migrations/hosted-prompt-registry-v1.md
test_scopes:
  - tests/test_agent_prompts.py
  - tests/test_packaging.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf multi-agent roles, trust levels, AI-use disclosure
  - ARCHITECTURE.md agent-role and Judge-independence requirements
  - docs/planning/agent-runtime-provenance.md Prompt authority
---

## Context
This deterministic Wave-26 ticket creates the package-owned prompt authority consumed by T-F17c.
Raw packaged bytes are authoritative; a database value, environment value, browser value, or
caller-supplied string is not. T-F00 supplies the local gate/spec-lint contract.

## Acceptance Criteria
- **AC-1**: Given the installed wheel, when the prompt registry loads, then it returns exactly one
  immutable UTF-8 prompt for each of `orchestrator`, `red_team`, `judge`, and `documentation`, with
  explicit version and SHA-256 of the exact packaged bytes.
- **AC-2**: Given a missing, duplicate, altered, role-mismatched, non-UTF-8, oversized, or
  secret-shaped prompt resource, when the registry validates it, then it fails closed before a
  provider call and exposes no prompt fragment in the error.
- **AC-3**: Given each role prompt, when its trust-boundary assertions are inspected, then it
  forbids authority expansion and encodes that role's specific boundaries from the planning
  document, including Orchestrator select/halt only over a fresh authorized
  coverage/cost/regression snapshot and candidate set, bounded mutation-only Red Team,
  independent/fail-closed Judge, and draft-only Documentation behavior.
- **AC-4**: Given a wheel installed outside the repository, when prompt resources are resolved
  through `importlib.resources`, then all four version/hash/content records are byte-identical to
  the build inputs without filesystem fallback.

## Test Plan
- Unit: exact role set, raw-byte hash, version, size/encoding, role separation, secret-shape refusal.
- Packaging: build/install wheel outside checkout and resolve all prompt resources.
- Integration/eval/e2e: none; provider messaging belongs to T-F17c.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged RED and Test Reviewer froze it.
- [ ] Prompt resources contain no secrets, target sessions, PHI, or environment-specific values.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F17a.md <DIFF_BASE>` exits 0.
- [ ] Wheel/package verification, diff check, and secret scan pass.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No OpenRouter transport change, provider call, prompt UI, runtime composition, or browser authoring.
