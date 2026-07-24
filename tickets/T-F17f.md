---
id: T-F17f
title: Show configured versus observed agent provenance and exact prompts
status: backlog
wave: 30
depends_on: [T-F17b, T-F17c, T-F17e]
branch: ticket/T-F17f-agents-provenance-ui
file_scopes:
  - src/agentforge/api/read_models.py
  - src/agentforge/api/postgres.py
  - src/agentforge/api/router.py
  - console/src/api/paths.ts
  - console/src/api/read-models.ts
  - console/src/types.ts
  - console/src/screens/AgentToolScreens.tsx
  - console/src/styles/console.css
test_scopes:
  - tests/test_agents_provenance_api.py
  - tests/auth/test_agent_prompts.py
  - console/tests/agents.test.tsx
  - console/tests/read-models.test.tsx
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf observability and AI-use disclosure
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-16, PRD-25, OPT-08, LEAD-05
  - User requirement: actual OpenRouter model and system prompt on Agents
  - docs/planning/agent-runtime-provenance.md Web and UI boundary
---

## Context
Wave 30 renders T-F17b provider-call evidence, T-F17c prompt identity, and T-F17e fresh runtime
capability. PostgreSQL/provider events are authoritative for observed execution; assignment/config
records are authoritative only for configured state. Clerk custom permissions are backend authority.

## Acceptance Criteria
- **AC-1**: Given an agent with configuration but no provider event, when `/agents` and the Agents
  screen render, then configured assignment is labeled configured/staged and observed execution is
  `not observed`; no model/upstream/request/tokens/cost are inferred.
- **AC-2**: Given successful provider events, when projected, then the latest and history views show
  provider-confirmed returned model, upstream, request id, input/output/reasoning tokens, measured
  cost state/value, prompt version/hash, configuration/generation hashes, timestamps, role, campaign,
  and logical/physical parent order.
- **AC-3**: Given a failed/retried call with incomplete provider facts, when projected, then each
  physical attempt has its typed error and unavailable fields; it is never collapsed into success or
  assigned zero cost.
- **AC-4**: Given `org:console:read`, when agent metadata is requested, then prompt version/hash and
  verification state are visible but prompt text is absent; given backend-verified
  `org:config:manage`, the dedicated role endpoint returns the exact packaged prompt text.
- **AC-5**: Given an unauthorized, wrong-organization, missing-permission, malformed-role, or
  prompt-hash-mismatch request, when the prompt endpoint is called, then it fails closed without
  prompt fragments, provider data, or existence leakage.
- **AC-6**: Given prompt text or any hostile/provider-supplied field, when the React screen renders,
  then it is escaped as text with bounded layout and no `innerHTML`, remote asset, or executable link.
- **AC-7**: Given deterministic activity, hosted activity, no activity, stale capability, API
  unavailable, or restricted prompt access, when the screen renders, then each state is explicit,
  keyboard navigable, and screen-reader labeled.
- **AC-8**: Given exact-key API decoders, when a configured/observed/prompt contract drifts, then
  Python and TypeScript decoders fail closed rather than silently dropping provenance.

## Test Plan
- Python API/auth: org scoping, permission matrix, prompt hash verification, exact observed fields,
  missing/failed/retry states.
- TypeScript unit/component: strict decoders; configured vs observed labels; exact prompt rendering;
  loading/empty/degraded/error/restricted/accessibility/XSS cases.
- Browser smoke: authenticated operator inspects all four roles after deployment; no credentials or
  tokens captured.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F17f.md <DIFF_BASE>` exits 0.
- [ ] Python/console lint, typecheck, tests, production build, accessibility, and secret scans pass.
- [ ] UI never calls a prompt-content endpoint for a principal without config permission.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No per-role configuration editing, prompt authoring, provider call, campaign launch, publication,
or weakening of backend permission checks.
