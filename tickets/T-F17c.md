---
id: T-F17c
title: Bind exact system prompts and provider observations to hosted calls
status: backlog
wave: 27
depends_on: [T-F17a, T-F17b]
branch: ticket/T-F17c-hosted-system-messages
file_scopes:
  - src/agentforge/agents/hosted.py
  - src/agentforge/agents/hosted_runtime.py
  - src/agentforge/providers/openrouter.py
  - docs/integration/migrations/hosted-runtime-system-message-v1.md
test_scopes:
  - tests/test_hosted_configuration.py
  - tests/test_hosted_runtime.py
  - tests/test_openrouter_transport.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf distinct agents, model choice, Judge independence, observability
  - docs/deployment/FOUR_MODEL_RECOVERY.md
  - docs/planning/agent-runtime-provenance.md Prompt authority and lineage
---

## Context
Wave 27 consumes T-F17a's exact prompt registry and T-F17b's terminal provider-event contract.
`HostedConfigurationSet`, `HostedRunBinding`, and the raw packaged prompt hash remain the
authorization authorities. This is deterministic transport/composition work; sampled model quality
is not asserted with mocked output.

## Acceptance Criteria
- **AC-1**: Given each hosted role, when `_invoke` prepares a call, then the first message is the
  exact registry-owned system prompt whose raw-byte SHA-256 equals that role configuration, and the
  second/only other message is canonical structured user input.
- **AC-2**: Given missing/mismatched prompt role/version/hash, zero/multiple/misplaced system
  messages, or a caller-supplied system message, when preflight runs, then it fails before
  credential resolution, usage reservation, or network I/O.
- **AC-3**: Given the fixed hosted configuration, when a role call is formed, then its requested
  model is exactly the locked model for that role, its configured upstream is the only permitted
  upstream, fallback/aliases remain disabled, and the Judge and Red Team stay independent.
- **AC-4**: Given every physical success or failure including retries, when OpenRouter transport
  terminates the attempt, then it emits exactly one T-F17b provider event with sanitized typed error
  or provider-confirmed identity/usage/cost and the correct prompt/configuration/generation hashes.
- **AC-5**: Given a returned model/upstream mismatch, missing request id/usage/cost, or invalid
  structured output, when processed, then the call fails closed, never becomes a successful
  execution, and preserves the failure event without raw response content.
- **AC-6**: Given system-prompt bytes in the request, when token/cost exposure is reserved, then the
  conservative input bound includes them and can only widen the authorized reservation.

## Test Plan
- Unit: message order/cardinality/hash, locked models/upstreams, callback cardinality, typed errors.
- Integration: fake HTTP transport covers success, all terminal failures, and retry-then-success;
  assert exact sanitized provider events.
- Eval: later authorized campaign verifies actual provider responses; no mocked behavior claim.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged RED and Test Reviewer froze it.
- [ ] Existing deterministic precedence and no-target-client runtime invariants remain green.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F17c.md <DIFF_BASE>` exits 0.
- [ ] No prompt, credential, provider response body, target evidence, or PHI enters logs/events.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No production Runner wiring, target traffic, browser prompt endpoint, provider credential
provisioning, or claim that mocked responses prove model behavior.
