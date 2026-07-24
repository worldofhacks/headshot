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
  - src/agentforge/target/spec.py
  - src/agentforge/campaign/authorization.py
  - src/agentforge/control_plane/serialization.py
  - src/agentforge/control_plane/store.py
  - src/agentforge/api/router.py
  - src/agentforge/api/read_models.py
  - src/agentforge/api/postgres.py
  - docs/integration/migrations/hosted-runtime-system-message-v1.md
test_scopes:
  - tests/test_hosted_configuration.py
  - tests/test_hosted_runtime.py
  - tests/test_openrouter_transport.py
  - tests/target/test_target_spec.py
  - tests/test_campaign_authorization.py
  - tests/control_plane/test_store.py
  - tests/test_postgres_api_m1d.py
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
is not asserted with mocked output. This ticket also owns the cross-layer hosted-100 authorization
contract so the hosted limits, domain scope/hash/serialization, API models, PostgreSQL preflight,
and transport ledger cannot disagree about an expanded profile.

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
- **AC-4**: Given every physical success or failure including transport-internal retries, when
  OpenRouter transport is invoked, then it requires the Runner-owned
  `begin_physical_attempt(logical_context, sequence)` factory before each reservation/network
  attempt. Retry-then-success commits two distinct pre-call invocation rows and two terminal events,
  preserves one running logical execution between attempts, and terminalizes that logical execution
  only with final success or terminal failure.
- **AC-5**: Given a returned model/upstream mismatch, missing request id/usage/cost, or invalid
  structured output, when processed, then the call fails closed, never becomes a successful
  execution, and preserves the failure event without raw response content.
- **AC-6**: Given system-prompt bytes in the request, when token/cost exposure is reserved, then the
  conservative input bound includes them and can only widen the authorized reservation.
- **AC-7**: Given scope-hashed `profile_id=hosted-100-v1` and
  `scope.caps.logical_case_limit=100`, when configuration validates, then `N=100`, `R=0`, role call
  maxima are exactly 100 each, concurrency is one, the hard physical maximum is 400, and actual
  calls must equal `300 + eligible_documentation_count`. Each global input/output/reasoning-token
  cap equals the sum of its four role caps; each role cash cap equals its exact Decimal
  token-cap-times-configured-price reservation and the global/binding spend cap equals their sum.
- **AC-8**: Given the hosted-100 time reservation, when authorization is requested, then
  `400 × provider_timeout_seconds` plus final T-F16 target time and bounded Runner overhead fits
  `scope.caps.run_timeout_seconds`, the authorization expiry covers that timeout, and the existing
  300-second per-call/3,600-second authorization ceilings remain hard. The hosted configuration,
  `HostedRunBinding`, operation/scope hash, canonical serialization, API input/read models,
  PostgreSQL preflight, and Runner all agree exactly; any profile/call/token/spend/retry/concurrency/
  time mismatch rejects before I/O.
- **AC-9**: Given any hosted profile other than exact `hosted-100-v1`, when a caller requests 400
  calls, spend above USD 5, or hosted-100-only token/time expansion, then domain, API, and control
  plane reject it and retain the legacy 56-call/USD-5 ceilings.

## Test Plan
- Unit: message order/cardinality/hash, locked models/upstreams, per-attempt factory cardinality,
  two distinct retry contexts, running-between-attempts state, typed errors, profile identity, and
  exact call/token/Decimal-spend/time formulas.
- Integration: fake HTTP transport covers success, all terminal failures, retry behavior outside
  the 100-case profile, invocation correlation, crash reconciliation, and exact sanitized events;
  domain/API/read-model/serialization/PostgreSQL tests accept exact hosted-100 and reject expanded
  legacy or mismatched profiles.
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
