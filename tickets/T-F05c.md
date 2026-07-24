---
id: T-F05c
title: Implement campaign-grant and reviewed-smoke preflight
status: backlog
wave: 17
depends_on: [T-F04h, T-F05a, T-F05d, T-F05e, T-F05f, T-F05g, T-F05h, T-F05i, T-F05j, T-F05k, T-F05l, T-F05m, T-F05n, T-F05o, T-F05p]
branch: ticket/T-F05c-live-campaign-preflight
file_scopes:
  - src/agentforge/campaign/live_preflight.py
  - scripts/preflight_live_campaign.py
test_scopes: [tests/test_live_campaign_preflight.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, exact target authorization, synthetic-only fixtures, budget, rate, abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34, USR-04, USR-07, LEAD-09
  - .tdd-swarm/reports/openrouter-scope-review-final.md C1
  - .tdd-swarm/reports/session-binding-readiness.md SB-001, SB-002, SB-003
---

## Context
[locked-decision] Wave 17 deterministic code consumes T-F05d's target-session fixture identity,
T-F05h/T-F05i authenticated source projections, T-F05e's immutable-context and fresh-state
validators, T-F05j configuration/job binding, T-F05k loader, T-F05l observation source, T-F05m
provider, T-F05n/T-F05o ordered rotation evidence, T-F05f's Runner gate, and T-F05g's rotation
verifier. It owns one public zero-call campaign preflight that reads immutable
`campaign.json` itself and adds T-F04e smoke/review provenance to existing campaign authorization,
binding, caps, target preflight, Policy Gateway, and complete secret-free lease checks. Expected
fixture/context/policy/release/source-trust expectations come from the grant, never caller-selected
values. It calls the landed validators and must not parse a mirror or accept combined state.

## Acceptance Criteria
- **AC-1**: Given `python scripts/preflight_live_campaign.py --authorization docs/evidence/authorizations/campaign.json --target-observation <TARGET_OBSERVATION> --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --corpus-manifest <CORPUS_MANIFEST> --target-session-fixture-manifest <TARGET_SESSION_FIXTURE_MANIFEST> --configuration-projection <HOSTED_CONFIGURATION_PROJECTION> --smoke-manifest <SMOKE_MANIFEST> --evidence-review <EVIDENCE_REVIEW> --security-review <SECURITY_REVIEW> --smart-lease-context <SMART_SESSION_LEASE_CONTEXT> --runner-deployment-state <FRESH_CURRENT_RUNNER_DEPLOYMENT_STATE> --runner-control-state <FRESH_CURRENT_RUNNER_CONTROL_STATE> --runner-rotation-evidence <RUNNER_ROTATION_EVIDENCE> --rotation-start-control-state <ROTATION_START_CONTROL_STATE> --rotation-terminal-control-state <ROTATION_TERMINAL_CONTROL_STATE> --zero-runner-deployment-state <ZERO_RUNNER_DEPLOYMENT_STATE> --runner-activation-event <RUNNER_ACTIVATION_EVENT> --final-runner-deployment-state <FINAL_RUNNER_DEPLOYMENT_STATE> --launcher-ref <LAUNCHER_REF> --check-only`, when invoked, then it parses `campaign.json` as a grant and exits 0 only after every criterion below passes; absent/malformed/request-only/expired grant or any missing chain stage exits 4.
- **AC-2**: The grant and observed artifacts exactly agree on the T-F05p tracked catalog path/hash and select exactly one of `clinical-copilot-week1|clinical-copilot-week2`, exactly one enabled session-auth chat surface, one credential generation, normalized scheme/host/port, exact host allowlist/hash, corpus ID/hash, and the complete T-F05d fixture/patient/context/attestation/manifest identity with `synthetic_only:true`. Web/Runner catalog hashes must match, Web has no resolver authority, all UI/evidence/upload surfaces remain disabled, and release/deployment/target/T-F04g hashes agree.
- **AC-3**: The grant itself binds the canonical T-F04e smoke-manifest SHA-256 and unequal Evidence/Security review-record SHA-256 values. Preflight invokes T-F04h review verification with those grant-derived expectations and proves two distinct non-executor APPROVED reviewers plus exact manifest/release/configuration/fixture/requested-returned/upstream/prompt/rubric/criteria/policy/catalog/data-policy/verifier provenance; no expected hash is accepted from a CLI substitution.
- **AC-4**: The grant, current Policy Gateway, and T-F05e context exactly agree on aggregate/per-role physical call/retry/input/output/reasoning-token/USD/rate/concurrency/timeout/wall-clock/abort caps, grant expiry, launcher/distinct Approver, operation hash/nonce, context schema/version/hash, canonical credential reference/hash, generation, exact lease timestamps/value digest, exact T-F05d tuple, target/surface, mandatory-policy/release binding, and immutable source trust/database identity binding. The verifier separately reauthenticates and recomputes the supplied T-F05h/T-F05i artifacts, requires age at most 30 seconds and matching trust/release/manifest/generation, then calls the fresh validator with `current_claim=None`, requiring zero active campaigns/live leases before enqueue. Context bytes remain pinned; fresh observation hashes/times may differ.
- **AC-5**: The verifier composes—not replaces—the existing authorization/binding/caps/target/Policy-Gateway checks, T-F05p catalog and surface policy, T-F05h/T-F05i source validators, both T-F05e validators, the T-F05j persistence, T-F05k loading, T-F05l acquisition, and T-F05m provider interfaces, T-F05n/T-F05o ordered rotation evidence, T-F05f enforcement interface, and T-F05g rotation verifier. Every mismatch exits 4 before database mutation, credential resolution, adapter/SDK construction, provider call, target call, or spend; success prints only `CAMPAIGN_PREFLIGHT_OK <CAMPAIGN_AUTHORIZATION_SHA256>`.

## Test Plan
- Unit (deterministic): mutate every grant binding independently, including target/host/surface/allowlist, corpus/T-F05d identity, release/deployment, role configuration/policies, smoke/review hashes, caps/principals/expiry, immutable context/trust fields, and fresh T-F05h/T-F05i attestation/hash/time/count/drain/abort fields.
- Integration (deterministic): invoke the exact public CLI with immutable local fixtures; patch store writes, resolver, provider, target adapter, socket, and spend hooks to fail; prove T-F04h review expectations originate from `campaign.json`.
- Eval: none.
- E2E: no network; existing Policy Gateway checks plus additive smoke-review gate.

## Definition of Done
- [ ] Independent Test Agent produced clean criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05c.md <DIFF_BASE>` exits 0.
- [ ] Exact public preflight consumes the grant and returns zero-call exit 4 on every mismatch.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No T-F05d fixture, T-F05h/T-F05i source producer, T-F05e context/parser, T-F05j–T-F05m delivery,
T-F05n/T-F05o rotation evidence, T-F05f Runner, T-F05g rotation, authorization creation/approval, raw session resolution,
smoke/campaign execution, provider/target call, evidence mutation, deploy, or publication.
