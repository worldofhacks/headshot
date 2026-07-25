---
id: T-F05g
title: Enforce zero-overlap SMART session rotation and deployment
status: backlog
wave: 16
depends_on: [T-F05e, T-F05f, T-F05h, T-F05i, T-F05j, T-F05k, T-F05l, T-F05m, T-F05n, T-F05o, T-F05p]
branch: ticket/T-F05g-smart-session-rotation
file_scopes:
  - railway/runner.json
  - .env.example
  - scripts/verify_runner_rotation_state.py
  - docs/deployment/RAILWAY.md
  - docs/target/READINESS.md
test_scopes: [tests/test_smart_session_lease_rotation.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, synthetic-only data, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34, USR-04, USR-07, LEAD-09
  - .tdd-swarm/reports/session-binding-readiness.md SB-002, SB-004, SB-005
  - .tdd-swarm/reports/session-lease-scope-review.md I1, I2, I3
---

## Context
[locked-decision] This ticket owns only deployment/configuration and the operator-verifiable
rotation gate after Runner enforcement and T-F05n evidence production land. It consumes the entire
authenticated ordered chain rather than attempting to infer history from one final snapshot. There
is no combined rotation authority, raw session value, source producer, activation action, or Runner
dispatch change here.

## Acceptance Criteria
- **AC-1**: `railway/runner.json` sets Runner deployment overlap to exactly zero with no rolling fallback. Runner-only `AGENTFORGE_SMART_SESSION_MAX_LIFETIME_SECONDS`, `AGENTFORGE_RUNNER_DEPLOYMENT_GENERATION_ID`, `AGENTFORGE_SMART_SESSION_LEASE_CONTEXT_REF`, `AGENTFORGE_SMART_SESSION_FRESH_STATE_PROVIDER`, `AGENTFORGE_RUNNER_DEPLOYMENT_TRUST_ROOT_SHA256`, `AGENTFORGE_RUNNER_CONTROL_PROJECTOR_TRUST_ROOT_SHA256`, and `AGENTFORGE_RUNNER_CONTROL_DB_IDENTITY_SHA256` are mandatory and have no defaults; examples contain placeholders/synthetic non-secret values only.
- **AC-2**: The exact offline command is `python scripts/verify_runner_rotation_state.py --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --target-session-fixture-manifest <TARGET_SESSION_FIXTURE_MANIFEST> --smart-lease-context <SMART_SESSION_LEASE_CONTEXT> --runner-rotation-evidence <RUNNER_ROTATION_EVIDENCE> --rotation-start-control-state <ROTATION_START_CONTROL_STATE> --rotation-terminal-control-state <ROTATION_TERMINAL_CONTROL_STATE> --zero-runner-deployment-state <ZERO_RUNNER_DEPLOYMENT_STATE> --runner-activation-event <RUNNER_ACTIVATION_EVENT> --final-runner-deployment-state <FINAL_RUNNER_DEPLOYMENT_STATE> --check-only`. Every artifact is supplied separately, reparsed, rehashed, and reauthenticated through T-F05h/T-F05i/T-F05e/T-F05n; omitted, duplicate, aliased, single-snapshot, or combined-state inputs exit 2/4.
- **AC-3**: Exit 0 requires T-F05n's complete chain: durable admissions closed and exact predecessor campaign/job set frozen in the start control artifact; the terminal artifact references that start hash and proves the identical complete set terminal with zero live leases and no later predecessor job; a signed zero-generation deployment artifact references the terminal hash and proves all predecessors stopped; a signed activation event references both hashes and intended new context/generation; and a higher-sequence signed final artifact references the activation event and proves exactly the intended one active generation. Hash, rotation ID, release, manifest, trust, generation, sequence, nonce, time, context, fixture, or set mismatch exits 4.
- **AC-4**: A current hard-aborted Runner claim is never dispatch-safe. A terminal historical hard-abort counts only when T-F05n proves the exact bounded campaign and every owned job terminal with no live lease. A fresh final snapshot alone, unverified activation/no-overlap hash, empty local queue, process boolean, or stale artifact can never prove the ordered history.
- **AC-5**: The new generation requires a new target version, scope, context hash/ref, grant nonce, launcher, and distinct Approver. Target-confirmed expiry is terminal; no procedure overwrites/reloads the context, refreshes/re-resolves/swaps a session or patient in place, or reuses an old observation/activation receipt.
- **AC-6**: `.env.example`, Railway guidance, and target readiness consistently document T-F05p's identical Web/Runner catalog hash, chat-only surface policy, one target/session/patient pin, and Runner-only credential mapping; T-F05j configuration/job binding; T-F05k secure loader; fixed T-F05l source; T-F05m per-call refresh; T-F05n event/evidence chain; and T-F05f sanitized public rejection message with separate machine code/status. They show only canonical versioned `secretref://` and `leasecontext://` references plus generation-specific Runner-only sealed-variable names and reject executable `env:` or `OPENEMR_SESSION_COOKIE` live-session guidance.
- **AC-7**: Documentation preserves issuer lifetime/idle timeout/history namespace/target ceiling/expired-response behavior as measured unknowns. Secret-pattern scans find no session material, and configuration tests—not prose alone—enforce zero overlap, mandatory no-default configuration, fixed source acquisition, ordered evidence, stale/substitution failure, and sanitation.

## Test Plan
- Unit (deterministic): exact no-default configuration and complete verifier flags; each chain hash/ID/sequence/nonce/time/set/trust negative; single-snapshot/combined/legacy input rejection.
- Integration (deterministic): offline admissions-closed → bounded drain/abort → zero generations → signed activation event → exactly one generation using synthetic signed/attested artifacts; canonical guidance and secret scan.
- Eval/E2E: none; no Railway/network/credential/controller/database/provider/target action.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05g.md <DIFF_BASE>` exits 0.
- [ ] Zero-overlap configuration and the entire independently authenticated ordered rotation history are mechanically verified.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No raw session value, secret provisioning/rotation, Runner dispatch/schema/source/evidence producer
code, Railway inspection/mutation, activation/deployment, live observation, provider/target call, or spend.
