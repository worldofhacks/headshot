---
id: T-F05n
title: Produce authenticated ordered Runner rotation evidence
status: backlog
wave: 15
depends_on: [T-F05e, T-F05f, T-F05h, T-F05i, T-F05j, T-F05o]
branch: ticket/T-F05n-runner-rotation-evidence
file_scopes:
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/runner_activation_event.json
  - contracts/v1/runner_activation_event.json
  - src/agentforge/contracts/v1/runner_rotation_evidence.json
  - contracts/v1/runner_rotation_evidence.json
  - src/agentforge/deployment/runner_rotation_evidence.py
  - scripts/project_runner_rotation_evidence.py
test_scopes: [tests/test_runner_rotation_evidence.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, synthetic-only data, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-binding-readiness.md SB-002, SB-004, SB-005
  - .tdd-swarm/reports/session-lease-scope-review.md I2
---

## Context
[locked-decision] This half-day ticket is the sole owner of strict
`RunnerActivationEvent/v1`, strict `RunnerRotationEvidence/v1`, and their offline
producer/verifier. It consumes separately authenticated T-F05h deployment states and T-F05o
bounded control history. It verifies a signed controller activation receipt but never performs,
authorizes, or requests activation; absent authorized receipt is `BLOCKED`.

## Acceptance Criteria
- **AC-1**: Both schema-version-1 artifacts reject duplicate/unknown/missing/non-finite/malformed fields and use RFC 8785 canonical UTF-8 bytes with no BOM/trailing newline and detached exact-byte SHA-256. Root/package schemas and registry match. Every identity/hash/nonce/sequence/timestamp is strict and every content-addressed output is create-only.
- **AC-2**: `RunnerActivationEvent/v1` is produced only from a strict signed `DeploymentControllerActivationReceipt/v1`. Its payload binds controller ID, environment, release SHA, deployment-manifest hash, rotation ID, terminal T-F05o control-state hash, T-F05h zero-deployment-state hash, intended predecessor/new generation IDs, immutable context ref/hash, activation nonce, controller sequence, whole-second `started_at`/`completed_at`, result `activated`, and zero-overlap policy hash. The receipt signature is Ed25519 over `UTF8("agentforge.runner-activation-receipt/v1") || 0x00 || RFC8785(payload)` and uses T-F05h's fixed no-follow trust root/manifest hash binding; caller key/trust/result/sequence/time overrides are forbidden.
- **AC-3**: `RunnerRotationEvidence/v1` binds by canonical hash five separately supplied artifacts in exact order: T-F05o start control state, T-F05o terminal control state, T-F05h `pre_activation_zero` deployment state, `RunnerActivationEvent/v1`, and T-F05h `post_activation_one` final state. It also binds release/manifest/rotation/predecessor/new-generation/context/target-session-fixture/policy identities. It embeds no source artifact bytes, raw token, session value, caller-composed state, or self hash.
- **AC-4**: Mechanical chain verification requires terminal control reference the start hash and identical complete campaign/job set; zero deployment reference terminal hash and prove closed admissions/zero generations/all predecessors stopped; activation event reference terminal+zero hashes and intended one new generation/context; final deployment reference the same terminal hash plus activation-event hash and prove exactly that intended generation. The start control state's authenticated draining observation and later controller artifacts satisfy `draining < zero < activation < final` controller sequence; all observation/activation nonces are distinct; start ≤ terminal database times, activation start ≤ completion, and zero/activation/final controller times are monotonic. Explicit hash links, not cross-clock assumptions, establish cross-authority order.
- **AC-5**: The activation producer independently reauthenticates the receipt/trust/release/manifest and creates the event only after validating supplied terminal+zero artifacts. The evidence producer independently invokes T-F05h/T-F05o/T-F05e validators and recomputes every hash. A final snapshot, opaque activation/no-overlap hash, unbounded campaign list, unsigned event, missing stage, alternate order, or one-field substitution cannot produce evidence.
- **AC-6**: The exact command is `python scripts/project_runner_rotation_evidence.py --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --target-session-fixture-manifest <TARGET_SESSION_FIXTURE_MANIFEST> --smart-lease-context <SMART_SESSION_LEASE_CONTEXT> --rotation-start-control-state <ROTATION_START_CONTROL_STATE> --rotation-terminal-control-state <ROTATION_TERMINAL_CONTROL_STATE> --zero-runner-deployment-state <ZERO_RUNNER_DEPLOYMENT_STATE> --activation-receipt <SIGNED_ACTIVATION_RECEIPT> --final-runner-deployment-state <FINAL_RUNNER_DEPLOYMENT_STATE> --output-root docs/evidence/runner-rotations`. It creates event/evidence JSON and detached digests under `<release_sha>/<rotation_id>/` without replacement; action/source/trust/state/hash/sequence/time/output overrides, stdin, and overwrite are rejected. Exits are `0`, `2`, `4` with no partial pair.
- **AC-7**: Stable failures are `runner-activation-source-untrusted`, `runner-activation-binding-mismatch`, `runner-rotation-schema-invalid`, `runner-rotation-chain-incomplete`, `runner-rotation-order-invalid`, and `runner-rotation-authority-unavailable`; none leaks receipt/source content. Deterministic tests use synthetic signatures/attestations and fake clocks, mutate every chain edge/set/nonce/sequence/time/identity, and patch controller/database/Railway/provider/target/network/spend hooks to fail.

## Test Plan
- Unit (deterministic): strict schemas/canonical bytes, activation signature/trust, five-stage hash chain, exact set/order/nonce/sequence/time/identity invariants, create-only failures.
- Integration (deterministic): exact CLI produces event+evidence from synthetic authenticated stages; every omitted/reordered/substituted stage leaves zero partial output.
- Eval/E2E: none; actual activation/receipt/controller/database/Railway activity is separately authorized.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05n.md <DIFF_BASE>` exits 0.
- [ ] Activation authenticity and the complete ordered rotation chain verify mechanically.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No deployment/controller command, observation acquisition, control-history projection, Runner
dispatch, configuration/runbook change, Railway action, raw session value, network, or spend.
