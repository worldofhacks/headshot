---
id: T-F05h
title: Produce authenticated Runner deployment state
status: backlog
wave: 8
depends_on: [T-F05a, T-F05d]
branch: ticket/T-F05h-runner-deployment-state
file_scopes:
  - pyproject.toml
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/runner_deployment_state.json
  - contracts/v1/runner_deployment_state.json
  - src/agentforge/policy/runner_state.py
  - src/agentforge/deployment/runner_deployment_state.py
  - scripts/project_runner_deployment_state.py
test_scopes: [tests/test_runner_deployment_state.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-binding-readiness.md SB-002, SB-004
  - .tdd-swarm/reports/session-lease-scope-review.md I1, I2
---

## Context
[locked-decision] This deterministic ticket is the sole owner of strict
`RunnerDeploymentState/v1` and verification/projection of signed
`DeploymentControllerObservation/v1` envelopes. It does not acquire an observation or perform an
activation. T-F05l is the sole production observation source and T-F05m invokes both on every
runtime refresh. A supplied JSON assertion, process-local count, environment flag, or
caller-selected trust root is never deployment authority.

## Acceptance Criteria
- **AC-1**: Schema URI `agentforge.runner-deployment-state`, `schema_version:1`, rejects duplicate, unknown, missing, non-finite, or malformed fields. Accepted artifacts are RFC 8785 canonical UTF-8 JSON with no BOM or trailing newline; their lowercase SHA-256 is computed over the exact detached bytes and is never a self-field. Root/package schema bytes and registry classification match.
- **AC-2**: The only fact source is a strict signed `DeploymentControllerObservation/v1` envelope whose canonical payload binds controller ID, environment, 40-lowercase-hex release SHA, deployment-manifest SHA-256, deployment generation ID, distinct active Runner generation IDs, Web campaign-launch admission state, Scheduler replica/admission state, stopped predecessor IDs, a 64-lowercase-hex request nonce, unique observation nonce, nonnegative controller sequence, whole-second UTC `observed_at`, and rotation fields. Rotation fields are exactly `rotation_id`, `rotation_phase`, `terminal_control_state_sha256`, and `activation_event_sha256`, with `null` only where the phase permits it. Unknown/duplicate fields, repeated IDs, or copied facts outside the signed payload fail.
- **AC-3**: Phase invariants are strict. `steady` may describe a truthful unsafe zero/one/multiple-generation observation. `draining` requires non-null rotation ID, closed Web/Scheduler admissions, and an active-generation set exactly equal to the predecessor set; T-F05o uses it to freeze the bounded control history. `pre_activation_zero` requires zero active generations, closed admissions, Scheduler replicas zero, all predecessor IDs stopped, and non-null terminal-control hash but null activation-event hash. `post_activation_one` requires exactly the intended new generation, the same rotation/predecessor/terminal-control binding, and a non-null activation-event hash. Controller sequence must be greater across draining → zero → activation → final evidence; a phase label cannot turn unsafe facts into approval.
- **AC-4**: The controller signature is Ed25519 over `UTF8("agentforge.runner-deployment-observation/v1") || 0x00 || RFC8785(payload)`. `pyproject.toml` declares `cryptography>=42` as a direct runtime dependency. Verification uses only `/run/agentforge/trust/runner-deployment-controller.ed25519.pub`; mandatory no-default `AGENTFORGE_RUNNER_DEPLOYMENT_TRUST_ROOT_SHA256` must equal the SHA-256 of that exact no-follow public-key file and immutable deployment-manifest binding. CLI trust-root/key/signature-bypass flags are forbidden.
- **AC-5**: The runtime typed producer accepts only T-F05l's non-serializable single-use receipt, independently loads/re-hashes the reviewed deployment manifest, verifies signature/trust/release/environment/generation, requires the signed request nonce equal the receipt's expected nonce, and derives every state field from the envelope. T-F05l is the only production constructor of that receipt. The offline evidence CLI uses a separate evidence-only entry point that reauthenticates a supplied signed envelope and its embedded nonce but cannot construct a runtime receipt, be selected by T-F05m, or satisfy Runner dispatch without a fresh T-F05l acquisition.
- **AC-6**: `validate_runner_deployment_state` re-verifies canonical bytes, detached digest, embedded signed source envelope, trust root, request/observation nonces, controller sequence, phase invariants, release, manifest, environment, generation, and copied-field equality. Stable failures are `runner-deployment-schema-invalid`, `runner-deployment-noncanonical`, `runner-deployment-source-untrusted`, `runner-deployment-request-mismatch`, `runner-deployment-binding-mismatch`, and `runner-deployment-authority-unavailable`; none includes source content or key material.
- **AC-7**: The offline command is `python scripts/project_runner_deployment_state.py --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --controller-observation <SIGNED_CONTROLLER_OBSERVATION> --output-root docs/evidence/runner-state`. It creates without replacement `docs/evidence/runner-state/<release_sha>/<generation>/runner-deployment-state.v1.<state_sha256>.json` plus a detached digest containing exactly 64 lowercase hexadecimal characters and one LF. Arbitrary output roots, raw state/count/admission/generation/request/trust overrides, stdin, and overwrite options are rejected.
- **AC-8**: Exits are `0` success, `2` CLI misuse, and `4` unavailable/untrusted/invalid authority with no partial output. Deterministic tests inject synthetic Ed25519 envelopes/nonces/clocks, cover every phase/hash-chain invariant, patch socket/HTTP/subprocess/controller hooks to fail, and prove absent authority creates no output; no test performs controller, Railway, database, provider, target, or network activity.

## Test Plan
- Unit (deterministic): strict schema/canonical bytes, signature/domain/key/path/request-nonce checks, phase/hash-chain invariants, copied-field equality, and stable redacted failures.
- Integration (deterministic): exact offline CLI/create-only paths and exits using synthetic signed envelopes; absent authority and every direct-state/bypass option fail with zero network/output.
- Eval/E2E: none; production acquisition belongs to T-F05l and actual controller access remains separately authorized.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05h.md <DIFF_BASE>` exits 0.
- [ ] The authenticated projection and root/package contract pass isolated consumer verification.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No observation acquisition transport, PostgreSQL projection, combined/context projection, activation,
Runner dispatch, Railway action, deployment, raw session value, provider/target call, network, or spend.
