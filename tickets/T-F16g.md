---
id: T-F16g
title: Verify final-target deployment grants without side effects
status: backlog
wave: 22
depends_on: [T-F16f]
branch: ticket/T-F16g-final-target-preflight
file_scopes:
  - src/agentforge/deployment/final_target_preflight.py
  - src/agentforge/deployment/final_target_observer.py
  - scripts/preflight_final_target_adapters.py
  - scripts/observe_final_target_state.py
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/final_target_deployment_authorization.json
  - src/agentforge/contracts/v1/final_target_current_state_attestation.json
  - contracts/v1/final_target_deployment_authorization.json
  - contracts/v1/final_target_current_state_attestation.json
  - pyproject.toml
test_scopes:
  - tests/test_final_target_deployment_preflight.py
  - tests/test_final_target_state_observer.py
  - tests/contract/test_conformance.py
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, evidence, versioned contracts, auth/rate requirements
  - AGENTS.md exact live authorization, Railway isolation, two-person and dual-remote law
  - docs/planning/final-target-adapters.md deployment gate
---

## Context
[locked-decision] The operational deploy agent may not invent grant parsing or call caller-authored state “current.” This deterministic predecessor owns a versioned grant, signed current-state attestation contract, injectable read-only observer, and networkless verifier. T-F16h alone invokes observation against authorized infrastructure.

## Acceptance Criteria
- **AC-1**: Exact verifier command is `python3 scripts/preflight_final_target_adapters.py --authorization docs/evidence/authorizations/final-target-adapters.json --release-manifest <RELEASE> --state-attestation <ATTESTATION> --catalog-manifest config/live-target-catalog-manifest.json --scan-plan <SCAN_PLAN> --rollback-manifest <ROLLBACK> --check-only`. It reads the grant itself; absent/malformed/request-only/expired input exits 4.
- **AC-2**: Bootstrap runs with the discoverable `python3` command and, before application imports, verifies Python >=3.12 plus grant-bound interpreter realpath/version/executable SHA-256, verifier script SHA-256, `pyproject.toml` SHA-256, installed dependency-set hash, and release SHA. Missing interpreter/dependency or drift exits 4; these values enter sanitized evidence.
- **AC-3**: Exact observer command is `python3 scripts/observe_final_target_state.py --authorization docs/evidence/authorizations/final-target-adapters.json --environment <ENVIRONMENT> --transition <TRANSITION> --output <ATTESTATION> --read-only`. With an injected read-only provider/Runner observer and sealed signing reference it emits a canonical Ed25519-signed attestation; tests use local fakes and no network.
- **AC-4**: Attestation binds schema/version, issuer/key fingerprint, environment/project/Runner/Web service IDs, transition, `observed_at`, expiry and maximum age, monotonic deployment IDs, raw provider-response digests, only-Web-public topology, deployed/current release, catalog/activation hashes, session reference hashes/generations/expiry/target binding, complete fixture descriptors, and hashes of release/catalog/scan/rollback inputs.
- **AC-5**: Each immutable signed transition-grant version binds trusted issuer/key fingerprint, the newly observed attestation hash, maximum age, expected next transition/state, bootstrap provenance, session/fixture/scan hashes, retry-inclusive per-flow/parent physical/cost/rate/time/trace/abort caps, one-worker limit, nonce/expiry, launcher/distinct approver, rollback, and environment-specific promotion scope. The executor cannot issue/edit it. Signature, freshness, monotonicity, digest, input-hash, or state mismatch exits 4.
- **AC-6**: Document activation additionally requires a fresh post-Runner attestation whose signed fixture result proves an actual zero-target-call Runner-local open/no-follow/regular-file/hash/length/media/doc-type/workflow check. A catalog descriptor or pre-deploy metadata claim is insufficient.
- **AC-7**: Staging cannot authorize production. The verifier enforces Runner-before-Web, a newly observed attestation after every transition, base `2.0.0` before conditional `2.1.0`, named rollback release/catalog, and no-screenshot/no-response-body rules.
- **AC-8**: Any mismatch exits 4 before mutation, secret/fixture resolution, adapter construction, socket, target/provider call, or spend. Success prints only `FINAL_TARGET_ADAPTER_PREFLIGHT_OK <AUTHORIZATION_SHA256> <ATTESTATION_SHA256> <BOOTSTRAP_SHA256>`; caller-selected expected values cannot substitute for signed/grant fields.

## Test Plan
- Unit: mutate every signature/issuer/freshness/monotonic deployment/raw digest/bootstrap/binding/cap/principal/session/fixture/catalog/scan/topology/sequence/rollback/promotion field.
- Integration: exact `python3` verifier command with all action hooks fail-if-called; observer uses injected provider/Runner reader and test signing key, including post-deploy fixture proof.
- Eval/E2E: none; no network.

## Definition of Done
- [ ] Reviewed criterion-tagged RED is frozen.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F16g.md <DIFF_BASE>` and contract conformance exit 0.
- [ ] Exact CLI is reachable and side-effect-free on success/failure.
- [ ] Observer/attestation signature, freshness, transition, and bootstrap provenance tests are frozen and green.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No grant creation, live observation, production signing-key provisioning, Railway mutation, target call, deploy, or promotion.
