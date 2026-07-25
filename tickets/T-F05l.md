---
id: T-F05l
title: Acquire fresh signed deployment-controller observations
status: backlog
wave: 12
depends_on: [T-F05h, T-F05j]
branch: ticket/T-F05l-controller-observation-source
file_scopes:
  - src/agentforge/deployment/controller_observation_source.py
test_scopes: [tests/test_deployment_controller_observation_source.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-binding-readiness.md SB-004
  - .tdd-swarm/reports/session-lease-scope-review.md I1
---

## Context
[locked-decision] This half-day ticket is the sole production
`DeploymentControllerObservationSource`. It acquires one new signed T-F05h envelope per call from
one fixed local deployment-controller IPC endpoint and returns a typed single-use receipt. It never
projects/approves state, performs deployment, reads a caller path, or caches a successful envelope.
Actual controller IPC remains an independently authorized operation and is `BLOCKED` when absent.

## Acceptance Criteria
- **AC-1**: The only production transport is Linux `AF_UNIX` `SOCK_SEQPACKET` at fixed `/run/agentforge/controller/deployment-observation-v1.sock`. No setting, constructor, job/payload/context, CLI, cwd, DNS, URL, host, port, fallback file, stdin, or retry chooses another source. Every ancestor and final endpoint is checked without following symlinks; directories are root-owned/not group-or-world-writable, final mode is a Unix socket, and pre/post-connect `(device,inode,uid,gid,mode)` must match.
- **AC-2**: After connect, `SO_PEERCRED` must return a positive peer PID and peer UID/GID exactly equal to the checked socket UID/GID and the no-follow owner UID/GID of `/run/agentforge/trust/runner-deployment-controller.ed25519.pub`; the trust-root file is independently hashed and bound by T-F05h. Pre/post-connect endpoint identity and the connected peer credential tuple are retained for that one request. Peer credentials alone never replace Ed25519 verification. Endpoint replacement, peer mismatch, unsupported platform/socket type, or missing trust authority fails before sending a request.
- **AC-3**: `acquire(context_binding, now)` generates a fresh 32-byte CSPRNG nonce and sends one bounded RFC 8785 canonical `DeploymentControllerObservationRequest/v1` frame binding request nonce, environment, release SHA, deployment-manifest hash, expected generation, controller/trust-root ID, and a code-owned five-second response deadline. Arguments cannot add raw state/counts/phase/paths. The response is exactly one frame no larger than 65536 bytes; truncation, extra frame/data, invalid UTF-8/JSON/canonical form, duplicate/unknown field, or timeout fails without retry.
- **AC-4**: The response must be a strict signed T-F05h `DeploymentControllerObservation/v1` envelope whose signed request nonce exactly equals the challenge, whose environment/release/manifest/generation/trust binding equals the request, and whose whole-second `observed_at` age is `0..5` seconds at receipt. A reused observation nonce, repeated response for another request nonce, non-increasing controller sequence within the source lifetime, stale/future response, or signature failure is rejected. Only nonce/sequence digests needed for replay defense may be retained; envelope/state success is never cached or reused.
- **AC-5**: Success returns non-serializable `AcquiredControllerObservation(envelope_bytes, request_nonce, received_at, peer_identity)` exactly once; its bytes pass unchanged to T-F05h. Stable failures are `controller-observation-source-unavailable`, `controller-observation-endpoint-unsafe`, `controller-observation-peer-untrusted`, `controller-observation-protocol-invalid`, `controller-observation-replayed`, and `controller-observation-stale`; none includes endpoint metadata, envelope bytes, nonce, key, or peer values.
- **AC-6**: Deterministic tests inject nonce/clock/transport/peer-stat abstractions and synthetic signed envelopes, prove two calls issue different challenges and obtain two responses, and cover endpoint/peer/size/frame/timeout/canonical/signature/binding/freshness/replay/sequence failures. Real `AF_INET`, DNS, HTTP, subprocess, Railway, controller, database, provider, target, and spend hooks are patched to fail; no test opens the production socket.

## Test Plan
- Unit (deterministic): fixed endpoint/no override, canonical request, peer/trust checks, bounded frame, challenge/freshness/replay/sequence checks, typed receipt, and redacted failures.
- Integration (deterministic): fake seqpacket transport performs two independent acquisitions and proves absent/unsafe/untrusted authority is zero-output/zero-fallback.
- Eval/E2E: none; real controller IPC is separately authorized and unavailable authority is an honest blocker.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05l.md <DIFF_BASE>` exits 0.
- [ ] The fixed authenticated acquisition channel is frozen before T-F05m integration.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No deployment-state projection/approval, context loading, PostgreSQL access, activation/deployment,
Runner dispatch, Railway action, raw session value, provider/target call, external network, or spend.
