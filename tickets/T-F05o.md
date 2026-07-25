---
id: T-F05o
title: Project bounded terminal control history for Runner rotation
status: backlog
wave: 14
depends_on: [T-F05h, T-F05i, T-F05j]
branch: ticket/T-F05o-runner-rotation-control-history
file_scopes:
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/runner_rotation_control_state.json
  - contracts/v1/runner_rotation_control_state.json
  - src/agentforge/control_plane/runner_rotation_control.py
  - scripts/project_runner_rotation_control.py
test_scopes: [tests/test_runner_rotation_control_history.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-binding-readiness.md SB-002, SB-004
  - .tdd-swarm/reports/session-lease-scope-review.md I2
---

## Context
[locked-decision] This half-day ticket is the rotation-specific T-F05i extension and sole owner of
strict `RunnerRotationControlState/v1`. It freezes one unambiguous predecessor campaign/job set
after durable admissions closure, then proves that identical complete set terminal in a later
authenticated read-only repeatable-read snapshot. It does not observe/activate deployments,
dispatch, change queue state, or compose final rotation evidence.

## Acceptance Criteria
- **AC-1**: Schema URI `agentforge.runner-rotation-control-state`, `schema_version:1`, phase `start|terminal`, rejects duplicate/unknown/missing/non-finite/malformed fields. Canonical UTF-8 JSON has no BOM/trailing newline; detached SHA-256 is over exact bytes. Root/package schemas and registry match. Both phases bind environment/release/deployment manifest, rotation ID, predecessor generation IDs, T-F05h start deployment-state hash, workload DB identity, query-set hash, read-only repeatable-read receipt, snapshot identity/time, and projector attestation.
- **AC-2**: Start projection accepts only a freshly validated signed T-F05h `draining` deployment state whose Web/Scheduler admissions are closed, whose active generation set is exactly the distinct predecessor set, and whose rotation ID is non-null. The private engine/trust/attestor come only through T-F05i's composition boundary. One read-only repeatable-read transaction verifies durable campaign-launch admission closure and derives code-owned campaign-event/job-row high-watermarks.
- **AC-3**: In that same start transaction, fixed queries enumerate every campaign and every job with matching release and predecessor generation lineage through the high-watermarks. The canonical sorted set contains campaign ID, campaign creation/event sequence, latest abort epoch/state, job ID/row sequence, terminal status/code, and any live binding only as `(worker_id, lease_token_sha256)`; no raw token/payload/session is emitted. Missing/duplicate/mixed lineage, an unclassified row, or a predecessor row outside the enumerated set fails.
- **AC-4**: Terminal projection requires the exact canonical start artifact and re-verifies its hash/attestation. A new read-only repeatable-read transaction queries the same exact primary identities, proves no new campaign/job for any predecessor generation exists above the frozen high-watermarks, and emits the identical sorted set with every campaign durably completed or hard-aborted, every job `completed|cancelled|dead_letter`, zero live lease, and terminal machine code/sequence. A hard-abort without all owned jobs terminal, missing row, changed membership/lineage, new predecessor work, or nonterminal job fails.
- **AC-5**: The terminal artifact includes `rotation_start_control_state_sha256`, start/terminal snapshot identities, and monotonic database event/job sequence bounds; start time must not exceed terminal time. Both artifacts are signed by T-F05i's workload-bound projector attestor using domain `agentforge.runner-rotation-control-state/v1` and pinned trust/DB identity. Their validator replays all canonical/attestation/binding/set/phase invariants.
- **AC-6**: Exact commands are `python scripts/project_runner_rotation_control.py --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --rotation-start-deployment-state <DRAINING_RUNNER_DEPLOYMENT_STATE> --phase start --output-root docs/evidence/runner-rotations` and the same command with `--phase terminal --rotation-start-control-state <ROTATION_START_CONTROL_STATE>`. They create content-addressed artifacts/digests without replacement. Caller set/cutoff/row/status/abort/trust/DSN/SQL/clock/output override, combined state, and stdin flags are forbidden; exits are `0`, `2`, `4`.
- **AC-7**: Deterministic tests use fake transactions/attestor/clock, assert exact query and start→terminal membership behavior, and attack omitted/new/reclassified rows, live leases, incomplete hard abort, high-watermark/time/snapshot/trust substitution, raw token leakage, and partial output. Real database/socket/controller/provider/target/Railway hooks are patched to fail.

## Test Plan
- Unit (deterministic): canonical schema/attestation, start/terminal phase and exact-set invariants, high-watermarks, lineage, redaction, stable failures.
- Integration (deterministic): two fake read-only repeatable-read snapshots prove a frozen complete set becomes entirely terminal with no new predecessor work.
- Eval/E2E: none; no live database/controller/deployment/Runner/provider/target activity.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05o.md <DIFF_BASE>` exits 0.
- [ ] The exact bounded predecessor campaign/job history is independently authenticated and complete.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No current-state replacement, deployment observation/acquisition, activation event/final evidence,
queue mutation, Runner dispatch, Railway action, raw session value, network, or spend.
