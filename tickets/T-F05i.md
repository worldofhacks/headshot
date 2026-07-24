---
id: T-F05i
title: Produce authenticated Runner control state
status: backlog
wave: 9
depends_on: [T-F05a, T-F05h]
branch: ticket/T-F05i-runner-control-state
file_scopes:
  - src/agentforge/contracts/registry.py
  - src/agentforge/contracts/v1/runner_control_state.json
  - contracts/v1/runner_control_state.json
  - src/agentforge/policy/runner_state.py
  - src/agentforge/control_plane/runner_control_state.py
  - scripts/project_runner_control_state.py
test_scopes: [tests/test_runner_control_state.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-binding-readiness.md SB-002, SB-004
  - .tdd-swarm/reports/session-lease-scope-review.md I2
---

## Context
[locked-decision] This deterministic ticket is the sole owner of strict current
`RunnerControlState/v1` and its PostgreSQL projector. It serializes after T-F05h because both
extend the registry and shared source-artifact validator. The projector obtains facts from the
private workload database in one source-authenticated, read-only, repeatable-read transaction;
no supplied counts, abort booleans, combined JSON, DSN, or process-local queue view is authority.
Rotation-specific bounded history is a separate T-F05o consumer so this ticket remains one concern.

## Acceptance Criteria
- **AC-1**: Schema URI `agentforge.runner-control-state`, `schema_version:1`, rejects duplicate, unknown, missing, non-finite, or malformed fields. Accepted artifacts are RFC 8785 canonical UTF-8 JSON with no BOM or trailing newline; their lowercase SHA-256 is computed over the exact detached bytes and is never a self-field. Root/package schema bytes and registry classification match.
- **AC-2**: The projector obtains its engine only from the private Runner composition root and sealed workload-database reference; `--dsn`, URL/host/user/password, supplied engine identity, counts, timestamps, abort state, SQL, and fixture-file state options are forbidden. One transaction sets/verifies `repeatable read` and `read only`, then verifies TLS/service binding, expected database/workload role/environment/Alembic revision and mandatory no-default `AGENTFORGE_RUNNER_CONTROL_DB_IDENTITY_SHA256`.
- **AC-3**: Inside that transaction, fixed parameterized queries over `campaign_run_events` and `jobs` derive distinct active campaign IDs/count plus each campaign's latest abort epoch/state; live lease bindings/count as `(campaign_run_id, job_id, worker_id, lease_token_sha256)` with no raw token; all active release/deployment-generation IDs; database `clock_timestamp()` as whole-second UTC `observed_at`; transaction snapshot identity; and a code-owned query-set SHA-256. Rows also expose stable campaign/job primary identities, generation lineage, created/terminal sequence, and terminal code needed by T-F05o without placing raw payload or token data in the artifact. Any missing lineage, mixed release/generation, writable/isolation drift, schema/query drift, or identity mismatch rolls back and emits nothing; an empty active set is valid.
- **AC-4**: The canonical snapshot body is signed after the read-only transaction by the workload-bound `RunnerControlProjectorAttestor` over `UTF8("agentforge.runner-control-state/v1") || 0x00 || RFC8785(body)`. Verification uses only `/run/agentforge/trust/runner-control-projector.ed25519.pub`; its SHA-256 must equal mandatory no-default `AGENTFORGE_RUNNER_CONTROL_PROJECTOR_TRUST_ROOT_SHA256` and the reviewed deployment manifest. Signer, key, DB identity, release, generation, or time cannot be supplied by CLI.
- **AC-5**: `validate_runner_control_state` re-verifies canonical bytes, detached digest, attestation, trust root, database identity, read-only/repeatable-read receipt, fixed query-set hash, release, manifest, environment, generation, and copied-field equality. Stable failures are `runner-control-schema-invalid`, `runner-control-noncanonical`, `runner-control-source-untrusted`, `runner-control-transaction-invalid`, `runner-control-binding-mismatch`, and `runner-control-authority-unavailable`; none includes SQL, DSN, row content, or key material.
- **AC-6**: The sole command is `python scripts/project_runner_control_state.py --deployment-manifest <CURRENT_DEPLOYMENT_MANIFEST> --output-root docs/evidence/runner-state`. It creates without replacement `docs/evidence/runner-state/<release_sha>/<generation>/runner-control-state.v1.<state_sha256>.json` plus the exact detached digest. Only the typed producer API accepts injected engine/attestor/clock authorities for tests; the public CLI rejects arbitrary output roots and source/trust overrides.
- **AC-7**: Exits are `0` success, `2` CLI misuse, and `4` unavailable/untrusted/invalid authority with rollback and no partial output. Deterministic tests use a fake connection and synthetic attestor, assert exact transaction/query order and stable row identities/lineage, patch socket/real-engine/provider/target hooks to fail, and prove absent database or attestor authority blocks; no test opens PostgreSQL or any network connection.

## Test Plan
- Unit (deterministic): strict schema/canonical bytes, attestation/domain/trust, database identity, fixed query shape, stable campaign/job identities and lineage, and redacted failures.
- Integration (deterministic): fake connection proves one read-only repeatable-read snapshot, rollback/create-only paths, exact CLI exits, and absence of caller state/DSN seams.
- Eval/E2E: none; actual private-database observation requires separate operational authority.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05i.md <DIFF_BASE>` exits 0.
- [ ] The authenticated current-state projector and root/package contract pass isolated verification.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No bounded rotation history/evidence, controller projection, combined/context projection, Runner
delivery/dispatch, live database, Railway action, raw session value, provider/target call, network, or spend.
