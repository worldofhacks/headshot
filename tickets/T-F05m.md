---
id: T-F05m
title: Refresh authenticated Runner state on every runtime check
status: backlog
wave: 13
depends_on: [T-F05e, T-F05h, T-F05i, T-F05j, T-F05k, T-F05l]
branch: ticket/T-F05m-authenticated-runner-state-provider
file_scopes:
  - src/agentforge/policy/runner_state_provider.py
test_scopes: [tests/test_authenticated_runner_state_provider.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-lease-scope-review.md I1, I3
---

## Context
[locked-decision] This half-day ticket owns only the closed runtime
`AuthenticatedRunnerStateProvider`. Configuration/reference/persistence, context filesystem
lifecycle, controller-observation acquisition, deployment/control projection, and validation are
landed dependencies. The provider composes them once per call and retains no successful state.

## Acceptance Criteria
- **AC-1**: `AuthenticatedRunnerStateProvider.observe(context, now, current_claim)` has exactly one production implementation selected by T-F05j's fixed provider value. `context` is T-F05k's pinned non-serializable handle and `current_claim` is T-F05e's trusted non-serializable queue binding or `None`; job/payload/CLI/JSON cannot construct either or supply source artifacts, paths, counts, booleans, trust, clocks, or expected state.
- **AC-2**: On every call, before any other source hook, the provider calls a new T-F05l `acquire(context.state_authority_binding, now)`. It passes that exact single-use receipt/envelope and expected request nonce directly to T-F05h's typed producer, then invokes a new T-F05i authenticated read-only repeatable-read projection. It never invokes T-F05h's offline path CLI or reads a caller/job-selected observation file.
- **AC-3**: After both new canonical artifacts exist in memory, the provider calls T-F05e's sole fresh-state validator with the pinned context, injected clock, and exact claim. It returns the two typed immutable artifacts only after their hashes/attestations/trust/release/manifest/generation/database identity/freshness and self-only claim/abort rules pass. It has no combined-state, serialized-claim, alternate parser, or process-local fallback.
- **AC-4**: Every invocation performs a new source challenge and new database transaction. No successful observation, artifact, validator result, source receipt, or partial pair is cached, retried, reused, written to a job, or accepted after error. Nonce replay/stale/future source, partial refresh, T-F05h/T-F05i disagreement, another campaign/lease, current hard abort, trust drift, or authority absence is terminal for that invocation; prior success cannot satisfy it.
- **AC-5**: Call order is exactly acquire controller observation → project/verify deployment state → project/verify control state → validate pair. Stable outward failure is `lease-context-refresh-unavailable` with a non-secret structured cause from the landed source/producer validators; no envelope, nonce, endpoint, DB, SQL, path, claim/token hash, or context content appears in return, exception, log, telemetry, or artifact.
- **AC-6**: Deterministic tests inject fake T-F05l/T-F05h/T-F05i authorities and clocks, make two calls with distinct signed observations/snapshots, and prove all partial/order/cache/fallback/current-claim negatives. Real filesystem, `AF_INET`, controller socket, PostgreSQL, resolver, adapter/client, Railway, provider/target, and spend hooks are patched to fail.

## Test Plan
- Unit (deterministic): protocol/type boundaries, exact composition order, claim provenance, failure mapping/redaction, and no combined/caller seams.
- Integration (deterministic): two non-cached refreshes through fake source/producers; every missing/stale/replayed/substituted/partial authority stops before downstream hooks.
- Eval/E2E: none; no live context root, controller IPC, database, Railway, provider, target, or secret.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05m.md <DIFF_BASE>` exits 0.
- [ ] The production provider acquires/projects/validates fresh independent state on every call.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No configuration/reference/migration/queue, file install/load/pin, source transport, source schemas,
Runner dispatch, activation/rotation, Railway action, credential resolution, network, or spend.
