---
id: T-F05j
title: Persist SMART lease-context configuration and job binding
status: backlog
wave: 11
depends_on: [T-F05e, T-F05h, T-F05i]
branch: ticket/T-F05j-smart-session-reference
file_scopes:
  - src/agentforge/config.py
  - src/agentforge/policy/smart_session_reference.py
  - src/agentforge/storage/models.py
  - src/agentforge/storage/queue.py
  - migrations/versions/0016_smart_session_lease_context_ref.py
  - .env.example
test_scopes: [tests/test_smart_session_lease_reference_persistence.py]
model_hint: capable
attempts: 0
traces_to:
  - Week_3_AgentForge.pdf live hard gate, scoped credentials, and abort
  - docs/requirements/REQUIREMENTS_MATRIX.csv PRD-03, PRD-07, PRD-09, PRD-34
  - .tdd-swarm/reports/session-lease-scope-review.md I3, I4
---

## Context
[locked-decision] This half-day ticket owns only Runner configuration, strict immutable context
reference parsing, and durable job/queue persistence. T-F05k owns filesystem installation/loading,
T-F05l owns deployment-controller observation acquisition, and T-F05m owns the runtime refresh
provider. It does not open a context file, observe source state, dispatch a job, or resolve a secret.

## Acceptance Criteria
- **AC-1**: SMART-capable Runner startup requires, with no defaults, `AGENTFORGE_SMART_SESSION_MAX_LIFETIME_SECONDS`, `AGENTFORGE_SMART_SESSION_LEASE_CONTEXT_REF`, `AGENTFORGE_SMART_SESSION_FRESH_STATE_PROVIDER=authenticated-runner-state-v1`, `AGENTFORGE_RUNNER_DEPLOYMENT_TRUST_ROOT_SHA256`, `AGENTFORGE_RUNNER_CONTROL_PROJECTOR_TRUST_ROOT_SHA256`, and `AGENTFORGE_RUNNER_CONTROL_DB_IDENTITY_SHA256`. Maximum lifetime uses T-F05e's exact `[60,3600]` ASCII-integer contract; hash settings are exactly 64 lowercase hexadecimal ASCII characters. Unknown provider values, blank/missing settings, dotenv inheritance outside local mode, or caller/CLI overrides fail before claim, file access, source acquisition, resolver, client, or network.
- **AC-2**: The sole context-reference language is exactly `leasecontext://staging/<release_sha>/<generation>/<context_sha256>`: release is 40 lowercase hexadecimal ASCII, generation follows T-F05e's 1..64 ASCII grammar, and context hash is 64 lowercase hexadecimal ASCII. Query, fragment, userinfo, port, percent encoding, dot/empty/extra segments, slash/backslash/control characters, case aliases, prefixes/suffixes, and terminal CR/LF fail. The parser returns typed components only; no setting/job supplies a filesystem root/path.
- **AC-3**: Migration/store/queue add immutable nullable `jobs.smart_session_lease_context_ref VARCHAR(256)`. It is mandatory for an authorization-classified SMART live job, absent for non-session jobs, included in `JobRecord`, persisted only from the authenticated campaign grant/context during enqueue, included in enqueue idempotency, and protected against update. Payload fields, enqueue callers, claim workers, or retries cannot supply or replace it independently; job/store reference, mandatory setting, context release/generation/hash, and authorization must all equal.
- **AC-4**: The existing lease-owned `PostgresJobQueue.fail` remains the only terminal rejection boundary. A nonretryable call with machine code `smart_session_lease_rejected` atomically yields `FailureOutcome.DEAD_LETTERED`, durable `dead_letter` status, `last_failure_code='smart_session_lease_rejected'`, exact public/persisted `last_failure_message='worker-supplied failure detail omitted'`, and cleared lease fields. No new allowlist or bypass admits a caller/internal detail string. Tests prove any nonempty internal failure detail is never the persisted/public message and raw detail appears in no record, repr, log, telemetry, or exception.
- **AC-5**: Configuration/reference/persistence failures are stable `lease-context-config-missing`, `lease-context-ref-invalid`, and `lease-context-job-binding-mismatch`, never echoing setting/job/payload content. Non-session and synthetic jobs remain compatible and never require the SMART setting or job field.
- **AC-6**: Deterministic tests cover every setting/reference variant, migration upgrade/downgrade shape, enqueue/idempotency/update/claim/retry behavior, exact sanitized terminal code/status/message, and zero file/source/resolver/client hooks. Existing queue failure sanitation is preserved rather than replaced.

## Test Plan
- Unit (deterministic): setting/reference grammar, typed components, stable failures, and non-session compatibility.
- Integration (deterministic): migration/store/enqueue/claim/idempotency/immutability plus exact nonretryable sanitized queue failure behavior.
- Eval/E2E: none; no filesystem, source authority, Runner dispatch, database server, Railway, provider, target, or secret.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged clean RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F05j.md <DIFF_BASE>` exits 0.
- [ ] Configuration/reference/job persistence and the sanitized queue rejection interface are frozen.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No context installation/loading/pinning, source acquisition, fresh-state provider, Runner dispatch,
credential resolution/value, live database/controller, Railway action, deployment, network, or spend.
