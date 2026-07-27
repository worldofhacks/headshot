# Railway deployment and rollback

**Reconciled:** 2026-07-26

**Current deployed-state snapshot:** [`../CURRENT_STATE.md`](../CURRENT_STATE.md)

This runbook governs AgentForge Web, Runner, Scheduler, and PostgreSQL on Railway. It does not
authorize a deployment, variable change, credential rotation, or live campaign.

## Topology

| Service | Public ingress | Command | Owns |
|---|---:|---|---|
| Web | yes | `python -m agentforge.web` | console, API, commands/reads, health/readiness, Alembic pre-deploy |
| Runner | no | `python -m agentforge.runner` | queue claims, hosted agents, target dispatch, evidence, telemetry |
| Scheduler | no | `python -m agentforge.scheduler` | target-version observation, authorization-blocked replay plans |
| PostgreSQL | no | managed | control plane, queue, evidence, audit, projections |

Clerk, OpenRouter/upstream models, Langfuse, and the Clinical Co-Pilot target are external. Provider,
target, Langfuse, and database credentials never enter the browser.

Staging and production use separate Railway environments, databases, service variables, target
authorization, credential generations, Clerk applications/Organizations/origins, and Langfuse
projects/keys.

## Current state

Staging:

- Web, Runner, and Scheduler are successful and share generation-policy digest `b83acb23…`;
- their packaged `hosted_policy.py` SHA-256 is identical;
- PostgreSQL must be verified by revision and schema shape: canonical `0026` adds campaign
  outcomes, `0027` adds immutable prompt snapshots, and `0028` adds bounded provider response
  evidence columns on `provider_call_events`;
- `/health` and `/ready` return 200; and
- unauthenticated `/api/v1/principal` returns 401.

Production:

- Web/Runner and Scheduler expose different policy hashes;
- production is therefore release-skewed; and
- no campaign may be launched until one reviewed release is intentionally deployed and accepted.

Exact IDs and hashes are in `docs/CURRENT_STATE.md`. Re-verify them immediately before an operation.

## Build and migration ownership

All services build `Dockerfile`. The runtime image contains:

- the AgentForge wheel;
- the built React console;
- the complete Alembic history;
- reviewed eval/workload/security-tool assets; and
- the Langfuse campaign verifier.

Only `railway/web.json` declares `alembic upgrade head`. Runner and Scheduler call an exact-head
readiness check before consuming/enqueuing work. The canonical repository chain is `0025` reviewed
workload provenance → `0026` campaign outcome breakdown → `0027` immutable prompt snapshots →
`0028` physical provider response evidence. Never hard-code a revision into automation that should
derive the packaged or deployed head.

One release must be tested as an immutable artifact. Do not independently rebuild services from
different source states.

## Service-scoped variables

### Web

- `AGENTFORGE_ENVIRONMENT`
- `DATABASE_URL`
- `PORT`
- `AGENTFORGE_CONSOLE_DIR=/app/console`
- `AGENTFORGE_MAX_REQUEST_BYTES`
- `VITE_CLERK_PUBLISHABLE_KEY` at build time
- `CLERK_PUBLISHABLE_KEY`
- `CLERK_JWT_KEY`
- `CLERK_AUTHORIZED_PARTIES`
- `CLERK_REQUIRED_ORG_ID`
- `CLERK_FRONTEND_API_ORIGIN`
- staging isolation guards for production Organization/origin
- `AGENTFORGE_LIVE_TARGET_CATALOG_JSON` for trusted read/command validation

Web must not contain OpenRouter, target-session, or Langfuse secret values.

### Runner

- `AGENTFORGE_ENVIRONMENT`
- `DATABASE_URL`
- `AGENTFORGE_RUNNER_WORKER_ID`
- `AGENTFORGE_LIVE_TARGET_CATALOG_JSON`
- `AGENTFORGE_WORKLOAD_ID`
- `AGENTFORGE_WORKLOAD_SHA256`
- `AGENTFORGE_CREDENTIAL_BINDINGS_JSON`
- `AGENTFORGE_SESSION_LEASES_JSON`
- the environment variables named by the sealed credential bindings
- `AGENTFORGE_JUDGE_CALIBRATION_PATH` when an exact human-enabled calibration is mounted
- `HEADSHOT_PER_CALL_USD`
- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_BASE_URL`
- `LANGFUSE_TRACING_ENVIRONMENT`

The hosted configuration set itself is staged through the authenticated control plane and stored
append-only in PostgreSQL. Ambient model-name variables are not production authority.

### Scheduler

- `AGENTFORGE_ENVIRONMENT`
- `DATABASE_URL`
- `AGENTFORGE_SCHEDULER_POLL_SECONDS`

Scheduler does not need target or provider credentials.

## Pre-deploy gate

Before any release:

1. identify the exact reviewed commit;
2. verify `origin/main == gitlab/main` for releases;
3. require GitHub Actions and GitLab CI green on the exact commit;
4. build/test the package, console, Docker image, migration history, and secret scan;
5. verify one Alembic head;
6. inspect migration upgrade/downgrade/quiescence requirements;
7. stop new launch and scheduling commands;
8. prove zero active target work-unit leases;
9. prove zero running hosted agent executions;
10. prove no dispatchable queued campaign authorization;
11. preserve database/PITR and rollback identifiers; and
12. obtain explicit deployment authority.

Deploying or restarting Runner invalidates heartbeat-based console readiness until a fresh heartbeat
is recorded. Operators must not click Launch during the deployment window.

## Deployment sequence

Use this order for schema-affecting releases:

1. **Runner artifact first, inert.** Deploy the new Runner while the old database head is active. It
   must refuse to claim work at the exact-head gate.
2. **Web and migration.** Deploy Web and let its pre-deploy command apply every migration to the new
   sole head.
3. **Web checks.** Verify `/health`, `/ready`, static/sign-in shell, and protected missing-token 401.
4. **Runner activation.** Verify exact head, trusted catalog/workload, provider/config readiness,
   Langfuse auth gate, and fresh heartbeat.
5. **Scheduler.** Deploy after the schema and Runner are healthy; verify heartbeat/planning only.
6. **Artifact parity.** Read the generation-policy digest and packaged `hosted_policy.py` hash from
   every service. All must match.
7. **Target-free acceptance.** Run the four-role OpenRouter/Langfuse acceptance with
   `target_call_limit = 0`.
8. **Langfuse query-back.** Verify remote observations; SDK flush is insufficient.
9. **Headshot projection.** Read the campaign-scoped `provider-calls` endpoint and confirm each
   durable OpenRouter invocation appears in Run Operations, Traces, and Costs with matching
   sequence, request ID, tokens, measured cost, status, and Langfuse locator. Parent-agent
   verification must not be described as independent per-child query-back proof. Confirm the
   aggregate payload carries no prompt or response bytes, and that
   `provider-calls/{invocation_id}/evidence` returns 401/403 without `org:evidence:read` and serves
   the exact prompt and recorded response with it. Calls recorded before `0028` correctly report no
   response rather than a reconstructed one.
10. **Fresh live authority.** Only now create a new campaign request and obtain distinct-person
   approval for the exact deployed policy/configuration/workload/lease.

For migrations whose constraints make old/new Runner overlap unsafe, scale the old Runner to zero
after quiescence instead of relying on `overlapSeconds`.

For the `0026` → `0027` release, keep the candidate Runner inert, quiesce and remove the old Runner
before Web applies the migration, then verify both the campaign-summary outcome columns and the
append-only `agent_prompt_snapshots` table, lineage trigger, and role grants before activating the
candidate Runner. `0027` is a normal forward migration from the canonical campaign-outcome
revision `0026`; do not rewrite or stamp migration history. Web has `SELECT` only; Runner has
`SELECT`/`INSERT`; neither service role may update/delete.

`0028` is a normal forward migration on top of `0027` and needs no Runner quiescence of its own. It
adds only a nullable `TEXT`, a defaulted `BOOLEAN`, a nullable digest column, and three CHECK
constraints to `provider_call_events`; on PostgreSQL 11+ these are catalog-only changes, so the
physical hot-path table is not rewritten and no long `ACCESS EXCLUSIVE` lock is taken. It grants no
new privileges — whether Web may read the recorded response is settled at the API boundary by
`org:evidence:read`. Its `downgrade()` destroys observed provider evidence that cannot be re-derived
from any other row, so treat it as forward-only in staging and production.

## Hosted configuration and policy parity

Web mints an authorization containing the generation-policy digest. Runner resolves that digest
through its closed package registry. If Web and Runner differ, Runner fails before provider I/O with
hosted runtime authority invalid.

Acceptance requires:

- same package/policy hash on Web, Runner, and Scheduler;
- staged configuration release compatible with that package;
- exact four-role model/upstream/prompt bindings;
- role/global call, token, cost, retry, rate, concurrency, and timeout capacity;
- credential references resolvable only by Runner; and
- a fresh authorization minted after parity is established.

Never edit only an expiry or digest to make a stale authorization pass.

## Health and readiness

`/health` proves only the Web process is alive.

`/ready` additionally proves the Web dependency/configuration boundary, including database and exact
schema. It does not prove:

- Runner heartbeat;
- provider credential/model route;
- Langfuse remote delivery;
- target credential/session lease;
- campaign authorization;
- Judge calibration;
- full-suite reliability; or
- real-user Clerk Organization/MFA/two-person behavior.

Use the authenticated read models and Runner/Scheduler heartbeats for component readiness.

## Acceptance after deployment

### Infrastructure smoke

- Web `/health` 200.
- Web `/ready` 200.
- static/sign-in shell 200.
- protected API without a token 401.
- Runner/Scheduler no public domains.
- exact schema head.
- same policy/file hashes across services.
- fresh Runner/Scheduler heartbeat.

### Human identity smoke

With two real invited Headshot members:

- MFA/session tasks complete;
- exact Organization enforced;
- wrong Organization denied;
- custom permissions enforced;
- Operator cannot authorize their own launch;
- Approver can authorize the immutable request;
- tokens do not enter URLs, logs, traces, or browser persistence.

### Target-free four-role acceptance

- one real call per hosted role;
- exact requested/returned model/upstream;
- physical provider lineage and measured usage/cost;
- Red Team output quarantined from any target;
- Langfuse exact query-back; and
- all rows terminal.

### Governed live acceptance

- fresh authorization after deployment;
- synthetic-only workload/canaries;
- target session lease covers the entire run timeout;
- exact target and hosted caps;
- attempt created before Red Team provider I/O;
- target request/results/verdicts durable;
- case errors remain explicit;
- no observed target work repeated;
- complete/failed/aborted Langfuse partial/full trace verified; and
- no publication/remediation without approval.

## Current live-suite caution

The current Runner fails an entire batch on an exhausted schema-invalid Judge response and cannot
resume. The current staged configuration authorizes zero retries. Until `PLAN.md` P1–P4 are deployed
and accepted, a fresh live launch can repeat completed target work and should not be treated as a safe
recovery mechanism.

## Rollback

Rollback is constrained by database compatibility:

1. stop launches/scheduling and quiesce work;
2. identify the last accepted application artifact and its supported schema range;
3. prefer rolling application code forward over destructive schema downgrade;
4. never downgrade while newer immutable rows violate the older schema's assumptions;
5. restore from PITR only with explicit authority and an understood data-loss window;
6. deploy one compatible artifact to all services;
7. verify policy/file parity, schema, health, and heartbeats;
8. rerun target-free acceptance; and
9. mint new live authorization—never reuse pre-rollback approval.

Do not use `git reset --hard`, force pushes, broad variable deletion, or database destructive commands
as deployment recovery.

## Evidence to retain

For every deployment:

- exact commit and both remote refs;
- GitHub and GitLab CI URLs/results;
- Docker image digest;
- Railway deployment IDs;
- before/after Alembic head;
- quiescence evidence;
- service policy/file hashes;
- health/readiness/401 results;
- heartbeat timestamps;
- target-free acceptance ID;
- Langfuse remote verification counts;
- rollback identifier; and
- the human authorization that permitted the external change.

Never retain raw credentials, session values, real PHI, or unbounded hostile payloads.
