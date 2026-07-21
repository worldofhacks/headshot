# M3 Durable Queue Handoff

## Scope delivered

M3 adds one Postgres `jobs` table and a storage-only API for exactly two logical queues:
`agent_work` and `regression_run`. It implements priority and scheduled eligibility,
`SELECT ... FOR UPDATE SKIP LOCKED` claims, bounded leases and heartbeats, deterministic
expired-lease reaping, retries, dead-letter containment, queue/run/attempt idempotency,
queued-work cancellation, depth counts, and deterministic backpressure.

The delivery contract is **at least once**, never exactly once. A claim transaction commits
before processing begins. A worker crash can therefore cause the payload to be delivered
again after its lease expires. Queue completion is an idempotent terminal commit for the
matching lease token; consumers must make target/model actions idempotent independently.

This slice does not wire the queue into campaign, policy, target, Judge, regression, cron,
observability, cost-governor, or UI code.

## Storage contract

- Migration `0004` follows `0003` and owns only `jobs`, `job_queue`, `job_status`, and the
  queue indexes. Downgrade removes only those objects.
- Deduplication is enforced by `UNIQUE(queue, campaign_run_id, attempt_id)`. It does not
  alter or weaken `attempt_result`'s independent `UNIQUE(campaign_run_id, attempt_id)`.
- Payload support is trusted process configuration. The default schemas are version 1 of
  `agent_work` and version 1 of `regression_run`. Public enqueue rejects unsupported work;
  a version-skew row already in the database is dead-lettered without blocking later work.
  Poison scans commit every 32 rows, then continue the same logical claim in a fresh short
  transaction so poison backlogs neither accumulate unbounded locks nor return false-empty.
- All scheduling and lease comparisons use Postgres time and timezone-aware timestamps.
- The aligned `Job` metadata model prevents a future Alembic autogenerate from proposing
  removal of migration `0004` objects.
- Existing Red Team, Recorder, and Judge roles receive no privilege on `jobs`; their M2
  isolation and append-only grants are unchanged.
- Failure diagnostics retain only a bounded code, an allowlisted static omission marker,
  time, and worker ID. Caller-provided messages, exception dumps, and credential-shaped
  values are never persisted. Job representations also omit payloads and lease tokens.

## Consumer integration

F1 Orchestrator should instantiate `PostgresJobQueue` from a trusted application-owned
database engine, enqueue versioned `agent_work`, claim briefly, process after claim returns,
heartbeat long work, then call `complete` or `fail`. Its durable business write must remain
idempotent. For execution evidence, retain the existing `attempt_result` uniqueness guard;
where possible, commit the authoritative result and queue completion in one database
transaction in a future integration API rather than assuming exactly-once target execution.

F3 approval workflows may use versioned `agent_work` payloads, but critical publication and
remediation still require the separate human gate. Queue completion is not approval.

F4 regression consumers should use `regression_run`; each actual regression dispatch still
needs a fresh `campaign_run_id`. Verdicts and live results must never be reused.

Campaign hard abort should stop producers, call `cancel_campaign` for queued work, and signal
active workers through the campaign's trusted abort mechanism. M3 intentionally does not
cancel an already leased external action. Cost-governor integration should call `depth` or
`backpressure`; the queue reports state but makes no model, target, policy, or budget decision.

Before adding a runtime queue principal, define a dedicated least-privilege role in a new
forward migration. Do not grant queue mutation to the Red Team, Recorder, or Judge roles and
do not edit migration `0001` or append unconditional `jobs` grants to `roles.sql` (fresh
installs execute that file before migration `0004` creates the table).

Follow D16 during payload changes: deploy readers that support the new version first, drain
or migrate old queued work, then remove old-version support. Unknown rows fail closed into
dead letter; they are never interpreted optimistically.

## Deployment prerequisite outside this lane

The current production wheel/container copies the Python package but does not ship
`alembic.ini` or the repository `migrations/` tree. Therefore the image alone cannot apply
revision `0004`. Before any F1/F3/F4 consumer uses this queue, the authorized deployment
composition must run `alembic upgrade 0004` (normally `alembic upgrade head`) from a trusted
repository migration artifact, or a later packaging change must ship migrations. Docker,
CI, and deployment configuration were explicitly outside this task and remain unchanged.

## Verification

The focused suite uses real ephemeral Postgres connections for locks and concurrency:

```bash
pytest -q tests/test_queue.py
pytest -q tests/test_migrations.py tests/test_db_roles.py tests/test_models.py tests/test_queue.py
```

It covers concurrent claim and enqueue races, locked-row skipping, lease ownership and
expiry, stale-worker completion rejection, retries and dead letters, poison version skew,
scoped cancellation, exact depth/threshold behavior, storage-role isolation, and the
`0003 -> 0004 -> 0003 -> 0004` migration cycle.
