# Headshot MVP — execution manifest (tdd-swarm)

Minimum manifest for the secure local MVP vertical slice. **Source of truth: `IMPLEMENTATION_PLAN.md`**
(tasks M1a, M2, M3, M6a, M4). AC-IDs below are stable handles into the plan's acceptance criteria; do not
re-decompose or re-plan. Same-wave tickets have **disjoint file scopes** (verified below).

## Gate commands (this repo — orchestrator re-runs these itself)

```
ruff check .
ruff format --check .
pytest                       # full suite
pytest tests/contract -q     # contract tests (P10 baseline — must stay green)
gitleaks git . --redact      # secret scan (full history)
```
Posture: **production-grade** (`.tdd-swarm/posture.md`). CI mirrors these + a `secret-scan` job; PR checks
`test` + `secret-scan` must be green. Env-isolation + migration + invariant tests are **non-deferrable**.

## Wave 1 — M1a (local runtime & deployment foundation)  [deps: P8 ✓]
- **AC-1** production-style `Dockerfile` builds; `compose.yaml` runs app + PostgreSQL locally.
- **AC-2** config model with explicit environment separation (local/staging/prod).
- **AC-3** `/health` (liveness) + `/ready` (DB connectivity + migration/schema readiness).
- **AC-4** CI runs against an ephemeral PostgreSQL service.
- **AC-5** (O1, invariant) env-isolation: a staging/local config **cannot resolve production target creds**.
- **AC-6** fake TargetAdapter (P9) is the only target locally — no live URL/cred/hosted secret.
- **AC-7** MUST NOT contain domain migrations, per-agent DB roles, append-only perms, or queue migrations.
- **File scope (impl):** `Dockerfile`, `compose.yaml`, `src/agentforge/config.py`, `src/agentforge/health.py`, `.github/workflows/ci.yml` (extend: ephemeral PG service).
- **Test ownership (Test Agent):** `tests/test_config.py`, `tests/test_health.py`, `tests/test_env_isolation.py`.

## Wave 2 — M2 (data model + migrations + per-agent DB roles + indexes)  [deps: M1a]
- **AC-1** entities + state machines (`PRESEARCH.md §5.2`).
- **AC-2** per-agent DB roles: Red Team INSERT-only staging (no read-back); **Recorder role INSERT-only** on the append-only authoritative `AttemptResult` table (**no UPDATE/DELETE grant to any role**, DB-enforced); Judge SELECT-only.
- **AC-3** indexes on severity/category/target-version.
- **AC-4** expand/contract migration (adds a field without data loss; destructive forbidden alongside consumers).
- **AC-5** (S1/S2, invariant) a Red Team write / any UPDATE/DELETE on the append-only table is **DB-rejected**.
- **File scope:** `src/agentforge/storage/models.py`, `migrations/**`, `src/agentforge/storage/roles.sql`.
- **Test ownership:** `tests/test_models.py`, `tests/test_db_roles.py`, `tests/test_migrations.py`.

## Wave 3 — M3 ∥ M6a (disjoint scopes → parallel OK)  [deps: M2]
**M3 — SKIP LOCKED queue**
- **AC-1** `SKIP LOCKED`, two logical queues + priority. **AC-2** at-least-once + lease expiry + heartbeat + reaper + dead-letter + idempotency/dedup on `{campaign_run_id,attempt_id}` + cancellation + poison. **AC-3** no long work in the claim txn. **AC-4** (invariant) no job zero-delivered or double-committed; expired lease reaped.
- **File scope:** `src/agentforge/storage/queue.py`, migration for `jobs`.
- **Test ownership:** `tests/test_queue.py`.

**M6a — provider-neutral observability core**
- **AC-1** OTEL interfaces + local/no-op/console exporter. **AC-2** durable `campaign_id/attempt_id/finding_id` correlation IDs. **AC-3** Postgres authoritative SoR views. **AC-4** (S9, invariant) hash reconciliation → mismatch marks run **degraded**. **AC-5** (S6, invariant) coverage only from hash-verified nonce-deduped verdicts. **AC-6** alert interfaces + deterministic tests. **AC-7** (O7) Langfuse-unavailable fallback → Postgres. **AC-8** synthetic-data only.
- **File scope:** `src/agentforge/observability/tracing.py`, `coverage_view.sql`, `alerts.py`, `reconcile.py`.
- **Test ownership:** `tests/test_observability.py`.
- **Disjointness:** M3 owns `storage/queue.py`; M6a owns `observability/*`. No shared file → **Wave 3 parallel**.

## Wave 4 — M4 (Policy Gateway + Execution Recorder, vs P9 fake)  [deps: M2, P9 ✓, P10 ✓, P5 ✓]
- **AC-1** enforces allowlist + per-target scoped creds + synthetic-data + budget + rate + **hard abort**, in runtime code independent of trigger. **AC-2** emits canonical-hash, append-only `AttemptResult` with per-dispatch `campaign_run_id`. **AC-3** Red Team path holds **no credentials**. **AC-4** (S3, invariant) `UNIQUE(campaign_run_id,attempt_id)` rejects a replay; gated publish idempotent. **AC-5** (invariant) no call without the gate; budget/rate trip abort; off-allowlist denied+audited; typed errors → backoff→queue→abort. **Verified against the P9 fake — no live target.**
- **File scope:** `src/agentforge/policy/gateway.py`, `recorder.py`, `allowlist.py`, `credentials.py`.
- **Test ownership:** `tests/test_gateway.py`, `tests/test_recorder.py`.

## Checkpoint / release procedure (dual-remote)
1. Wave complete → integration branch green (all gates re-run by orchestrator). 2. Push `swarm/*` to GitHub.
3. At a checkpoint/release: owner-approved PR → GitHub `main`. 4. Push the same `main` commit to `gitlab`.
5. **Verify `git rev-parse main` == GitHub `origin/main` == GitLab `gitlab/main`** before declaring done.
6. GitLab auth unavailable → record it as a checkpoint blocker, continue local/GitHub, do not idle.
