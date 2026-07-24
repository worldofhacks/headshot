# WP-06 — Make readiness and launch availability authoritative

**Branch:** `rtg/wp06-platform-readiness`

**Model:** capable

**Depends on:** WP-02, WP-08

**Implements toward (live validation pending):** part of RT-14

Read Web readiness, API launch availability, component heartbeat storage, target catalog,
corpus loader, queue schema, deployment requirements, and RT-14.

**Implementation writes only**

- `src/agentforge/readiness.py`
- `src/agentforge/app.py`
- `src/agentforge/api/backend.py`
- `src/agentforge/api/postgres.py`
- `src/agentforge/release_manifest.py`

**Test writes only**

- `tests/test_platform_readiness.py`
- `tests/test_readiness_m1d.py`

## Required result

Keep `/health` liveness-only. `/ready` must fail closed unless all local/read-only facts
hold:

- exact migration head and database connectivity;
- packaged console;
- valid local Clerk and Web security configuration;
- schema-valid full corpus and expected hashes from one immutable, packaged, release-bound
  manifest whose hash is checked against deployment configuration;
- trusted catalog with valid WP-08 ownership authorizations for live entries;
- compatible queue schema;
- fresh available Runner and Scheduler heartbeats for the exact environment.

Use PostgreSQL time and one exported heartbeat interval/freshness policy shared by
readiness, Runner, Scheduler, and tests. Reject missing, stale, future,
wrong-environment, or unavailable heartbeats. Readiness may contact PostgreSQL only—never
Clerk/JWKS, target, provider, Railway, or hosted model.

Replace `runner_available=True` with a trusted callable/query. Campaign launch must recheck
Runner availability immediately before enqueue; readiness is never campaign authorization.
Public responses and logs contain generic reason codes only.

Tests cover catalog/corpus failures, stale-ready TOCTOU, wrong/future heartbeat, queue
incompatibility, ownership expiry, no-network enforcement, generic 503 behavior, and zero
queue mutation from readiness. Replace obsolete mock-only/fake-DSN readiness expectations
in `tests/test_readiness_m1d.py`; readiness cannot be green from schema/auth mocks alone.

Local readiness tests cannot establish deployed readiness. WP-21B must verify the deployed
Railway Web service against its actual private Postgres/Runner/Scheduler state and exact
release/migration/role identities before RT-14 can close.

**Focused verifier**

```bash
python -m pytest tests/test_platform_readiness.py tests/test_readiness.py tests/test_readiness_m1d.py tests/test_postgres_api_m1d.py tests/deployment -q
```

**Handoff:** WP-20A composes readiness and WP-20B exposes it without treating it as launch
authority.
