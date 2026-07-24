# WP-02 — Enforce per-agent database roles at runtime

**Branch:** `rtg/wp02-runtime-db-roles`

**Model:** capable

**Depends on:** WP-01

**Implements toward (live validation pending):** RT-10

Read `src/agentforge/storage/roles.sql`, campaign runtime/composition, Recorder/Judge
database paths, existing role tests, and RT-10.

**Implementation writes only**

- `src/agentforge/storage/role_scope.py`
- `src/agentforge/storage/roles.sql`
- `src/agentforge/campaign/runtime.py`
- `src/agentforge/campaign/coordinator.py`
- `src/agentforge/runner.py`
- `docs/deployment/RAILWAY.md`
- `migrations/versions/<MIGRATION_REV>_runtime_roles.py`

**Test writes only**

- `tests/test_runtime_db_role_isolation.py`
- `tests/test_readiness_m1d.py`
- `tests/test_campaign_coordinator.py`

## Required result

Create a closed, transaction-scoped role API using compile-time role identifiers and
`SET LOCAL ROLE`; caller text must never enter SQL identifiers. Runtime Recorder writes,
Judge rereads, and Red Team staging operations must run under their exact roles. Agent
objects may not receive the owner/control-plane connection.

Production Runner must reject a superuser, table owner, `BYPASSRLS` user, broad inheriting
login, or login unable to assume the required roles. Use a dedicated non-owner,
`NOINHERIT` runtime login; the migration/admin `DATABASE_URL` is not a production fallback.
Select an explicit production runtime DSN, set a fixed safe `search_path`, and grant only
the named control-plane reads plus exact Recorder, Judge, and Red Team operations and
sequences. The grant migration is mandatory and must upgrade/downgrade without ownership
or `PUBLIC` access.

Replace the readiness test's hard-coded `0013` head with a stronger graph check: there is
exactly one packaged head, it descends from `0013`, and a fully migrated throwaway database
equals that head. Future serialized migrations must not require editing a frozen literal.

Tests against a real throwaway PostgreSQL process must prove SQLSTATE 42501 for prohibited
actions as a non-evidentiary implementation precheck,
including:

- Red Team reading/writing authoritative evidence or reading staging;
- Recorder update/delete/truncate;
- Judge mutation of evidence, campaign, finding, authorization, or publication state;
- role-name injection;
- pooled-connection role leakage after success, denial, cancellation, and exception.

Also prove permitted Recorder insert, Judge read, Red Team staging insert, role reset, and
explicit local-test composition. Do not grant ownership, `ALL`, `PUBLIC`, `SUPERUSER`,
`BYPASSRLS`, blanket sequence access, or append-only mutation.

RT-10 remains `LIVE_EVIDENCE_REQUIRED` until WP-21B verifies the actual deployed private
Railway Postgres roles/grants and production service identities through authorized live
operations. A throwaway database cannot establish deployed least privilege.

**Focused verifier**

```bash
python -m pytest tests/test_runtime_db_role_isolation.py tests/test_db_roles.py tests/test_migrations.py tests/test_readiness_m1d.py tests/test_runner_campaign.py tests/test_campaign_coordinator.py -q
```

**Security focus:** privilege inheritance, pool contamination, raw-engine leakage,
error-path rollback, owner bypass, sequence grants, and migration downgrade.

**Handoff:** WP-20A verifies that every persisted observation, verdict, and replay uses the
correct runtime role. Do not change coverage semantics or agent behavior here.
