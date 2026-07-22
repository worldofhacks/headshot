# Railway deployment runbook

> **Status — selected/planned, not deployed:** Railway is the locked full-platform host. No Railway
> project, service, domain, database, deployment, rollback, or green check is asserted by this
> document. Resource creation and live verification require an authorized human integration step.

This runbook defines the required staging and production topology and the evidence needed before a
deployed status can be claimed.

## Repository deployment artifacts

The repository now prepares one multi-stage production image and three service-specific Railway
config files. These files describe deployable process boundaries; they do **not** create a Railway
project, environment, service, database, domain, variable, or deployment.

| Railway service | Config-as-code path | Exact process |
|---|---|---|
| Web | `/railway/web.json` | `python -m agentforge.web` |
| Runner | `/railway/runner.json` | `python -m agentforge.runner` |
| Scheduler | `/railway/scheduler.json` | `python -m agentforge.scheduler` |
| Web pre-deploy | `/railway/web.json` | `alembic upgrade head` |

Each Railway service must be configured in the Dashboard to use its exact config path. The same
reviewed `Dockerfile` is built for all three processes. Its final non-root Python image contains the
installed wheel, `/app/alembic.ini`, the complete `/app/migrations` tree, and only the compiled Vite
assets under `/app/console`. Node, npm, TypeScript sources, tests, source maps, and development servers
remain outside the runtime stage.

The commands are packaging contracts, not evidence that all private runtime composition exists. At
this integration point Runner refuses to start without the trusted credential resolver, adapter
factory, and atomic result/queue-completion composition; Scheduler refuses to start without an
authoritative persisted schedule repository and queue composition. Keep both services private and
stopped until those dependencies are implemented and verified. Do not set their readiness override
variables merely to make Railway show a running process. Runner enablement also requires a gate before
every outbound dispatch and a bounded active-work cancellation signal; a campaign-level queue claim
cannot provide either invariant by itself.

`VITE_CLERK_PUBLISHABLE_KEY` is the one frontend build argument. It is a public, environment-specific
identifier, is required by every service build because all three services build the same image, and is
consumed only by the throwaway Node stage. It is not an authentication secret or a private-service
authority input. No Clerk secret, JWT verification key, session token, database URL, provider
credential, or target credential may be a Docker build argument.

## Topology

Create the same four-service pattern in separate Railway **staging** and **production** environments.

| Service | Public ingress | Private connections | Responsibility |
|---|---:|---|---|
| Web | **Yes — the only public service** | PostgreSQL, runner/scheduler control surfaces where explicitly required | React console shell, FastAPI, Clerk human authentication, backend authorization, health/readiness |
| Runner | No | PostgreSQL, approved model providers, external target only through the Policy Gateway | Claims durable jobs and executes agent/campaign work |
| Scheduler | No | PostgreSQL | Enqueues scheduled regression/campaign jobs; never performs attack execution inline |
| PostgreSQL | No | Web, runner, scheduler through Railway private networking | Jobs, checkpoints, findings, approvals, audit records, append-only evidence |

External boundaries:

- The user's Browser signs in through Clerk and sends its Clerk session to the public Web service.
- Clerk is the managed human IdP. With `CLERK_JWT_KEY`, Web verifies issued session JWTs without a
  request-time Clerk/JWKS call.
- Model providers and the OpenEMR target are external. Only the trusted Policy Gateway may release a
  target-scoped credential or send a live request.
- A Clerk token is never forwarded to runner, scheduler, Postgres, a model provider, or the target.

Do not expose runner, scheduler, PostgreSQL, an admin dashboard, a metrics endpoint, or an internal
queue endpoint with a Railway public domain.

## Environment isolation

Staging and production are independent security boundaries, not variable groups over one shared
database.

| Boundary | Staging | Production |
|---|---|---|
| Railway Web domain | Staging HTTPS origin only | Production HTTPS origin only |
| PostgreSQL | Dedicated staging database | Dedicated production database |
| Clerk application | Dedicated staging configuration | Dedicated production configuration |
| Required Organization | Staging Headshot Organization with its own exact ID | Production Headshot Organization with a different exact ID |
| Authorized parties | Staging Web origin only | Production Web origin only |
| Target authorization | Fake/non-production target entry only; cannot resolve production credential | Authorized live target entries only after the live-campaign gate |
| Provider/target secrets | Staging-scoped or absent | Production-scoped, least privilege, target-bound |
| Data | Synthetic fixtures only | Synthetic fixtures only; real PHI remains forbidden |

Hard checks:

- `AGENTFORGE_ENVIRONMENT` is set explicitly by Railway to `staging` or `production`.
- Deployed environments never read `.env` or `.env.local`.
- Staging configuration fails to load if it contains the production Railway origin or production
  Clerk Organization ID.
- Staging cannot resolve a production target credential reference.
- A database, volume, domain, key, Organization ID, or secret reference is never shared across the two
  environments merely for convenience.

## Public and private boundaries

The public Web service uses a default-deny route policy.

Public allowlist:

- `GET /health` for process liveness;
- `GET /ready` for deployment readiness; and
- only the concrete static/sign-in/callback shell paths required to complete Clerk authentication.

The integration must enumerate the shell paths after the frontend route contract is known. Do not use
`/auth/*`, `/api/*`, or any other broad wildcard as a public exemption.

Protected surfaces include all console data, APIs, findings, evidence, event streams, WebSockets,
campaign controls, target/configuration management, approvals, remediation, audit records, internal
metrics, and queue operations. Frontend hiding is not protection; FastAPI dependencies enforce the
boundary on every protected route.

Railway private networking does not replace application authorization. Web-to-runner and each service's
database access remain least-privilege and authenticated. Per-agent database roles enforce the recorder,
Judge, and Red Team data boundaries.

## Build and deployment flow

Deploy the same reviewed commit through staging before production.

1. Require green unit, integration, contract, corpus, lint, formatting, secret-scan, and package checks
   for the commit. Record actual results; never infer green from a local run.
2. Build the repository's production image from that commit. Do not inject secrets at image-build time.
3. Quiesce/drain the environment: stop new schedules and launches, allow active leases to finish or
   abort safely, and verify queue/checkpoint compatibility.
4. Confirm PostgreSQL backup/PITR posture and the current migration revision.
5. Run the single pre-deploy schema apply path:

   ```bash
   alembic upgrade head
   ```

6. Deploy private runner and scheduler plus the public Web service using version-compatible job and
   checkpoint payloads. Use expand/contract migrations; never deploy a destructive contraction with a
   consumer that still needs the old schema.
7. Gate promotion on `/health`, `/ready`, an unauthenticated-denial smoke test, an authenticated
   least-privilege smoke test, exact Organization/origin checks, and a private-service exposure check.
8. Re-enable scheduling only after readiness, queue, error-rate, and auth-denial signals are healthy.
9. Promote the same commit to production with explicit human authorization and repeat the gates.

The process commands are fixed in the repository artifact table above. A command's presence is not
evidence that its external Railway service exists or is healthy. In particular, do not point Runner at
the one-shot `python -m agentforge.campaign run` CLI: Railway Runner consumes durable `agent_work` jobs,
while the campaign CLI consumes local files and is not a queue service.

Only Web owns the schema-changing pre-deploy command. Runner and Scheduler must check that the database
is already at the integrated Alembic head before consuming or producing work and must wait or exit
fail-closed when it is not. This avoids concurrent Alembic writers if Railway builds the three services
at the same time. For the first deployment and every migration-bearing release: deploy Web's pre-deploy
migration, verify `/ready`, then activate Runner and Scheduler.

## Pre-deploy migrations

- Alembic is the only schema apply path.
- The checked-in `alembic.ini` intentionally has a blank `sqlalchemy.url`. Programmatic migration tests
  may inject an isolated URL; normal CLI/pre-deploy execution uses the process `DATABASE_URL`. A usable
  localhost value in the INI would override Railway and is forbidden.
- Migrations are forward-compatible expansions first; application rollout follows; destructive
  contractions land only after all old consumers are gone.
- The migrator uses a narrowly controlled database administration binding. Runtime Web/runner/scheduler
  roles do not receive migration authority.
- A migration failure stops deployment. Web must not become ready against a partial or stale schema.
- Job/checkpoint payloads are versioned. An unknown version dead-letters or parks safely rather than
  being interpreted under a new schema.
- Code rollback does not roll back PostgreSQL. Keep the old schema compatible throughout the rollback
  window.

## Health and readiness

`GET /health` is liveness only. It returns success when the process can serve and does not query
PostgreSQL, Clerk, a model provider, or the target.

`GET /ready` returns success only when the service can safely receive traffic. The integrated Web
checks PostgreSQL connectivity, the exact Alembic head, packaged console availability, and local
Clerk/Web security configuration parsing. It does not make a Clerk network request from the probe. A
failed dependency or configuration check returns `503` and blocks promotion.

Container CI exercises both sides without contacting Clerk: an unconfigured image must return `503`,
while the same image connected to a migrated throwaway PostgreSQL database and given an in-memory
generated RSA public fixture plus valid local settings must return `200`. This is packaging evidence,
not real-user or deployed-environment verification.

Readiness is not a reason to call the live target or a model. Those dependencies have separate runtime
health, circuit-breaker, and campaign preflight behavior.

After deployment, verify at minimum:

```text
GET /health                    -> 200
GET /ready                     -> 200 only when DB/schema/local auth config are ready
protected route, no token      -> 401
protected route, wrong org     -> 403
protected route, no permission -> 403
private service public URL     -> absent/unreachable
```

Never include a bearer token in a command transcript, CI log, screenshot, or ticket. Perform
authenticated smoke tests through a secret-safe test harness.

## Sealed variables

Configure variables separately in each Railway environment. Values are injected at runtime by
reference and never committed, printed, included in build arguments, or copied between environments.

| Variable or class | Service | Handling |
|---|---|---|
| `AGENTFORGE_ENVIRONMENT` | All | Plain enumerated setting; exact environment value |
| `PORT` | Web | Assigned by Railway; Web binds this exact decimal port |
| `AGENTFORGE_CONSOLE_DIR` | Web | Fixed packaged path `/app/console`; never a host/source directory in deployment |
| `AGENTFORGE_MAX_REQUEST_BYTES` | Web | Explicit integer request-body cap from 1 KiB through 10 MiB |
| `DATABASE_URL` | Each service that needs DB access | Railway reference to that environment's private Postgres; use least-privilege role per service |
| `VITE_CLERK_PUBLISHABLE_KEY` | Build of each shared-image service | Public identifier; required Docker build argument, environment-specific, consumed only when compiling the browser bundle |
| `CLERK_PUBLISHABLE_KEY` | Web | Public backend identifier; environment-specific |
| `CLERK_JWT_KEY` | Web | Multiline PEM public verification key; sealed/integrity-controlled |
| `CLERK_AUTHORIZED_PARTIES` | Web | Exact HTTPS Web origins only; no wildcard |
| `CLERK_REQUIRED_ORG_ID` | Web | Exact environment-specific Headshot Organization ID |
| `CLERK_FRONTEND_API_ORIGIN` | Web | Exact environment-specific Clerk Frontend API HTTPS origin used by the CSP `connect-src`; no path or wildcard |
| `CLERK_PRODUCTION_AUTHORIZED_PARTIES` | Staging Web only | Exact production-origin comparison guard; never treated as a staging origin |
| `CLERK_PRODUCTION_ORG_ID` | Staging Web only | Exact production Organization comparison guard; never accepted as staging membership |
| `CLERK_SECRET_KEY` | None for request auth | Absent. Future Backend API administration only after separate review |
| `AGENTFORGE_LIVE_TARGET_CATALOG_JSON` | Web + Runner | Identical reviewed, secret-free target/surface/policy definitions; never browser-authored |
| `AGENTFORGE_CREDENTIAL_BINDINGS_JSON` | Runner only | Opaque `secretref://` handle to Runner variable-name mapping; contains no credential value |
| Model-provider keys | Runner only where needed | Dedicated, scoped, expiring/spend-limited keys; never exposed to Web/browser |
| Target credential value | Runner only | Stored under the mapped Runner variable; never present on Web, in the catalog, or in PostgreSQL |
| Observability secrets | Emitting services only | Synthetic/redacted telemetry; no real PHI or auth tokens |

Treat public Clerk keys as configuration that can change authentication trust even though they are not
confidential. Audit all changes. Rotate compromised secrets and redeploy; never “temporarily” log them.

## Exact Clerk configuration by environment

Complete this table with private dashboard evidence during provisioning. Do not commit actual secret
keys, invitation links, session tokens, or backup codes.

| Setting | Staging | Production |
|---|---|---|
| Sign-up mode | Restricted; administrator invitations | Restricted; administrator invitations |
| Organization | Headshot; staging-specific exact ID | Headshot; production-specific exact ID |
| Personal Accounts | Disabled | Disabled |
| User-created Organizations | Disabled | Disabled |
| MFA session task | Required for all users | Required for all users |
| Factors | TOTP + backup codes; SMS optional/not sole | TOTP + backup codes; SMS optional/not sole |
| Roles | Observer, Operator, Approver, Auditor | Observer, Operator, Approver, Auditor; Enhanced B2B add-on provisioned |
| Permissions | Exact custom matrix in `docs/security/AUTHENTICATION.md` | Exact same keys; environment-local assignments |
| Authorized parties | Exact staging Railway HTTPS origin | Exact production Railway HTTPS origin |
| Frontend API origin | Exact staging Clerk FAPI HTTPS origin | Exact production Clerk FAPI HTTPS origin |
| JWT verification | Environment's PEM public key, networkless | Environment's PEM public key, networkless |
| Accepted human token | `session_token` only | `session_token` only |
| Publishable-key class | `pk_test_…` | `pk_live_…` |
| Production-isolation guards | Exact production origin + Organization ID supplied for comparison and rejected as staging values | Not needed; production uses its own exact values |
| Secret key | Absent for request authentication | Absent for request authentication |

Before promotion, use negative tests to prove that swapping either environment's Organization ID,
publishable key/JWT key pair, or origin causes denial.

## Rollback

Rollback begins by containing side effects, not by clicking redeploy:

1. Stop new scheduler enqueues and campaign launches.
2. Trigger the hard abort for unsafe active campaigns; otherwise drain active leases with bounded time.
3. Preserve logs, audit events, migration revision, deployed commit, and queue/checkpoint versions without
   recording tokens or secrets.
4. Roll the affected service back through Railway deployment history to a known compatible image.
5. Do **not** automatically run a destructive Alembic downgrade. The expand/contract schema should remain
   compatible with the prior image.
6. If data restoration is necessary, treat PostgreSQL PITR/restore as a separate incident procedure,
   restore to a new isolated database first, validate, and explicitly rebind services.
7. Re-run liveness/readiness, authentication denial/allow tests, schema, queue, and private-network smoke
   tests before resuming schedules.

If a Clerk configuration change caused the incident, restore the last reviewed exact origins,
Organization ID, and key pair; revoke affected sessions/users as appropriate. Never fail open or disable
authentication to recover availability.

## Deployment evidence checklist

- [ ] Staging and production are separate Railway environments with separate Postgres databases.
- [ ] Only Web has a public domain; runner, scheduler, and PostgreSQL have none.
- [ ] Environment-scoped variables and least-privilege database roles are verified.
- [ ] Staging cannot resolve production target credentials or accept production Clerk configuration.
- [ ] Alembic migration and revision evidence is captured without credentials.
- [ ] The Web service uses `/railway/web.json`; Runner and Scheduler use their respective private config paths.
- [ ] The built image contains `/app/alembic.ini`, the complete migration tree, and compiled console assets, and contains no Node/npm/source maps.
- [ ] Clean-database and `0003 -> 0004 -> integrated head` migrations pass inside that exact image.
- [ ] Web honors Railway `PORT`; Runner and Scheduler expose no HTTP listener.
- [ ] `/health` and `/ready` behave as documented.
- [ ] Public shell paths are enumerated; all other human routes deny by default.
- [ ] Clerk restricted enrollment, Headshot Organization, MFA, roles, permissions, and add-on are verified.
- [ ] Missing/wrong auth, wrong Organization, missing permission, and same-user approval are denied.
- [ ] A different authorized approver succeeds without bypassing the Policy Gateway.
- [ ] Rollback is exercised in staging and both code and database recovery limits are recorded.
- [ ] Exact staging/production URLs and actual CI/deployment statuses are added to README only after
      successful verification.
