# AgentForge / Adversarial Machine

AgentForge is a reusable, multi-agent adversarial evaluation platform for continuously
red-teaming AI applications. Its first target is the externally deployed OpenEMR Clinical
Co-Pilot. The target is reached over an authorized live URL; its code does not live in this
repository.

> **Delivery status — 2026-07-23:** the Clerk-backed React console, protected FastAPI `/api/v1`,
> organization-scoped PostgreSQL control plane, private Runner, live target adapter, and Langfuse
> telemetry projection have a provisioned Railway baseline. The current release adds the private
> regression planner and migrations through `0013`; its exact deployment evidence is recorded
> separately after promotion. Live campaigns remain bounded by persisted exact-scope authorization,
> synthetic-only evidence, rate/budget/timeout caps, and abort controls.

| Endpoint | Status |
|---|---|
| Staging platform URL | `https://web-staging-8e30.up.railway.app` |
| Production platform URL | `https://web-production-44528.up.railway.app` |
| Authorized live target URL | `https://agent-production-9f62.up.railway.app` |

The requirements source of truth is [Week_3_AgentForge.pdf](Week_3_AgentForge.pdf). See
[PLAN.md](PLAN.md), [ARCHITECTURE.md](ARCHITECTURE.md), and
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for sequencing and acceptance criteria.

## Safety invariants

- No real protected health information (PHI) is permitted. All fixtures, canaries, evidence,
  logs, and demonstrations use synthetic data.
- The Judge is independent of attack generation and can never downgrade a deterministic,
  confirmed exploit.
- The trusted Policy Gateway is the only path to an external target. It enforces the exact
  target authorization, environment-scoped allowlist, target-bound credentials,
  synthetic-data assertion, budget and rate limits, timeout, and hard abort.
- Human approval is required before publishing a critical finding or performing remediation.
  The launcher and approver must be different Clerk users; there is no self-approval bypass.
- Human authentication is necessary but never sufficient to authorize a live campaign.

## Locked Railway topology

The full platform is hosted on Railway in separate staging and production environments. Web, Runner,
and PostgreSQL are provisioned in both environments. Scheduler is part of this release and must be
verified as a private service during promotion.

| Railway component | Network boundary | Responsibility |
|---|---|---|
| Web | **Public** | React console shell, FastAPI, Clerk request authentication, authorization dependencies, health/readiness |
| Runner | Private | Campaign and agent workload execution; no public ingress |
| Scheduler | Private | Enqueues scheduled work; does not execute attacks inline |
| PostgreSQL | Private | Jobs, checkpoints, exploit records, approvals, and append-only evidence |

Clerk is an external managed identity provider. The OpenEMR target and model providers are also
external. Only the Railway Web service receives public traffic; private services communicate over
Railway's private network. See [Railway deployment](docs/deployment/RAILWAY.md).

## Clerk prerequisites

Provisioning is a manual integration step. Staging and production must use isolated Clerk
configuration, including different exact Organization IDs and authorized origins.

1. Enable **Restricted** sign-up mode and use invitations for enrollment.
2. Enable Organizations, create the single required **Headshot** Organization, disable Personal
   Accounts, and disable user-created Organizations.
3. Require MFA for every user. Enable authenticator-app TOTP and backup codes; SMS may be offered
   but must not be the only factor.
4. Create exactly the `org:operator` and `org:approver` Organization roles and assign the custom
   permissions in the matrix below. Remove any retired or demo roles.
5. Copy the publishable key and PEM JWT public key for each environment. Configure exact,
   non-wildcard authorized parties and the environment's exact Headshot Organization ID.
6. Do **not** configure `CLERK_SECRET_KEY` for request authentication. It is a future-only
   requirement if the backend later manages users or invitations through Clerk's Backend API.

The complete checklist is in [Authentication](docs/security/AUTHENTICATION.md).

## Local development

Python 3.12+ and PostgreSQL 16 are expected. Local development may use HTTP only on loopback; all
staging and production origins use HTTPS.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env.local
docker compose up -d postgres
alembic upgrade head
cd console
npm ci
VITE_CLERK_PUBLISHABLE_KEY=pk_test_your_local_fixture npm run build
cd ..
python -m agentforge.web
```

`.env.local` is local-only and must never be committed. Use synthetic values. The Clerk
authentication path and protected API tests use locally generated fixture keys and make no Clerk,
Railway, target, model, or JWKS request. `/ready` remains `503` until PostgreSQL is at the packaged
Alembic head, the built console exists, and the complete Clerk and Web security configuration parses.

### Authentication configuration contract

| Variable | Local meaning | Secret? |
|---|---|---|
| `VITE_CLERK_PUBLISHABLE_KEY` | Public identifier embedded in the browser bundle | No |
| `CLERK_PUBLISHABLE_KEY` | Backend public environment identifier validated by the auth configuration; the current networkless Python verifier itself receives the PEM key and authorized parties | No |
| `CLERK_JWT_KEY` | PEM public key used for networkless JWT verification | No, but integrity-sensitive |
| `CLERK_AUTHORIZED_PARTIES` | Comma-separated exact browser origins; for example `http://localhost:5173` | No |
| `CLERK_REQUIRED_ORG_ID` | Exact environment-specific Headshot Organization ID | No, but security-sensitive configuration |
| `CLERK_PRODUCTION_AUTHORIZED_PARTIES` | Staging-only comparison guard containing the exact production origin list | No, but security-sensitive configuration |
| `CLERK_PRODUCTION_ORG_ID` | Staging-only comparison guard containing the exact production Headshot Organization ID | No, but security-sensitive configuration |
| `CLERK_FRONTEND_API_ORIGIN` | Exact HTTPS Clerk Frontend API origin admitted by deployed CSP; optional locally | No |
| `AGENTFORGE_MAX_REQUEST_BYTES` | Request-body ceiling, 1 KiB–10 MiB; defaults to 1 MiB | No |
| `AGENTFORGE_CONSOLE_DIR` | Optional built-console directory; image default `/app/console` | No |
| `CLERK_SECRET_KEY` | **Unset for request authentication**; future Backend API administration only | Yes |

Production rejects HTTP origins. Loopback HTTP origins are accepted only when
`AGENTFORGE_ENVIRONMENT=local`. Wildcards are rejected. A staging configuration must never contain
the production Railway origin or production Organization ID. Local and staging use a Clerk
`pk_test_…` publishable key; production requires its matching `pk_live_…` key.

Run the local checks with:

```bash
pytest
ruff check .
ruff format --check .
```

## Public and protected routes

The public route policy is an allowlist, not a list of exceptions:

- `GET /health` — process liveness only.
- `GET /ready` — readiness; returns unavailable when dependencies or schema are not ready.
- Built static assets and the non-data SPA shell, including `/sign-in` and nested Clerk sign-in paths,
  `/session-tasks/choose-organization`, `/session-tasks/setup-mfa`, and
  `/session-tasks/reset-password`. Frozen console direct routes also receive only the shell; their data
  stays closed until the browser presents a bearer session to protected `/api/v1`.

Every `/api/v1` route defaults to protected. Console data, findings, evidence, the event stream,
campaign actions, target/configuration management, approvals, audit data, and remediation are never
public. Unknown API paths never receive the SPA fallback.

Missing, expired, malformed, not-yet-valid, incorrectly signed, wrong-algorithm, wrong-party, or
non-session authentication receives a generic `401`. An active authenticated session that lacks the
required Headshot Organization, permission, or distinct approver receives `403`. Clerk verifier or
security-configuration failure denies access and reports service unavailability (`503`) without
exposing tokens or headers.

## Backend role and permission matrix

Only custom Organization permissions from verified Clerk session claims authorize backend actions.
Frontend labels and Clerk system permissions are not backend authority.

| Role | Backend-authoritative custom permissions |
|---|---|
| `org:operator` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:launch`, `org:campaign:abort`, `org:targets:manage`, `org:config:manage` |
| `org:approver` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:authorize`, `org:findings:approve`, `org:findings:resolve` |

A role is useful for assignment and audit display, but the backend checks the verified custom
permission set for each operation. Client-supplied roles or permissions are ignored.

## Authentication is not campaign authorization

Clerk answers **who the human is** and which Headshot custom permissions are present in that verified
session. It does not answer **whether this target may be attacked now**. Campaign launch remains a
separate decision:

1. Clerk authenticates the human, exact Organization membership is verified, and the relevant custom
   permission is required.
2. A different authorized approver supplies the approval when the operation requires two people.
3. The Policy Gateway independently verifies target authorization, allowlist membership,
   target-bound credentials, synthetic-only fixtures, budgets, rate limits, timeout, monitoring, and
   abort capability.

Failure at any stage denies the action. Clerk tokens are human credentials and must never be reused as
agent, runner, scheduler, model-provider, or target credentials.

## Current local availability

Revisions through `0013` add authoritative results, exact two-role authorization, regression replay
planning, and four-agent runtime observability to the exact-scope control plane. A trusted server
catalog prepares immutable campaign scopes; a private durable Runner claims the PostgreSQL queue,
revalidates authorization immediately before every dispatch, resolves scoped credentials only at that
boundary, and persists evidence before atomic job completion. The private Scheduler creates one
append-only, human-authorization-blocked replay plan when a ready target version changes; it never
executes an attack or bypasses campaign authorization. Application and database controls reject
self-approval, and neither queue completion nor a replay plan is approval.

For the Clinical Co-Pilot `/chat` surface, a live campaign pins one versioned, patient-scoped SMART
session for its entire bounded run and reuses one HTTP client so cookies and connection state persist.
The Runner never silently refreshes or rotates that identity: local expiry or the target's session-
expired response hard-aborts the run before another attempt. Rotation requires a new secret-reference
generation, target version, exact authorization scope, and distinct-person approval.

The deterministic synthetic profile runs the real nine-case corpus through the queue, Runner,
coordinator, recorder, independent Judge, findings, API, Coverage, and event repositories without a
target/model socket. Local integration evidence proves all attempts and hash-verified Coverage;
this is not a deployed or live-target claim. A live run remains blocked until the exact deployed target,
ownership authorization, synthetic fixture/canary, surface, credential reference, caps, nonce, and a
distinct Clerk Approver are persisted and every network-free preflight gate passes. Scheduling, traces,
immutable configuration snapshots, component heartbeats, resilience history, and live-probe
authorization are projected only from durable records; unavailable observations remain explicitly
unavailable rather than being replaced by dummy data.

## Further documentation

- [M1d integration handoff](docs/planning/M1D_INTEGRATION_HANDOFF.md)
- [Security-tool integration plan](docs/planning/SECURITY_TOOL_INTEGRATION_PLAN.md)
- [Security-tool ATO evidence](docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md)
- [Identity and access ADR](docs/adrs/0002-identity-and-access.md)
- [Authentication security contract](docs/security/AUTHENTICATION.md)
- [Railway deployment runbook](docs/deployment/RAILWAY.md)
- [Measured-cost and nonlinear scale model](docs/cost/COST_ANALYSIS.md)
- [Clinical Co-Pilot target/session readiness](docs/target/READINESS.md)
- [Threat model](THREAT_MODEL.md)
- [User workflows](USERS.md)
- [User-locked requirements matrix](docs/requirements/REQUIREMENTS_MATRIX.csv)
