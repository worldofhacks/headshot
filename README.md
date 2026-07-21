# AgentForge / Adversarial Machine

AgentForge is a reusable, multi-agent adversarial evaluation platform for continuously
red-teaming AI applications. Its first target is the externally deployed OpenEMR Clinical
Co-Pilot. The target is reached over an authorized live URL; its code does not live in this
repository.

> **Delivery status — 2026-07-21:** Railway is the locked hosting platform and Clerk is the
> locked human identity provider. The isolated authentication foundation is implemented and
> offline-tested on this branch, but it is not wired into the FastAPI application or console and is
> not verified on Railway. No deployment or green deployment check is claimed here.

| Endpoint | Status |
|---|---|
| Staging platform URL | **PENDING — not deployed or verified** |
| Production platform URL | **PENDING — not deployed or verified** |
| Authorized live target URL | **PENDING — record only after the live-target gate passes** |

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

The full platform is hosted on Railway in separate staging and production environments. This
is the target topology; it is not a claim that the services have been provisioned.

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
4. Create the four Organization roles and the custom permissions in the matrix below. Clerk's
   production plan includes only the first two custom roles without the Enhanced B2B
   Authentication add-on; the locked four-role design therefore requires that add-on.
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
uvicorn agentforge.app:app --reload
```

`.env.local` is local-only and must never be committed. Use synthetic values. The Clerk
authentication package can be tested offline with fixture keys before Clerk resources exist; it is
not wired into `agentforge.app` in this foundation task.

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
- The minimal static sign-in and callback shell required to complete Clerk authentication. Its
  concrete paths must be enumerated during integration; broad authentication wildcards are forbidden.

Everything else defaults to protected. Console data, findings, evidence, event streams,
WebSockets, campaign actions, target/configuration management, approvals, audit data, and
remediation are never public.

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
| `org:observer` | `org:console:read`, `org:findings:read`, `org:evidence:read` |
| `org:operator` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:campaign:launch`, `org:campaign:abort`, `org:targets:manage`, `org:config:manage` |
| `org:approver` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:campaign:authorize`, `org:findings:approve`, `org:findings:resolve` |
| `org:auditor` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read` |

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

## Further documentation

- [Identity and access ADR](docs/adrs/0002-identity-and-access.md)
- [Authentication security contract](docs/security/AUTHENTICATION.md)
- [Railway deployment runbook](docs/deployment/RAILWAY.md)
- [Threat model](THREAT_MODEL.md)
- [User workflows](USERS.md)
- [User-locked requirements matrix](docs/requirements/REQUIREMENTS_MATRIX.csv)
