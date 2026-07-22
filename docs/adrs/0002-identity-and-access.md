# ADR-0002 — Identity and access for the Headshot platform

- **Status:** Accepted; implementation selected/planned, not yet deployed
- **Date:** 2026-07-21
- **Deciders:** platform author; subject to integration verification
- **Applies to:** human access to the Railway-hosted console and API
- **Does not apply to:** agent/workload, model-provider, target, or database identities

## Context

The seven-hour MVP needs production-defensible human identity without spending the time or accepting
the risk of a custom password, OAuth, or session subsystem. The platform exposes highly sensitive
operations: viewing adversarial evidence, launching or aborting campaigns, managing targets and
configuration, approving findings, and reading audit records. A compromised browser identity must not
be able to become a workload identity or bypass the separate live-campaign Policy Gateway.

The platform will run on Railway with one public Web service and private runner, scheduler, and
PostgreSQL services. Staging and production require isolated identity configuration. Only synthetic
data is permitted, but that does not reduce the need for strong access control or auditability.

## Decision

### Managed identity provider

Use **Clerk** for human authentication. Do not build or store platform passwords, implement a custom
OAuth flow, or create a custom session database.

Clerk application access is restricted and invitation-only. Every accepted user must:

- belong to the one required Clerk Organization named **Headshot**;
- use the exact environment-specific Organization ID configured by the backend;
- complete required MFA using authenticator-app TOTP with backup codes available; and
- receive one of the Organization roles and custom permission sets defined below.

Personal Accounts and user-created Organizations are disabled. SMS may be enabled as an additional
factor but must never be the only factor. Staging and production use isolated Clerk configuration;
staging must not accept the production Railway origin or production Organization ID.

### Request authentication

The FastAPI authentication boundary will use Clerk's official Python backend SDK and its official
request-authentication API. For human-facing endpoints it will:

1. accept only `session_token`;
2. verify JWT signatures networklessly with the environment's PEM `CLERK_JWT_KEY`;
3. configure an explicit, exact, non-wildcard `CLERK_AUTHORIZED_PARTIES` origin list;
4. require the exact `CLERK_REQUIRED_ORG_ID` for Headshot;
5. reject pending sessions and all verifier ambiguity; and
6. derive an immutable Principal from verified claims only.

The Principal contains only user ID, session ID, Organization ID, Organization role, and an immutable
set of Organization custom permissions. It never retains the bearer token, authorization header,
request object, Clerk request state, or any client-supplied role/permission field.

`VITE_CLERK_PUBLISHABLE_KEY` and `CLERK_PUBLISHABLE_KEY` are public identifiers.
`CLERK_JWT_KEY` is a public verification key whose integrity still matters. `CLERK_SECRET_KEY` is not
required for request authentication and must not be added to that path. It is reserved for a future,
separately reviewed Backend API capability to manage users or invitations.

### Authorization model

Custom Organization permissions from verified Clerk claims are the backend authority. Clerk system
permissions are not sufficient because they are not included in session claims. A role label is useful
for assignment and audit display, but it does not create permissions and is never accepted from the
browser as authority.

| Organization role | Required custom permission assignment |
|---|---|
| `org:observer` | `org:console:read`, `org:findings:read`, `org:evidence:read` |
| `org:operator` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:campaign:launch`, `org:campaign:abort`, `org:targets:manage`, `org:config:manage` |
| `org:approver` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:campaign:authorize`, `org:findings:approve`, `org:findings:resolve` |
| `org:auditor` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read` |

The production four-role design requires Clerk's **Enhanced B2B Authentication** add-on: current Clerk
documentation includes only the first two custom production roles without that add-on. Provisioning the
add-on is a pre-deployment prerequisite, not something the code can emulate safely.

### Two-person and campaign invariants

A launcher cannot approve or authorize their own operation. The backend compares immutable verified
user IDs and requires `approver.user_id != launcher_user_id` in addition to the required custom
permission. There is no solo-user, emergency, role-based, or permission-based self-approval bypass.

Clerk authentication and Headshot permissions never authorize an attack by themselves. The Policy
Gateway independently enforces the exact target authorization, environment-scoped allowlist,
target-bound credentials, synthetic-only assertion, budget, rate, timeout, monitoring, and hard abort.

### Public routes and failure behavior

Only `GET /health`, `GET /ready`, and the concrete minimal static/sign-in/callback shell required for
Clerk authentication may be public. The integration must enumerate those shell paths; a broad wildcard
is forbidden. Every data, event-stream, WebSocket, campaign, finding, evidence, target, configuration,
approval, remediation, and audit route defaults to protected.

- Missing, malformed, expired, not-yet-valid, wrongly signed, unsupported-algorithm, wrong-party,
  wrong-token-type, and pending authentication return a generic `401`.
- An active authenticated principal with a missing/wrong Organization, missing custom permission, or
  same-user approval returns `403`.
- Clerk SDK, verifier, or security-configuration failure fails closed and returns a generic `503`.

Errors, logs, traces, metrics, exception messages, and Principal representations never contain bearer
tokens or authorization headers.

## Alternatives considered

### Custom password and session system — rejected

This would require secure password enrollment and recovery, hashing and rehashing, MFA, session
rotation and revocation, cookie/CSRF defenses, account lockout, audit trails, and an administrative
surface. It is not production-defensible in the MVP timebox and would create a high-impact credential
store that is unrelated to the graded platform capabilities.

### Auth0 — viable, not selected

Auth0 is a credible managed identity provider and avoids custom passwords. It was not selected because
the implementation would still require a fresh organization/RBAC/session integration and dashboard
configuration during the same short timebox. Clerk's React integration, Organization session tasks,
restricted enrollment, and custom Organization permission model align directly with the locked
Headshot flow. No claim is made that Auth0 is generally less secure.

### Clerk — selected

Clerk supplies managed sign-in, restricted enrollment, Organizations, MFA session tasks, and custom
Organization roles/permissions while allowing the backend to verify session JWTs from a pinned public
key without a request-time JWKS dependency. This is the smallest implementation that preserves a
server-side authorization boundary.

## Consequences

### Positive

- No platform password database, password-reset system, custom OAuth flow, or custom session store.
- Authentication dependencies can default-deny FastAPI routers and remain independent of frontend UI
  labels.
- Networkless verification removes Clerk/JWKS availability from the hot path for already-issued
  session tokens.
- Exact origins and the exact Headshot Organization reduce subdomain-cookie and organization-confusion
  risk.
- Immutable user IDs make the two-person invariant testable and auditable.

### Costs and residual risks

- Clerk configuration drift is security-sensitive and needs a checked manual deployment checklist.
- The four custom roles require a paid production add-on.
- A stolen bearer token remains usable until it expires or a verification control rejects it. XSS
  prevention, short session lifetime, secure Clerk defaults, MFA, token redaction, and incident-driven
  revocation remain necessary.
- Networkless verification does not fetch current membership or permission state on each request.
  Revocation and role changes therefore have token-freshness latency bounded by Clerk session-token
  refresh/expiry. Critical-action step-up or an online freshness check is a post-MVP hardening option;
  it must not silently turn into a fail-open fallback.
- If Clerk is unavailable, new sign-ins, session refresh, and administrative changes may be unavailable.
  Protected routes continue to deny verifier/configuration failures.
- Exact authorized parties mitigate one browser-origin threat; they do not replace XSS, CSRF controls
  when cookies are used, strict CORS, or server-side authorization.

## Validation

Acceptance requires offline deterministic tests for signature and time validation, algorithm
allowlisting, exact authorized party and Organization enforcement, custom permission checks,
client-claim rejection, token/header redaction, environment isolation, distinct approver identity, and
zero network calls. Railway integration then requires staging and production smoke tests, exact public
route enumeration, and a denial test before any deployed status is claimed.

## References

- [Clerk React quickstart](https://clerk.com/docs/react/getting-started/quickstart)
- [Clerk request authentication](https://clerk.com/docs/reference/backend/authenticate-request)
- [Clerk manual JWT verification](https://clerk.com/docs/guides/sessions/manual-jwt-verification)
- [Clerk Organization roles and permissions](https://clerk.com/docs/guides/organizations/control-access/roles-and-permissions)
- [Clerk restrictions and allowlist](https://clerk.com/docs/authentication/allowlist)
- [Clerk session tasks](https://clerk.com/docs/guides/configure/session-tasks)
- [Authentication contract](../security/AUTHENTICATION.md)
- [Railway deployment runbook](../deployment/RAILWAY.md)
