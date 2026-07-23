# Headshot authentication and authorization

> **Status — 2026-07-21:** Clerk is the locked human identity provider. This integration branch wires
> the offline-tested M1c verifier into a bearer-only `/api/v1` boundary and a Clerk React console.
> It is **not deployed** and has not been verified with real Clerk users. Dashboard provisioning,
> Railway staging, and all external acceptance tests remain required before this can be called an
> operational Clerk integration.

This document is the security contract for human access to the Headshot console and API. It does not
define agent/workload credentials and it does not authorize live campaigns.

## Security invariants

1. Every meaningful human-facing route defaults to authenticated.
2. The backend accepts only a Clerk `session_token` for human access.
3. Session JWTs are verified networklessly with the environment's PEM public key.
4. Authorized parties are explicit exact origins. Wildcards are invalid.
5. An active principal must belong to the exact configured Headshot Organization.
6. Only custom Organization permissions from verified Clerk claims authorize backend operations.
7. Frontend role labels, request bodies, headers, cookies, and other client-supplied permission text have
   no authority.
8. Bearer tokens and authorization headers never enter a Principal, response, log, metric, trace, or
   exception representation.
9. The launcher and approver user IDs must differ. No role or permission bypasses identity separation.
10. Authentication never replaces Policy Gateway authorization for a live campaign.

## Identity boundaries

| Identity | Credential and authority | Explicitly cannot do |
|---|---|---|
| Human user | Clerk session token → immutable Headshot Principal → verified custom permissions | Act as a runner/agent, authenticate to a target/model/database, or bypass the Policy Gateway |
| Web service | Railway workload configuration and private service bindings | Treat a human token as a service credential |
| Runner/scheduler/agents | Private Railway service identity, per-agent DB roles, target-scoped credential references | Use Clerk to gain target access or human approval authority |
| External target | Target-bound credential released only by the trusted Policy Gateway | Trust a Clerk session as target authorization |

Clerk establishes human identity. The Policy Gateway establishes whether a specific external target can
be exercised under the exact safety envelope. They are independent gates.

## Configuration contract

Configuration loads before protected traffic is served. Missing, malformed, or unsafe values fail
closed. Environment values are never accepted from a request.

| Variable | Required in local | Required in staging/production | Contract |
|---|---:|---:|---|
| `AGENTFORGE_ENVIRONMENT` | Optional; defaults to `local` | Yes | Exactly `local`, `staging`, or `production`; deployed values come from the process environment, not dotenv files |
| `VITE_CLERK_PUBLISHABLE_KEY` | For console integration | Yes | Public frontend identifier; it is intentionally visible in the browser bundle |
| `CLERK_PUBLISHABLE_KEY` | For auth tests/integration | Yes | Public backend environment identifier validated by configuration; the current Python verifier has no publishable-key option |
| `CLERK_JWT_KEY` | Yes for auth integration | Yes | Complete PEM public verification key from the matching Clerk instance; used for networkless verification |
| `CLERK_AUTHORIZED_PARTIES` | Yes | Yes | Comma-separated, non-empty list of exact origins, including scheme and port when non-default |
| `CLERK_REQUIRED_ORG_ID` | Yes | Yes | Exact Organization ID of that environment's Headshot Organization |
| `CLERK_PRODUCTION_AUTHORIZED_PARTIES` | No | Staging only | Explicit production-origin comparison guard; staging fails if its allowed origins intersect this list |
| `CLERK_PRODUCTION_ORG_ID` | No | Staging only | Explicit production Organization comparison guard; staging fails if its required ID matches |
| `CLERK_FRONTEND_API_ORIGIN` | Optional | Yes | Exact HTTPS Clerk Frontend API origin admitted by Web CSP; never a wildcard |
| `AGENTFORGE_MAX_REQUEST_BYTES` | Optional | Optional | 1 KiB–10 MiB request-body ceiling; defaults to 1 MiB |
| `AGENTFORGE_CONSOLE_DIR` | Optional | Image default | Built static asset directory; runtime image uses `/app/console` |
| `CLERK_SECRET_KEY` | No | No | **Not used for request authentication.** Future-only Backend API user/invitation administration |

`VITE_CLERK_PUBLISHABLE_KEY` is also a required Docker build argument for the console stage. It is
public and may be embedded in the compiled JavaScript; it must still match the backend environment.
No private/secret value may use a `VITE_` name.

### Authorized-party rules

- Each entry is a complete origin: scheme, host, and optional port only. Userinfo, path, query,
  fragment, glob, regex, and wildcard syntax are rejected.
- Production and staging use HTTPS origins. `http://localhost` and loopback equivalents are local-only.
- Production HTTP origins are rejected at configuration load.
- Staging must not accept the production Railway origin or production Headshot Organization ID.
- Local and staging require a Clerk `pk_test_…` publishable key; production requires the matching
  `pk_live_…` form. A prefix/environment mismatch fails configuration.
- The verifier receives the configured list on every authentication decision. A token whose `azp`
  identifies a different origin is unauthenticated.
- CORS uses an independently explicit least-privilege origin list. CORS is not authentication.

`CLERK_JWT_KEY` is public-key material, not a secret, but replacing it changes who can mint accepted
tokens. Store it as sealed, environment-scoped Railway configuration and review changes like a secret
rotation. Supply a complete `BEGIN PUBLIC KEY` PEM using literal newlines or the supported escaped `\n`
form; private-key material is rejected.

## Enrollment and session policy

- Clerk **Restricted mode** is enabled. Sign-up is by administrator-issued invitation; a public sign-up
  link is not an enrollment path.
- There is one allowed Organization per environment, named **Headshot**. The backend checks its exact ID,
  not its display name or slug.
- Personal Accounts and user-created Organizations are disabled.
- MFA setup is a required session task for all users. Enable authenticator-app TOTP and backup codes.
  SMS may be additional but must not be the only factor.
- Users with incomplete session tasks are `pending`. Pending sessions are treated as signed out and
  rejected from protected routes.
- Staging and production Clerk applications, publishable keys, JWT keys, Organization IDs, invitations,
  memberships, and authorized parties are isolated.

## Request authentication flow

1. A FastAPI dependency receives the request. It requires an explicit Bearer header and never logs the
   `Authorization` or cookie headers. Cookie-only authentication is rejected from meaningful APIs, so
   state-changing routes do not inherit ambient-cookie CSRF authority.
2. Configuration validates the backend publishable identifier for the environment. The current Clerk
   Python verifier is invoked with the local PEM JWT key, exact authorized parties, and accepted token
   type `session_token`; its options do not include the publishable identifier.
3. The verifier checks token structure, JWT header/algorithm, signature, expiry, not-before time, and
   authorized party without a JWKS network request.
4. Any non-authenticated, handshake, pending, or non-session result is denied. SDK and configuration
   exceptions are caught at the boundary and never become access.
5. Only after successful verification are the SDK-normalized identity and Organization values read.
6. A frozen Principal is constructed from the minimum fields below. The token, header, raw request,
   Clerk request state, and verifier message are discarded.
7. The exact required Headshot Organization ID is checked.
8. The route's required custom permissions are checked as an all-of set.
9. Approval paths reload the Organization-scoped authorization request and compare the authenticated
   approver with its immutable persisted launcher user ID. The request accepts only the request ID and
   decision—not a launcher identity. A database trigger repeats the separation check.
10. Live-campaign paths then enter the separate Policy Gateway. Authentication success cannot skip it.

The verifier's default clock-skew allowance must be accounted for in deterministic tests: expired and
not-yet-valid fixtures are placed comfortably outside the allowed skew, or the supported SDK option is
set explicitly.

## Verified claims and Principal

Raw session-token layouts may change between Clerk token versions. The application consumes the current
SDK-normalized verified payload rather than trusting decoded client JSON or parsing Clerk's compact
Organization object itself. The current boundary reads `sub`, `sid`, `exp`, optional `nbf`/`iat`/`sts`,
and the SDK-normalized `org_id`, `org_role`, and `org_permissions` fields.

| Verified semantic value | Use | Failure behavior |
|---|---|---|
| Token type | Must be `session_token` | `401` |
| `exp` / `nbf` | Token time validity | `401` |
| `azp` | Exact authorized-party check | `401` when present and not allowed |
| Session status (`sts`) | Reject `pending` sessions | `401` |
| User ID | Stable human identity and audit correlation | `401` if absent after successful verification |
| Session ID | Session-level audit correlation | `401` if absent after successful verification |
| Organization ID | Exact Headshot membership boundary | `403` if absent or wrong on an otherwise active session |
| Organization role | Assignment/audit context only | Never expanded into permissions |
| Organization custom permissions | Sole RBAC authority for backend operations | `403` when a required permission is absent |
| Actor/impersonation marker (`act`) | Disallowed because it cannot prove the human separation invariant | `403` |

The immutable Principal has exactly this security-relevant shape:

```text
Principal(
  user_id: str,
  session_id: str,
  organization_id: str,
  organization_role: str,
  organization_permissions: frozenset[str],
)
```

Its representation is safe to log only because it never stores the token or headers. Authentication
code still avoids logging the whole Principal by default; audit events select the minimum identifiers
needed for the event.

## Custom permissions and roles

Clerk system permissions are not included in session claims and are not backend authority. Configure
these custom permissions exactly:

- `org:console:read`
- `org:findings:read`
- `org:evidence:read`
- `org:campaign:launch`
- `org:campaign:abort`
- `org:campaign:authorize`
- `org:targets:manage`
- `org:config:manage`
- `org:findings:approve`
- `org:findings:resolve`
- `org:audit:read`

Assign them as follows:

| Role | Custom permissions |
|---|---|
| `org:operator` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:launch`, `org:campaign:abort`, `org:targets:manage`, `org:config:manage` |
| `org:approver` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:authorize`, `org:findings:approve`, `org:findings:resolve` |

The role set is intentionally limited to these two roles. Both roles can inspect the full protected
platform and audit history; action permissions remain least-privilege.

Role strings are never mapped to permissions in application code. If a token says
`org:approver` but its verified custom-permission set lacks `org:campaign:authorize`, authorization is
denied. If a request body says it has a permission absent from the verified token, it is ignored.

## FastAPI dependency semantics

| Helper | Contract |
|---|---|
| `require_authenticated()` | Return a verified immutable Principal; otherwise raise the generic authentication error |
| `require_headshot_organization()` | Require the exact configured Organization ID on an authenticated Principal |
| `require_permissions(*permissions)` | Require every named custom permission from the verified immutable set; empty or unknown dependency configuration is rejected |
| `require_distinct_approver(launcher_user_id, principal)` | Require the approval custom permission and prove `principal.user_id != launcher_user_id`. Both Principal and launcher ID come from server dependencies/request state, never request parameters or bodies. There is no role or self-approval exception. |

For a campaign authorization, the distinct approver must carry `org:campaign:authorize`. Finding
approval and resolution additionally use `org:findings:approve` and `org:findings:resolve` on their
respective endpoints. Both identities are persisted in the audit event. The FastAPI integration must
populate `request.state.launcher_user_id` only from the persisted workflow record after an
Organization-scoped server lookup; a request parameter, header, body, or browser state must never set it.

The integrated campaign-decision path performs the same rule inside the transactional control-plane
store rather than trusting a client-visible dependency input: it loads the request by verified
Organization and request ID, uses its stored launcher, and writes the authenticated approver. Revision
`0005` enforces the rule again in PostgreSQL. Queue state and queue completion are not inputs to this
decision and cannot manufacture an approval.

### Protected integration manifest

Every `/api/v1` endpoint requires an active Principal in the exact Headshot Organization. The read
dependencies are:

- console/campaigns/approvals/targets/configuration/components/costs/events:
  `org:console:read`;
- findings/coverage/resilience: `org:console:read` plus `org:findings:read`;
- evidence/traces: `org:console:read` plus `org:evidence:read`; and
- audit: `org:console:read` plus `org:audit:read`.

Mutation dependencies are exact: campaign request/launch `org:campaign:launch`, campaign decision
`org:campaign:authorize`, abort `org:campaign:abort`, finding decision
`org:findings:approve`, finding resolution `org:findings:resolve`, target/surface management
`org:targets:manage`, and configuration validation/publication `org:config:manage`. Every mutation
also requires a bounded `Idempotency-Key`. The complete method/path matrix and current availability are
in [M1d integration handoff](../planning/M1D_INTEGRATION_HANDOFF.md).

## Failure contract

Client responses are intentionally generic. Internal diagnostic reason codes may be counted, but raw
SDK messages are not returned or logged because the SDK request state can contain the token.

| Status | Conditions | Response rule |
|---:|---|---|
| `401 Unauthorized` | Missing/malformed token; expired or not-yet-valid token; invalid signature; `none` or unsupported algorithm; wrong authorized party; wrong token type; pending/handshake session; missing verified user/session identity | Generic authentication failure; no parsing detail or token echo |
| `403 Forbidden` | Active authenticated session has missing/wrong Organization; lacks custom permission; is an actor/impersonation session; launcher attempts self-approval | Generic authorization failure; do not reveal which other permissions exist |
| `503 Service Unavailable` | Clerk verifier/SDK initialization, PEM parsing, or security-configuration failure | Fail closed; alert operators using a non-sensitive reason code |

No fallback accepts an unverified token, calls a client role authoritative, fetches JWKS after local-key
failure, or disables the Organization/authorized-party checks.

## Browser and XSS handling

- Use Clerk's supported React components/SDK flow; do not implement a custom password or OAuth flow.
- The console uses `ClerkProvider`, restricted `SignIn`, explicit choose-Organization/setup-MFA/reset-
  password task routes, `useAuth({ treatPendingAsSignedOut: true })`, and request-time `getToken()`.
- Never persist a session token in `localStorage`, `sessionStorage`, IndexedDB, application state
  snapshots, service-worker caches, or analytics. Never put it in a URL or redirect parameter.
- Treat `VITE_CLERK_PUBLISHABLE_KEY` as public. No secret or private key may use a `VITE_` variable.
- Render finding/evidence strings through React's escaped text path. Raw adversarial HTML, SVG, Markdown
  HTML, and target output remain quarantined unless a reviewed sanitizer and explicit reveal workflow are
  used.
- Deliver a restrictive CSP and standard security headers from the Web/edge integration; avoid
  `unsafe-inline` and `unsafe-eval`. This is defense-in-depth, not a substitute for safe rendering.
- If Clerk session cookies authenticate state-changing requests, apply CSRF protection and strict CORS
  in addition to SameSite/secure cookie settings. `authorizedParties` and CORS do not replace CSRF or
  server-side permissions.
- The current `/api/v1` integration does not authenticate mutations from cookies: it requires the
  request-time bearer token. CORS remains an exact-origin defense-in-depth boundary.
- Event-stream and WebSocket authentication occurs before accepting the connection; validate the exact
  browser Origin and re-check permission for privileged messages/actions.

The event stream uses authenticated `fetch()` because native `EventSource` cannot attach the Bearer
header. Tokens in query strings are rejected before routing. Reconnect uses `Last-Event-ID`; payloads
carry redacted audit data, never credentials. Each connection is bounded by the verified JWT expiry
and a 30-second maximum lifetime, so permission/membership revocation is refreshed without retaining a
token in stream state.

## Logging, tracing, and redaction

Never record:

- the `Authorization` header or bearer token;
- the Clerk `__session` cookie or any cookie header;
- the full request headers, full Clerk request state, raw JWT, JWT signature, or SDK exception object;
- `CLERK_JWT_KEY` contents, even though it is public-key material; or
- invitation links, backup codes, or `CLERK_SECRET_KEY`.

Allowed structured audit fields are event type, outcome, stable reason code, request/correlation ID,
route template, environment, user ID when authentication succeeded, session ID only when operationally
required, Organization ID, required permission names, launcher user ID, approver user ID, and timestamp.
Apply the repository's centralized secret-redaction function before every logging/tracing sink.

Event streams and WebSockets use the same authentication and permission boundary before connection
acceptance. Never put a token in a URL, query string, SSE event, or WebSocket message.

## Revocation and permission freshness

Networkless verification validates the signed snapshot in the session token; it does not query Clerk
for current membership or permission state on every request. A removed permission, revoked membership,
or disabled user can therefore remain represented until Clerk refreshes or expires that token.

For MVP:

- use Clerk's short-lived session-token behavior and required MFA;
- keep critical effects behind the distinct-approver and Policy Gateway gates;
- record session/user IDs so incident response can identify affected actions; and
- document operator revocation and token-expiry expectations during provisioning.

Post-MVP hardening may require a maximum token age, step-up reauthentication, webhook-driven local
denial state, or an online Clerk freshness check for critical actions. Any online check must time out
and fail closed; it must not replace signature, Organization, permission, or identity-separation checks.

## Manual Clerk Dashboard checklist

Complete separately for staging and production and capture non-secret evidence. Never paste keys,
tokens, invitations, or backup codes into tickets or this repository.

- [ ] Create or select the environment-specific Clerk application.
- [ ] In **Restrictions**, enable Restricted mode; verify unaffiliated public sign-up is blocked.
- [ ] Enable Organizations and create the one required Organization named **Headshot**.
- [ ] Record its exact Organization ID in the matching environment's sealed variables.
- [ ] Disable Personal Accounts and confirm an incomplete Organization task leaves the session pending.
- [ ] Disable user-created Organizations; users can only join the administrator-controlled Headshot
      Organization.
- [ ] Enable required MFA as a session task for all users.
- [ ] Enable authenticator-app TOTP and backup codes; verify SMS is not the only enabled factor.
- [ ] Create exactly `org:operator` and `org:approver` and add them to the Headshot
      Organization's role set; remove any retired or demo roles.
- [ ] Create all eleven custom permissions and assign the exact matrix above.
- [ ] Confirm backend checks never depend on Clerk system permissions.
- [ ] Invite at least two different test humans so launcher/approver separation can be exercised.
- [ ] Assign least-privilege roles and verify a launcher cannot approve their own operation.
- [ ] From **API keys**, copy the environment's publishable key and PEM JWT public key into sealed
      variables. Do not add `CLERK_SECRET_KEY` for request authentication.
- [ ] Set exact HTTPS authorized parties for the Railway Web origin. Add loopback HTTP only to local.
- [ ] Prove staging rejects the production Railway origin and production Organization ID.
- [ ] Verify the enumerated shell routes (`/sign-in`, Clerk's nested sign-in route, and the three
      `/session-tasks/*` routes) against the provisioned Clerk application; verify every `/api/v1`
      route defaults protected.
- [ ] Run negative authentication, permission, redaction, and zero-network tests, then two-real-user
      Railway staging smoke tests, before changing status from local integration to deployed.

## Required automated tests

The authentication suite is offline and deterministic. It uses fixture RSA keys and locally signed
tokens; Clerk, Railway, target, model, JWKS, and other network requests are forbidden.

Coverage includes missing/malformed/expired/not-yet-valid tokens, invalid signatures, unsupported and
`none` algorithms, wrong authorized party, wildcard config rejection, wrong/missing Organization,
missing/correct custom permission, ignored client roles/permissions, token/header redaction, safe
Principal representation, production HTTP rejection, staging/production isolation, same-user approval
denial, distinct authorized approval, fail-closed verifier/configuration errors, and a suite-wide no-network
assertion.

## Official Clerk references

- [React quickstart](https://clerk.com/docs/react/getting-started/quickstart)
- [Request authentication](https://clerk.com/docs/reference/backend/authenticate-request)
- [Manual JWT verification](https://clerk.com/docs/guides/sessions/manual-jwt-verification)
- [Organization roles and permissions](https://clerk.com/docs/guides/organizations/control-access/roles-and-permissions)
- [Restrictions and allowlist](https://clerk.com/docs/authentication/allowlist)
- [Session tasks](https://clerk.com/docs/guides/configure/session-tasks)
