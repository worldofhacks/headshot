# Headshot Operator Console

Authenticated React/Vite console for the AgentForge control plane. It preserves the frozen
titanium-and-ceramic visual system while replacing all sample state with protected same-origin
`/api/v1` reads, commands, and ordered events.

Status: integration code is present, but external Clerk and Railway configuration is still
required. A surface whose authoritative repository or service is absent renders a typed
`unavailable` state. The console never substitutes sample records or local command success.

## Local checks

Requires Node `^20.19 || >=22.12`.

```bash
cd console
npm ci --ignore-scripts
npm audit --omit=dev
npm run typecheck
npm test
npm run check:forbidden
npm run build
npm run check:bundle
```

`VITE_CLERK_PUBLISHABLE_KEY` is the only console environment value. It is a public Clerk
identifier, not a secret. The secret key, JWT verification key, database credentials, target
credentials, and provider keys must never enter the browser build.

For an authenticated local flow, configure the matching backend Clerk values and serve the built
assets through the FastAPI Web process. `npm run dev` is useful for CSS/component work, but no
cross-origin development proxy is provided: API requests deliberately remain on the browser's
current origin.

## Identity boundary

- `@clerk/react` 6.12.6 is pinned. `@clerk/clerk-js` and `@clerk/ui` are also pinned and bundled,
  so sign-in UI does not require a runtime JavaScript CDN.
- Sign-up is not offered. Access is invitation-only and Clerk Dashboard policy remains the
  authority for enrollment, required MFA, and the required organization.
- Pending session tasks have dedicated choose-organization, MFA-setup, and password-reset routes.
- Impersonated and degraded identity sessions fail closed in the console. FastAPI independently
  verifies every request and remains the final authority.
- A fresh Clerk session credential is retrieved for every request. It is held only long enough to
  construct the in-memory `Authorization` header and is never persisted, logged, placed in a URL,
  or copied into application state.

The frontend displays the immutable principal and capabilities returned by `/api/v1/principal`.
Capabilities may courtesy-disable a control; they never authorize it. Roles, request bodies,
headers, cookies, or labels supplied by the browser have no authority.

## Routes

The direct-route contract is:

```text
/live                  /live/:attempt
/findings/:finding     /approvals/:request
/coverage              /resilience
/traces                /costs
/targets               /config
/sign-in
/session-tasks/choose-organization
/session-tasks/setup-mfa
/session-tasks/reset-password
```

History navigation uses the browser History API. FastAPI supplies the SPA fallback only for
unknown non-API `GET` paths; `/api/*`, `/health`, and `/ready` are never rewritten to HTML.

## Data and command boundary

Every protected read consumes the server envelope:

```text
ready | empty | unavailable | stale | degraded | error
```

The browser adds only a transient `loading` state. Adversarial request/response material is
rendered through escaped React text nodes. No raw HTML sink is used.

Commands use the exact `/api/v1` routes, fetch a fresh session credential, add a client-generated
`Idempotency-Key`, wait for a server acknowledgement, and then refresh authoritative state. There
are no optimistic campaign, approval, finding, target, or configuration mutations. An ambiguous
transport failure reuses the same key for the same path/payload; the key changes only when the logical
action changes. Launcher
identity is never sent in a decision body. The server enforces organization scope, custom
permissions, immutable operation hashes, and the two-person rule.

The ordered event feed uses authenticated `fetch()` streaming because native `EventSource` cannot
set an authorization header. Reconnect uses `Last-Event-ID`; stream credentials never enter query
parameters. The client bounds retained events, detects gaps, and refreshes the read projections.
The server closes the stream at token expiry or after 30 seconds, whichever comes first, so reconnect
must present a fresh request-time token and permission set.

## Honest unavailable features

The current backend explicitly reports missing repositories for findings/evidence joins,
regression history, persisted traces, measured accounting, component heartbeats, and configuration
snapshots. Related screens and controls remain visible as typed unavailable states until those
dependencies exist. Target authoring and revision controls likewise require a trusted server-side
catalog; the console does not accept arbitrary hosts, adapters, credentials, or endpoints.

## Safety

Authentication is not campaign authorization. A campaign still requires a persisted exact-scope
authorization request, a distinct authenticated approver, and a server-authorized launch. Queue
completion is never approval. The browser never computes verdicts, integrity, readiness, coverage,
or approval. No real PHI belongs in this platform; use synthetic fixtures only.
