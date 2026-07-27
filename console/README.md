# Headshot Operator Console

Authenticated React/Vite console for the AgentForge control plane. It preserves the frozen
titanium-and-ceramic visual system while replacing all sample state with protected same-origin
`/api/v1` reads, commands, and ordered events.

Status (updated 2026-07-26): the existing console is deployed to Railway staging; this operations
candidate is built and integrated but **not yet deployed**. The public Web tier at
`https://web-staging-8e30.up.railway.app` serves the prior console shell and protected same-origin
API; `/health` and `/ready` return `200`, and an unauthenticated protected API request returns `401`.
Private Web/Runner/Scheduler code-policy hashes agree and staging PostgreSQL remains at Alembic
`0025`; the candidate package has sole head `0026`.

Governed campaigns now produce real hosted-agent and target records. The latest 34-case run stopped at
case 12 on schema-invalid Judge output. Its 36 agent and 16 target rows remain `queued` for Langfuse
query-back because the current verifier rejects failed campaigns. Signed-in real-user Organization,
permission, MFA, cross-Organization, and two-person acceptance remains a human audit. Production is
reachable but release-skewed and must not run campaigns. See `../docs/CURRENT_STATE.md`.

A surface whose authoritative repository or service is absent still renders a typed `unavailable`
state. The console never substitutes sample records or local command success.

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

Primary navigation is exactly Runs, Findings, Coverage, Approvals, Observability, and System. Their
workspace grouping is:

- Runs: Operations, Targets.
- Findings: Findings, Reports.
- Observability: Traces, Costs.
- System: Agents, Tool inventory, Configuration.

The canonical and preserved deep-link route contract is:

```text
/runs                  /runs/:campaign
/findings              /findings/:finding
/coverage              /approvals
/observability         /observability/:campaign
/system

# preserved aliases/deep links
/live                  /live/:attempt
/findings/:finding     /approvals/:request
/reports               /reports/:report
/resilience
/traces                /traces/:campaign
/costs                 /costs/:campaign
/targets               /targets/:campaign
/agents
/tooling               /config
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

## Observability views

Runs opens the authoritative campaign operations view. It reports only backend facts for planned,
started, running, completed, failed, skipped, and remaining cases; logical attempts; physical target
requests; provider calls; current stage/agent/attempt; measured provider/target/total costs; exact
limits; queue state; verdict distribution; and terminal failure/retryability. Missing values stay
Unknown, Unavailable, or Partial. The same live operations projection backs Targets and active-run
surfaces.

Observability's Traces view visualizes the durable request ledger correlated to Langfuse: transport
status, endpoint metadata, latency, volume, measured cost, and export state. Costs visualizes
campaign spend, approved budget utilization, cost per request, duration, and reconciliation between
campaign summaries and physical ledgers. Both receive the selected campaign explicitly so an older
campaign is not lost outside a bounded global projection.

The event feed invalidates affected cached projections after each authenticated event, reconnects
with `Last-Event-ID`, and falls back to five-second polling when streaming is unavailable. Last valid
data remains visible with freshness/staleness state.

An expanded execution can fetch its immutable prompt snapshot only with `org:evidence:read`.
System-prompt and ordered provider-message contents stay collapsed by default; no prompt is included
in list, aggregate, SSE, log, or Langfuse payloads.

PostgreSQL is authoritative and Langfuse is a fail-soft external projection. The console does not
query Langfuse with browser credentials. Hosted provider token/cost facts come from provider responses
and physical-call records; target-call accounting is a separate contracted value. SDK flush is not
remote proof, so `queued` remains visible until exact query-back.

## Honest unavailable features

Target authoring and revision controls require a trusted server-side catalog; the console does not
accept arbitrary hosts, adapters, credentials, or endpoints. Any repository or integration that is
not composed remains visible as a typed unavailable state rather than falling back to sample data.

## Safety

Authentication is not campaign authorization. A campaign still requires a persisted exact-scope
authorization request, a distinct authenticated approver, and a server-authorized launch. Queue
completion is never approval. The browser never computes verdicts, integrity, readiness, coverage,
or approval. No real PHI belongs in this platform; use synthetic fixtures only.
