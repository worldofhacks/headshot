# M1d authenticated console and Railway integration handoff

> **Status — 2026-07-21:** this branch contains a local, offline-testable M1d integration
> foundation. It is **not deployed**, is not verified with real Clerk users, and is not a fully live
> campaign system. Railway and Clerk resources were not created or changed, and no target, model, or
> provider was contacted.

## Integrated lineage

The integration branch is based on `211665dfb024f169a1d3e2daa8f1dc96864d29cd` and preserves the
reviewed dependency histories:

| Dependency | Integrated commit |
|---|---|
| Target-agnostic core (PR #7) | `8fc27066f6263db27c84c3a4dd81338c45a3ba74` |
| Durable queue (PR #8) | `53ce4586385d3dee97c1444c732a4a227010b876` |
| Campaign coordinator (PR #9) | `43b0cee2b0b08b3c60ac4de76c8ec85fc39231a3` |
| Clerk foundation (PR #10) | `4023edf0537ab9edf1217607bb52a54e79dd6b77` |
| Frozen console (PR #11) | `96033b33c1135c63340be4b66d119e795c9089ca` |

PR #8's reviewed Git commit is the 40-character value above. The shorter value in the task prompt was
not a valid complete object name.

The integrated Alembic head is `0005`, directly after `0004`. Revision `0005` adds organization-scoped,
append-only target/surface snapshots and state events, campaign authorization requests and decisions,
campaign run/attempt state, finding-decision primitives, idempotency records, and audit events. Database
triggers enforce append-only history, persisted-launcher separation, exact authorization scope, and
approved-scope launch constraints.

## What is composed locally

- One FastAPI Web process serves the built React SPA and `/api/v1` from the same origin. `/health` is
  liveness-only; `/ready` checks PostgreSQL, the exact Alembic head, the packaged console, and local
  Clerk/Web security configuration without contacting Clerk, a target, or a model.
- The browser uses `@clerk/react` and asks Clerk for a session token at request time. Tokens are sent
  only as `Authorization: Bearer …` to same-origin protected APIs and are not put in application
  persistence or URLs. Pending sessions and actor/impersonation sessions remain closed.
- FastAPI independently verifies only Clerk `session_token` values with `CLERK_JWT_KEY`, exact
  `authorizedParties`, and the exact Headshot Organization before checking custom permissions.
- PostgreSQL-backed API projections are scoped by the immutable Principal's verified Organization ID.
  Reads return typed `ready`, `empty`, `unavailable`, `stale`, `degraded`, or `error` envelopes; the
  browser adds only transient `loading`.
- Commands require a 16–128-character `Idempotency-Key`, return a server acknowledgement, and never
  update the UI optimistically. The console reuses one key across ambiguous retries of the same
  path/payload and rotates it only when the logical action changes. Persisted control-plane mutations
  append audit events.
- The ordered event endpoint is bearer-authenticated fetch streaming, not native `EventSource`. It
  validates the exact browser origin, forbids tokens in query strings, uses `Last-Event-ID`, and emits a
  reconciliation snapshot marker, ordered audit deltas, gap markers, and heartbeats with bounded pages.
  A connection closes by verified token expiry or after 30 seconds, whichever comes first, forcing a
  fresh request-time token and permission evaluation on reconnect.
- The private runner and scheduler have process entrypoints but no HTTP listeners. Both deliberately
  refuse startup while their trusted compositions are absent.

This is integration infrastructure, not proof that the external environment is operational.

## Public authentication dependencies

| Dependency | Reviewed pin/use |
|---|---|
| `clerk-backend-api` | `6.0.1`; networkless Python request authentication |
| `@clerk/react` | `6.12.6`; `ClerkProvider`, `useAuth().getToken()`, sign-in and session-task UI |
| `@clerk/clerk-js` | `6.25.6`; locked transitive/frontend runtime compatibility |
| `@clerk/ui` | `1.25.6`; locked Clerk UI compatibility |

`VITE_CLERK_PUBLISHABLE_KEY` is public. No `VITE_` variable may contain a secret.
`CLERK_SECRET_KEY` is intentionally absent from request-authentication code and configuration. A later
server-only Clerk Backend API feature may add it as a sealed variable only after an explicit review.

## Environment contract

| Variable or build argument | Consumer | Contract |
|---|---|---|
| `AGENTFORGE_ENVIRONMENT` | Web, auth, control plane | Exactly `local`, `staging`, or `production` |
| `DATABASE_URL` | Web, runner/scheduler composition, migrations | Environment-private PostgreSQL DSN; never exposed to the browser |
| `PORT` | Web | Railway-assigned decimal port; defaults to `8000` locally |
| `VITE_CLERK_PUBLISHABLE_KEY` | Console build argument | Public environment-specific Clerk key; required at image build |
| `CLERK_PUBLISHABLE_KEY` | Backend auth config | Public backend copy; environment prefix must match |
| `CLERK_JWT_KEY` | Backend auth verifier | Complete PEM public key for offline RS256 verification |
| `CLERK_AUTHORIZED_PARTIES` | Auth, CORS, stream-origin check | Comma-separated exact browser origins; no wildcard; deployed values are HTTPS |
| `CLERK_REQUIRED_ORG_ID` | Backend auth | Exact environment-specific Headshot Organization ID |
| `CLERK_PRODUCTION_AUTHORIZED_PARTIES` | Staging isolation guard | Production origins staging must reject |
| `CLERK_PRODUCTION_ORG_ID` | Staging isolation guard | Production Organization ID staging must reject |
| `CLERK_FRONTEND_API_ORIGIN` | Web CSP | Exact HTTPS Clerk Frontend API origin; required when deployed |
| `AGENTFORGE_MAX_REQUEST_BYTES` | Web request boundary | Integer from 1 KiB through 10 MiB; defaults to 1 MiB |
| `AGENTFORGE_CONSOLE_DIR` | Web/readiness | Optional built-asset directory; image default is `/app/console` |
| `ALEMBIC_CONFIG` | Readiness/migrations | Optional path; image default is `/app/alembic.ini` |

Do not set `AGENTFORGE_RUNNER_EXECUTION_READY` or `AGENTFORGE_SCHEDULER_READY` to bypass the current
refusal: neither flag composes the missing trusted service. The code still exits unavailable.

## Expected FastAPI dependency signatures

M1d consumes the M1c public surface without accepting client authority:

```python
def require_authenticated(request: Request, config: ClerkAuthConfig = Depends(...)) -> Principal: ...
def require_headshot_organization(
    principal: Principal = Depends(require_authenticated),
    config: ClerkAuthConfig = Depends(...),
) -> Principal: ...
def require_permissions(*required_permissions: str) -> Callable[[Principal], Principal]: ...
def require_distinct_approver(
    launcher_user_id: str = Depends(server_only_workflow_lookup),
    principal: Principal = Depends(require_headshot_organization),
) -> Principal: ...
```

The persisted workflow lookup must supply `launcher_user_id`; a body, header, query parameter, URL
segment, cookie, or browser state must never supply it. In the integrated control plane, the approval
command accepts only the authorization request ID and decision. It reloads the organization-scoped
request and compares the authenticated approver with the immutable stored launcher. The database repeats
that check. Queue completion has no path to create a human approval.

## `/api/v1` endpoint and permission matrix

All routes below require a verified, active session in the exact configured Headshot Organization.
Permissions are all-of custom Clerk Organization permissions. Role text is never authority.

| Method and path | Required custom permission(s) | Current authoritative behavior |
|---|---|---|
| `GET /principal` | `org:console:read` | Verified Principal and capabilities |
| `GET /campaigns`, `/campaigns/{id}`, `/campaigns/{id}/attempts` | `org:console:read` | Organization-scoped persisted runs and attempts |
| `GET /attempts/{id}/evidence` | `org:console:read`, `org:evidence:read` | Persisted attempt result/evidence and verdict projection |
| `GET /findings`, `/findings/{id}` | `org:console:read`, `org:findings:read` | Typed unavailable: authoritative finding-to-evidence relation is absent |
| `GET /approvals` | `org:console:read` | Persisted campaign authorization requests and decisions |
| `GET /coverage` | `org:console:read`, `org:findings:read` | Typed unavailable until the projection proves both hash verification and nonce deduplication |
| `GET /resilience` | `org:console:read`, `org:findings:read` | Typed unavailable: regression-history repository is absent |
| `GET /traces` | `org:console:read`, `org:evidence:read` | Typed unavailable: persisted trace repository is absent |
| `GET /costs` | `org:console:read` | Typed unavailable: measured accounting repository is absent |
| `GET /targets`, `/targets/{id}` | `org:console:read` | Immutable target/surface versions and current state; credential presence only, never values |
| `GET /configuration` | `org:console:read` | Typed unavailable: configuration snapshot repository is absent |
| `GET /components` | `org:console:read` | Typed unavailable: heartbeat repository is absent |
| `GET /audit` | `org:console:read`, `org:audit:read` | Organization-scoped append-only audit history |
| `GET /events` | `org:console:read` | Authenticated, origin-checked ordered audit stream |
| `POST /campaign-authorization-requests` | `org:campaign:launch` | Persists canonical exact-scope request and immutable launcher |
| `POST /campaign-authorization-requests/{id}/decisions` | `org:campaign:authorize` | Persists exact-scope decision; rejects stored launcher self-approval |
| `POST /campaigns` | `org:campaign:launch` | Typed unavailable until trusted runner execution is composed |
| `POST /campaigns/{id}/abort` | `org:campaign:abort` | Persists abort state/audit and cancels queued work |
| `POST /findings/{id}/decisions` | `org:findings:approve` | Typed unavailable until finding/evidence relation exists |
| `POST /findings/{id}/resolve` | `org:findings:resolve` | Typed unavailable until finding/evidence relation exists |
| `POST /targets`, `/targets/{id}/versions` | `org:targets:manage` | Typed unavailable: a trusted server-side authoring catalog is absent; browser hosts/adapters/credential references have no authority |
| `POST /targets/{id}/lifecycle` | `org:targets:manage` | Append-only lifecycle transition for an existing immutable server-authored target version |
| `POST /targets/{id}/surfaces`, `/targets/{id}/surfaces/{surface_id}/versions` | `org:targets:manage` | Typed unavailable: a trusted server-side surface catalog is absent; browser endpoints have no authority |
| `POST /targets/{id}/surfaces/{surface_id}/state` | `org:targets:manage` | Append-only enable/disable transition for an existing immutable server-authored surface version |
| `POST /live-probe-authorization-requests` | `org:campaign:authorize` | Typed unavailable: distinct probe-authorization workflow is absent |
| `POST /configuration/validate`, `/configuration/publish` | `org:config:manage` | Typed unavailable: configuration snapshot/validation repository is absent |

Every POST requires `Idempotency-Key`. Campaign authorization hashes the resolved target and surface,
endpoint/method/auth posture, corpus hash, caps, and nonce. Any mutation changes the hash and invalidates
approval.

## Console source-of-truth matrix

| Screen | Current authoritative source | Explicit unavailable state |
|---|---|---|
| Live | Campaigns, attempts, evidence, abort state, and ordered audit events from PostgreSQL | Runtime component heartbeats; campaign-request control until a server-prepared composition scope is available; launch while runner composition is absent |
| Findings | Protected findings endpoint | Finding list/detail and publication/resolution until a finding-to-evidence relation exists |
| Approvals | Persisted authorization requests/decisions and immutable launcher identity | Campaign launch until runner composition exists |
| Coverage | Protected findings-scoped endpoint | Verified coverage remains unavailable until an Organization-scoped projection proves content-hash reconciliation and nonce deduplication; no totals/readiness are invented |
| Resilience | Protected resilience endpoint | Regression/version history repository is absent |
| Traces | Protected evidence-scoped traces endpoint | Persisted/OTEL trace repository is absent |
| Costs | Protected costs endpoint | Measured accounting repository is absent; no token-times-price estimate is substituted |
| Targets | Immutable server-authored target/surface snapshots and append-only lifecycle/state history | Target/surface authoring until a trusted catalog exists; live probe authorization until its distinct workflow exists |
| Configuration | Protected configuration and audit endpoints | Immutable configuration snapshots, validation, publication, and effective config are absent |
| Birdseye/runtime health panel on Live | Protected components endpoint | Component registration/heartbeat repository is absent |

The console contains no production demo dataset, synthetic tick/spawn loop, random success, principal
switcher, locally calculated verdict/integrity/readiness, or optimistic command completion. A disabled
control names its missing dependency.

## External and integration blockers

1. Provision isolated staging and production Railway environments with only Web public and with private
   runner, scheduler, and PostgreSQL; inject sealed variables, run `alembic upgrade head`, and verify
   `/health`, `/ready`, rollback, and private-service exposure.
2. Configure separate Clerk applications: Restricted enrollment, one exact Headshot Organization,
   Personal Accounts and user-created Organizations disabled, required TOTP plus backup-code MFA, exact
   roles/custom permissions, exact origins, and two distinct invited test users.
3. Implement and review a target-bound credential-value resolver plus surface-bound adapter/executor
   composition. Execution must recheck authorization, target lifecycle, surface state, and persisted
   abort before every outbound dispatch, use attempt-granular idempotent completion, and give active
   work a bounded cancellation signal. Until then the private runner and campaign launch remain
   fail-closed unavailable; a campaign-level queue row is not sufficient proof.
4. Add the authoritative campaign-composition source that supplies a server-prepared canonical request
   scope to the console; do not reconstruct it from client-owned role/permission or target authority.
5. Add a trusted server-side target and surface authoring catalog/provisioning workflow. The HTTP
   boundary must never turn browser-supplied hosts, adapters, credential references, or endpoints into
   dispatch authority; only lifecycle and enable/disable transitions are currently exposed as writes.
6. Add an authoritative schedule repository and queue composition. Until then scheduler startup remains
   unavailable and no scheduled work is fabricated.
7. Add a persisted finding-to-evidence relationship before finding reads, approval, publication, or
   resolution can become authoritative.
8. Add repositories for persisted traces, measured cost/accounting, immutable configuration snapshots,
   component heartbeats, regression/resilience history, and the distinct live-probe workflow.
9. Perform staging verification with two real Clerk users: authenticated API and fetch-stream access,
   self-approval denial, exact-scope approval and launch flow, cross-Organization denial, token
   redaction, and Railway exposure/readiness tests.
10. Conduct a separate, explicitly authorized live-target gate before any target or model request.

Production must continue to fail closed whenever Clerk configuration, Organization membership,
authorized parties, required permissions, exact approval scope, or the downstream safety gate is
invalid. Authentication identifies and authorizes the human application action; it never authorizes an
attack by itself.
