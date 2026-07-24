# Human and workload authorization model

## Status

The backend authentication, custom-permission checks, exact-Organization check, generic failure
semantics, and distinct-launcher/Approver rule are **implemented and locally tested**. The complete
real-environment Clerk Dashboard configuration and two-user deployed acceptance are **unavailable** and
are not release evidence in this packet.

This packet explicitly assumes a **single Headshot Clerk Organization**, not multi-customer SaaS.
Clerk is deliberately a human identity boundary only. A valid human session never grants permission
to attack a target by itself. The user has assigned Clerk the lowest current priority; that sequencing
does not relax or prove any Clerk control.

| Control | Candidate source | Live evidence |
|---|---|---|
| Networkless Clerk token verification and authorized-party validation | Implemented/tested | Older deployment returns 401 on protected routes; final candidate unavailable |
| Exact Headshot Organization and backend custom permissions | Implemented/tested | Exact real membership/permission acceptance unavailable |
| Invitation restriction, personal-org disablement, and MFA | Required Dashboard posture | Unavailable |
| Different Operator launcher and Approver | Implemented/tested, including database invariant | Two-real-user acceptance unavailable |
| Exact campaign authorization and Policy Gateway revalidation | Implemented/tested | Frozen-corpus final campaign unavailable |

## Human request path

1. The browser obtains a Clerk `session_token` and sends it in the Bearer `Authorization` header to
   same-origin Web.
2. Web verifies the token networklessly with the configured PEM key, rejects wildcard authorized
   parties, and requires the exact environment-specific Headshot Organization.
3. Web reduces verified claims to an immutable Principal containing only minimal identifiers and the
   immutable custom Organization permission set.
4. The endpoint checks the exact backend permission. Frontend labels, request-body roles,
   client-supplied permissions, and Clerk system permissions are not authority.
5. A campaign authorization decision must be from a different user than the persisted launcher.
6. The Policy Gateway independently verifies the exact target and surface, allowlist, corpus hash,
   execution profile, authorization expiry/nonce, credential binding, synthetic-data assertion,
   budget, rate, logical/physical limits, retries, timeout, monitoring, and abort before every target
   send.

Missing/invalid authentication returns generic 401. A valid session missing the required Organization
or custom permission returns generic 403. Auth verifier/configuration failure returns 503 and denies
the operation. The implementation is documented in
[`../../security/AUTHENTICATION.md`](../../security/AUTHENTICATION.md).

## Backend custom permissions

| Human role | Custom permissions accepted by backend | Cannot do |
|---|---|---|
| Operator `org:operator` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:launch`, `org:campaign:abort`, `org:targets:manage`, `org:config:manage` | Authorize a campaign; approve/resolve a finding merely because the role label says Operator |
| Approver `org:approver` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:authorize`, `org:findings:approve`, `org:findings:resolve` | Approve their own launch; bypass the Policy Gateway; publish/remediate without the applicable gate |

The source of these exact constants is
[`../../../src/agentforge/auth/permissions.py`](../../../src/agentforge/auth/permissions.py), and
the route-to-permission dependencies are in
[`../../../src/agentforge/api/router.py`](../../../src/agentforge/api/router.py).

## Campaign authorization envelope

The persisted operation hash binds the whole immutable run identity:

- target identity and exact HTTPS host;
- adapter kind and auth mode;
- digest of the target credential reference or explicit no-auth marker;
- corpus ID and exact corpus SHA-256;
- run nonce and expiry;
- budget, rate, attempt, logical-case, physical-request, retry, and timeout caps; and
- when hosted roles are used, configuration-set hash, generation-policy hash, session generation,
  provider call/spend limits, retry/concurrency ceiling, provider timeout, and exact role
  model/provider/token-parameter identities.

Changing any bound field produces a different hash and invalidates the approval. A configured service,
loaded credential, Clerk login, queue job, scheduler plan, or frontend button does not create campaign
authority.

The `release_sha256` field is schema/format checked, not independently proven to name the deployed
commit by that field alone. Final staging must populate it from an immutable saved source/image
artifact and independently reconcile it with the GitHub/GitLab commit and Railway deployment
identity. An arbitrary 64-character label is not acceptable release evidence.

## Workload authorization and credentials

| Principal/component | May call | Credential access | Storage authority |
|---|---|---|---|
| Web | PostgreSQL; Clerk token verifier is local/networkless | Clerk public verification/configuration material; no target/model/Langfuse secret | Organization-scoped commands and projections; permission-gated |
| Scheduler | PostgreSQL only | Database binding only | Create idempotent blocked replay plans and heartbeat; no attack execution |
| Runner | PostgreSQL, model provider, Langfuse, Policy Gateway/target adapter | Resolves provider, Langfuse, and exact target credential references at the owning boundary | Claims jobs; writes lifecycle, evidence, verdict, finding/report, and accounting rows through reviewed repositories |
| Orchestrator | Verified Postgres projection; hosted model only through Runner lifecycle when configured | No target credential | Read verified signals; emit bounded directive/execution record |
| Red Team | Hosted model only through Runner lifecycle when configured | No target credential; no target adapter | May propose/quarantine variants; exact target dispatch remains the reviewed corpus; no authoritative evidence write |
| Policy Gateway + Recorder | Exact allowlisted target adapter | Sole release point for target-scoped credential | Recorder appends authoritative AttemptResult and request ledger |
| Judge | Hash-verified evidence; hosted model only through Runner lifecycle when enabled | No target credential, mutation tool, or publication credential | Read evidence; deterministic oracles decisive; identity-drifted model remains advisory/fail-closed |
| Documentation | Confirmed sanitized evidence; hosted model only through Runner lifecycle when configured | No target credential or publication credential | Draft-only report/disposition path; publication remains human-gated |
| Langfuse projector | Langfuse Cloud | Runner-only environment keypair | Observability projection only; cannot mutate campaign evidence or authority |

The foundational database grant matrix is
[`../../../src/agentforge/storage/roles.sql`](../../../src/agentforge/storage/roles.sql). Later
migrations add narrowly scoped Web, Runner, and Scheduler grants and database triggers. Database
ownership/administrator access remains a trusted infrastructure boundary; the per-agent role model is
not claimed to protect against a fully compromised database administrator.

## Public routes

Only liveness, readiness, compiled static assets, and the minimal non-data sign-in/session-task shell
may be public. Every `/api/v1` route is protected by default. Evidence, findings, campaigns,
approvals, configuration, audit, events, and observability data are not public. Event streams require
authentication, `org:console:read`, same-origin browser provenance, a bounded cursor, and periodic
re-authentication. Read-only Railway review confirms that Web is the only public service and that the
older release denies an unauthenticated protected request; it does not prove the final candidate's
real Clerk flow.

## Live verification still required

Before this control family can be marked live-verified, staging must demonstrate exact Headshot
membership/custom permissions, denial for wrong Organization/missing permission, distinct real
Operator and Approver identities, and a normal UI/API flow that cannot bypass campaign authorization.
The user has identified Clerk as a lower-priority workstream; that priority does not convert the
unverified state into evidence. If Clerk acceptance remains incomplete, the campaign and release
scorecard must say **blocked/unavailable** rather than use demo authentication or a bypass.
