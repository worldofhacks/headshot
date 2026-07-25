# Headshot / AgentForge

Headshot is a reusable multi-agent adversarial evaluation platform for AI applications. Its first
target is the externally deployed OpenEMR Clinical Co-Pilot. Headshot reaches that target over an
authorized live URL; the target's source code is not part of this repository.

> **Delivery status — 2026-07-25:** the Clerk-backed React console, protected FastAPI `/api/v1`,
> organization-scoped PostgreSQL control plane, private Runner, live target adapter, and Langfuse
> telemetry projection are implemented; the packet preparation base has the sole Alembic head
> `0021_four_role_agent_acceptance`, and the intended release adds incoming `0022`. Candidate
> `2069036e` is deployed to **staging** Runner-first
> across Runner, Web, and Scheduler, with the database at `0021`. The public Web health/readiness,
> unauthenticated protection boundary, and console/sign-in shell were smoke-tested. No staging
> campaign or provider/target call ran, and no signed-in Clerk user, organization, permission, or MFA
> flow was audited. **Production remains unverified.** An earlier authorized, synthetic-only campaign
> ran against the live Co-Pilot target by a direct script; every verdict it produced is
> `INDETERMINATE` and **no exploit has ever been confirmed** — see
> [Red-teaming coverage review (2026-07-25)](docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md).
> Live campaigns remain bounded by persisted exact-scope authorization, synthetic-only evidence,
> rate/budget/timeout caps, and abort controls.

| Endpoint | URL | Verification status |
|---|---|---|
| Staging platform | `https://web-staging-8e30.up.railway.app` | **Infrastructure smoke verified** — `/health` 200, `/ready` 200, protected unauthenticated request 401, console/sign-in shell 200; no signed-in audit or campaign |
| Production platform | `https://web-production-44528.up.railway.app` | **Older release** — `23490ea` / `0013`; final candidate not deployed |
| Authorized live target | `https://agent-production-9f62.up.railway.app` | **Reached** — owner-authorized; live HTTP evidence in `evals/results/` and `docs/evidence/zap/` |

The two platform rows are recorded here because a deployed URL is submitted with every checkpoint.
Staging records only the completed infrastructure smoke; it is not evidence of a signed-in Clerk
flow, a governed campaign, live model calls, or target calls. Production identifies the older
release only, not the final candidate. See the dated evidence record and remaining promotion gates in
[`docs/deployment/RAILWAY.md`](docs/deployment/RAILWAY.md).

## What the candidate implements

- A FastAPI API and React console backed by organization-scoped PostgreSQL records. Read models use
  explicit `ready`, `empty`, `unavailable`, `stale`, `degraded`, and `error` states; the browser does
  not fabricate successful data.
- A durable `SKIP LOCKED` PostgreSQL queue, campaign state machine, lease/heartbeat/reaper behavior,
  dead-letter handling, command idempotency, and append-oriented audit/events.
- A trusted server catalog plus exact-scope campaign authorization. The operation hash binds the
  target and surface versions, literal host and allowlist, adapter/auth mode, synthetic-data
  assertion and attestation, corpus identity/hash, budget, logical/physical request caps, target
  rate, retry policy, timeout, hosted configuration, and nonce.
- Four distinct runtime roles: Orchestrator, Red Team, independent Judge, and Documentation. The
  deterministic Runner path records their real ordered executions; Documentation runs only when a
  confirmed finding exists.
- Hosted OpenRouter configuration, transport, provider/model lineage, token/retry/cost accounting,
  and role adapters. At this source baseline the campaign Runner can host the Orchestrator, Judge,
  and Documentation roles. A traced Qwen Red Team generation component exists and is tested, but it
  is not yet wired into the reviewed-candidate/fresh-authorization campaign loop. It must not be
  described as a deployed fourth hosted agent.
- Deterministic-oracle precedence. Oracle/canary confirmation and evidence errors are decisive.
  A model Judge is advisory unless the exact Judge identity has a valid, enabled calibration
  artifact. Failed or unavailable calibration does not convert an exploit into a safe result.
- PostgreSQL-authoritative agent and physical-request accounting plus Langfuse Cloud projection.
  Agent observations carry parent/run/attempt identity, provider/model, latency, tokens, retries,
  errors, and measured cost when supplied. Raw credentials and evidence bodies are not exported.
  An SDK flush remains `queued`; only exact remote query-back can mark a row `exported`.
- An ATO-style packet, integration packet, migration notes, and evidence-classification rules. They
  deliberately leave final release, live campaign, performance, cost, demo, and social evidence
  pending where it does not yet exist.

## Current release gates

- Integrate and independently review the final security corpus/Judge evidence without changing its
  owner-authored conclusions.
- Deploy one exact final commit to staging, apply the single latest migration head, and pass GitHub
  Actions on that exact commit.
- Run one separately authorized, synthetic-only campaign through the normal Web/API and private
  Runner. The deployed trace must prove ordered roles, target requests, findings/report behavior,
  and provider lineage.
- Query Langfuse Cloud back and reconcile exact observation IDs and values against PostgreSQL.
- Publish the authorized 100-case performance evidence, final numeric cost analysis, demo URL, and
  social-post URL.
- Confirm the real Clerk role assignments and two-user flow before claiming live RBAC proof. The
  backend controls are implemented and tested, and deployed protected routes return `401`, but the
  external role proof remains pending and is not a substitute for campaign authorization.
- Bind an immutable image digest and compatible rollback image, prove the exact candidate on staging,
  then promote Runner-first to production. This synthetic assignment does not require a database
  backup artifact; additive migrations, quiescence, staging proof, and compatible image rollback are
  the release controls.

### Canonical source of truth

Three documents govern; everything else derives from them. When a document disagrees with one of
these, the canonical document wins — and when one of these disagrees with the code, the code wins and
the drift is recorded rather than papered over.

| Document | Governs |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The binding architecture: agent roster, trust boundaries, contracts, cost model shape, deployment, AI-use disclosure |
| [docs/planning/DECISIONS.md](docs/planning/DECISIONS.md) | The numbered decision log, D1–D26, with each decision's rationale, fallback, and invalidation condition |
| [docs/cost/COST_ANALYSIS.md](docs/cost/COST_ANALYSIS.md) | The cost model: three independent cost families on different scaling functions, scaled in complete test runs at 100 / 1K / 10K / 100K |

Current honest status of the red-team capability itself lives in
[docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md](docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md),
which supersedes the 2026-07-24 review.

## Safety invariants

- Only synthetic data is permitted. Real PHI is forbidden in fixtures, prompts, evidence, logs,
  traces, reports, screenshots, and demonstrations.
- The Red Team proposes input; it does not hold a target credential, mint authoritative evidence,
  judge an outcome, or publish a finding.
- The Policy Gateway and Execution Recorder are the only target exit and evidence-authoring
  boundary. Every physical request is independently reserved, revalidated, capped, and recorded.
- Deterministic evidence outranks a model assessment. `INDETERMINATE` and `ERROR` never mean safe.
- Human authentication never authorizes a campaign. A live run still needs the complete
  authorization envelope and a distinct approval decision.
- Critical publication and remediation remain human-gated. Documentation creates drafts, not
  autonomous publication.

## Railway topology

The full platform topology is deployed and smoke-tested in Railway staging. The current release still
requires production promotion. Web, Runner, Scheduler, and PostgreSQL are separate services in each
environment; only Web may receive public ingress.

| Service | Ingress | Responsibility |
|---|---|---|
| Web | Public HTTPS | React shell, FastAPI, authentication/permission checks, command/read APIs, health/readiness |
| Runner | Private | Claims campaign jobs, resolves sealed references, runs agent work, sends authorized target/provider traffic, records evidence |
| Scheduler | Private | Detects target-version changes and records authorization-blocked replay plans; it does not attack inline |
| PostgreSQL | Private | Campaigns, approvals, jobs, work-unit reservations, evidence, verdicts, findings, reports, audit, agent/request accounting |

Clerk is an external managed identity provider. The OpenEMR target and model providers are also
external. Only the Railway Web service receives public traffic; private services communicate over
Railway's private network. See [Railway deployment](docs/deployment/RAILWAY.md).

## Clerk prerequisites

Provisioning and real-user verification are manual integration steps. Staging and production must use
isolated Clerk configuration, including different exact Organization IDs and authorized origins.

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

Python 3.12+, Node.js, and PostgreSQL 16 are expected.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env.local
docker compose up -d postgres
alembic upgrade head
cd console
npm ci
npm run build
cd ..
python -m agentforge.web
```

`.env.local` is ignored. Never commit or print target sessions, provider credentials, Clerk session
tokens, organization identifiers that are treated as deployment configuration, or Langfuse keys.

Run the source gates with:

```bash
ruff check .
ruff format --check .
pytest
python -m agentforge.evals validate-corpus evals
python scripts/validate_target_catalog.py
cd console
npm test
npm run typecheck
npm run build
npm audit --audit-level=high
```

Container, migration, browser, secret, and security-tool gates are documented in
[the release runbook](docs/deployment/RAILWAY.md). Passing local tests is not deployment evidence.

## HTTP authentication and response behavior

The public allowlist is intentionally small:

- `GET /health` - process liveness only.
- `GET /ready` - dependency, packaged-console, security-configuration, and exact-schema readiness.
- Static assets and the minimal non-data sign-in/session-task SPA shell.

All `/api/v1` data and commands require a verified Clerk session, exact configured Headshot
Organization membership, and the endpoint's custom permission. Missing or invalid authentication
returns a generic `401`; an authenticated principal without the required organization, permission,
object scope, or distinct-approver identity receives `403`; verifier/configuration failure denies
with `503`. Frontend role text and client-supplied permissions have no authority.

The backend source defines Operator and Approver permission sets and verifies tokens networklessly
with an explicit authorized-party list and exact organization. Final real-environment role
assignment/MFA proof remains pending; see [USERS.md](USERS.md) and
[authentication documentation](docs/security/AUTHENTICATION.md).

## Authorized campaign workflow

1. The browser selects a server-reviewed target/catalog entry and server-provided workload template.
2. Web constructs the canonical scope from server state. Browser fields cannot replace the target's
   allowlist, synthetic-data attestation, credential reference, corpus hash, or provider authority.
3. The launch request and separate decision are persisted. Any scope change requires a new decision.
4. Launch writes an idempotent durable job. It is not an inline target request.
5. Runner re-reads the scope and approval, proves the queue lease, validates the catalog and
   credential/session lease, reserves each physical coordinate, and revalidates before every send.
6. Orchestrator selects authorized work; Red Team emits an `AttackAttempt`; the Policy Gateway sends
   it; the Recorder persists hash-addressed evidence; Judge applies deterministic precedence; and
   Documentation conditionally writes a sanitized draft and blocked regression disposition.
7. PostgreSQL remains authoritative. Langfuse is reconciled afterward by exact IDs; missing or
   provider-estimated values remain explicitly classified.

Legacy direct-live scripts intentionally refuse before reading credentials or opening a target
socket. Use only the authenticated Web/API and private Runner path.

## External API, rate, and retry contracts

| Boundary | Authentication | Limits and failure behavior |
|---|---|---|
| Clinical Co-Pilot | Runner-only session resolved from an environment-scoped opaque reference; Clerk tokens are never forwarded | Exact HTTPS host/path/method, request/response size and content-type limits, campaign rate/budget/timeout/physical caps; typed retry is bounded by the authorized policy and hard-aborts on exhaustion or session expiry |
| OpenRouter | Runner-only provider key resolved from a role-unique opaque reference | Exact model and upstream provider, fallbacks disabled, global and per-role call/token/USD/rate/concurrency caps, at most one configured retry, bounded `Retry-After`, then typed failure |
| Langfuse Cloud | Environment-specific public/secret keypair on private Runner | Projection is fail-soft for deterministic telemetry but mandatory before a hosted provider call; remote delivery is unproven until paged exact query-back succeeds |
| Clerk | Browser bearer session verified by Web with the configured public JWT key | Exact authorized parties and organization; no dynamic JWKS fallback; token expiry and short event-stream reconnect bound freshness |

## API windows, queue state, and indexes

The fetch-based event stream uses `Last-Event-ID`, pages at most 100 ordered audit events, signals
cursor gaps, and reconnects after a short authentication window. Most REST collection views currently
use fixed server-side windows (typically 200-1,000 rows) and do **not** expose general client cursor
pagination or total counts. That is a documented scalability gap, not hidden pagination.

The queue is at-least-once: `queued -> leased -> completed`, with `cancelled` and `dead_letter`
terminal states. Claims are short `SKIP LOCKED` transactions; work runs outside the claim
transaction. Lease tokens, heartbeat/reaper behavior, payload versions, enqueue fingerprints, and
idempotent completion protect state. A reserved but unobserved physical target send is treated as
ambiguous and is never silently declared unsent.

Revisions through `0021` add authoritative results, exact two-role authorization, regression replay
planning, and four-agent runtime observability to the exact-scope control plane; `0017`–`0021` add
hosted agent-execution lineage, provider-call lineage, recordable provider identity, agent-acceptance
authority, and the four-role agent acceptance surface. Incoming `0022` must remain the sole head and
compose the governed runtime before final release binding. A trusted server
catalog prepares immutable campaign scopes; a private durable Runner claims the PostgreSQL queue,
revalidates authorization immediately before every dispatch, resolves scoped credentials only at that
boundary, and persists evidence before atomic job completion. The private Scheduler creates one
append-only, human-authorization-blocked replay plan when a ready target version changes; it never
executes an attack or bypasses campaign authorization. Application and database controls reject
self-approval for campaign authorization. Finding approval still requires the release fix that
rejects the raiser as approver and rejects missing raiser lineage in both application and database.
Neither queue completion nor a replay plan is approval.

## Contracts and migrations

The deterministic synthetic profile runs the real nine-case corpus through the queue, Runner,
coordinator, recorder, independent Judge, findings, API, Coverage, and event repositories without a
target/model socket. Local integration evidence proves all attempts and hash-verified Coverage;
this is not a deployed or live-target claim. Scheduling, traces,
immutable configuration snapshots, component heartbeats, resilience history, and live-probe
authorization are projected only from durable records; unavailable observations remain explicitly
unavailable rather than being replaced by dummy data.

A live run **through the platform's production authorization path** — campaign-authorization request,
a decision by a distinct authenticated Clerk Approver, `POST /campaigns`, the PostgreSQL queue, and
the private durable Runner — remains blocked until the exact deployed target, ownership authorization,
synthetic fixture/canary, surface, credential reference, caps, nonce, and that distinct Approver are
persisted and every network-free preflight gate passes. Live *probing* of the authorized target has
happened by other means and its artifacts are checked in under `evals/results/`; those runs were
launched by direct scripts that now fail closed, and their recorded two-person provenance is one human
plus one AI agent identified by free text, not two distinct authenticated principals. Read them as
evidence about the target, never as evidence that the governed loop has executed.

## Further documentation

**Canonical** (see *Canonical source of truth* above)

- [Binding architecture](ARCHITECTURE.md)
- [Decision log D1–D26](docs/planning/DECISIONS.md)
- [Cost model — three independent families, scaled in test runs](docs/cost/COST_ANALYSIS.md) — projections are
  explicitly unmeasured; no dollar figure in this repository comes from a measured run

**Current honest status**

- [Red-teaming coverage review — 2026-07-25](docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md)
  (supersedes [2026-07-24](docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-24.md))
- [Vulnerability report index](docs/vulnerabilities/README.md) — six DRAFT reports; 004–006 contain
  embedded offline re-derivations over retained captures, but none is published and no independent
  attestation or separately recorded reproduction artifact exists; PRD-32 remains incomplete
- [Ticket and requirement reconciliation](TICKETS.md)
- [Requirements matrix](docs/requirements/REQUIREMENTS_MATRIX.md) ·
  [canonical CSV ledger](docs/requirements/REQUIREMENTS_MATRIX.csv)

**Reference**

- [Threat model](THREAT_MODEL.md)
- [User workflows](USERS.md)
- [Identity and access ADR](docs/adrs/0002-identity-and-access.md)
- [Build-vs-configure ADR](docs/adrs/0001-build-vs-configure.md)
- [Authentication security contract](docs/security/AUTHENTICATION.md)
- [Railway deployment runbook](docs/deployment/RAILWAY.md)
- [Clinical Co-Pilot target/session readiness](docs/target/READINESS.md)
- [Hosted role model resolution](docs/agents/RED_TEAM_MODEL_RESOLUTION.md)
- [Security-tool ATO evidence](docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md)
- [Security-tool integration plan](docs/planning/SECURITY_TOOL_INTEGRATION_PLAN.md)
- [M1d integration handoff](docs/planning/M1D_INTEGRATION_HANDOFF.md)
