# Headshot / AgentForge

Headshot is a reusable multi-agent adversarial evaluation platform for AI applications. Its first
target is the externally deployed OpenEMR Clinical Co-Pilot. Headshot reaches that target over an
authorized live URL; the target's source code is not part of this repository.

The canonical requirements are [Week_3_AgentForge.pdf](Week_3_AgentForge.pdf). The
[submission index](SUBMISSION.md), [architecture](ARCHITECTURE.md),
[threat model](THREAT_MODEL.md), and [requirements matrix](docs/requirements/REQUIREMENTS_MATRIX.md)
separate implemented controls from local tests, deployed observations, and outstanding gates.

## Release truth - 2026-07-24

The newest implementation is **not deployed**. This table is the audited pre-release boundary, not
a claim about the eventual final commit.

| Item | Audited value | Evidence meaning |
|---|---|---|
| Documentation/source baseline | `eac2968` | Integration candidate inspected for this update; not a final release |
| GitHub `main` | `23490ea` | Older deployed release |
| GitLab `main` | `23490ea` | Exact mirror of the older release |
| Railway staging/production source | `23490ea` | Healthy prior Web/Runner/Scheduler/PostgreSQL baseline |
| Railway database revision | `0013` | Prior schema |
| Candidate migration graph | one head at `0017` | Source capability only; not applied to Railway |
| Headshot Langfuse staging observations | `0` | The new agent-observability path has not run in staging |

The prior release proves basic health, readiness, protected-route denial, and the Railway topology.
It does **not** prove the candidate hosted-agent implementation, migration `0014`-`0017`, the final
corpus, a live four-agent campaign, or Langfuse query-back. See the
[predeployment Langfuse baseline](docs/evidence/langfuse/PREDEPLOYMENT_BASELINE_2026-07-24.md).

| Public URL | Current status |
|---|---|
| Staging Headshot Web | <https://web-staging-8e30.up.railway.app> - prior release |
| Production Headshot Web | <https://web-production-44528.up.railway.app> - prior release, not the final candidate |
| Authorized external target | <https://agent-production-9f62.up.railway.app> - target only; health is not campaign authorization |

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
- Obtain an explicit human production-deploy grant and bind a compatible rollback deployment and
  database recovery point. No source commit or documentation packet grants production promotion.

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

Only Web is intended to have public ingress. The currently observed prior release follows this
boundary; the exact final deployment must re-prove it.

| Service | Ingress | Responsibility |
|---|---|---|
| Web | Public HTTPS | React shell, FastAPI, authentication/permission checks, command/read APIs, health/readiness |
| Runner | Private | Claims campaign jobs, resolves sealed references, runs agent work, sends authorized target/provider traffic, records evidence |
| Scheduler | Private | Detects target-version changes and records authorization-blocked replay plans; it does not attack inline |
| PostgreSQL | Private | Campaigns, approvals, jobs, work-unit reservations, evidence, verdicts, findings, reports, audit, agent/request accounting |

Deployment details and rollback rules are in [docs/deployment/RAILWAY.md](docs/deployment/RAILWAY.md).

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

PostgreSQL indexes cover queue claims/reaping/depth, organization/run lookups, finding severity,
category and target version, audit cursors, agent trace/delivery/provider-request lookup, and
work-unit reservations. A final representative 100-case run must still measure query and regression
SLOs.

## Contracts and migrations

The runtime package contains versioned JSON Schemas in
[`src/agentforge/contracts/v1`](src/agentforge/contracts/v1), including typed success, evidence,
verdict, report, regression, tool, and error shapes. Producer/consumer and compatibility tests run
against that registry. At this audit baseline the PRD's additional literal root `/contracts`
publication is still a release item.

The candidate Alembic graph has exactly one head at `0017`. Revisions `0014`-`0017` add physical
work-unit reservations, append-only hosted configuration sets, exact Langfuse delivery verification,
and provider/model/Judge lineage. These revisions are additive, but database downgrade can discard
evidence; normal rollback retains the expanded schema and deploys a compatible prior image.

## Release discipline

GitHub Actions is the authoritative CI gate. GitLab is a passive exact mirror and is not a pipeline
gate. The final `main` commit must be identical on both remotes and Railway; never force-push.
Staging migration and acceptance precede production. Production requires the explicit human grant
and rollback binding described above.

## Documentation

- [Submission index](SUBMISSION.md)
- [Architecture](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
- [Users and workflows](USERS.md)
- [ATO packet](docs/evidence/ato/README.md)
- [Integration packet](docs/integration/INTEGRATION_PACKET.md)
- [Requirements matrix](docs/requirements/REQUIREMENTS_MATRIX.md)
- [Development log](docs/DEVLOG.md)
- [Cost analysis](docs/cost/COST_ANALYSIS.md)
- [Target/session readiness](docs/target/READINESS.md)
- [Vulnerability index](docs/vulnerabilities/README.md)
