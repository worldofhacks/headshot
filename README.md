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
| Last committed candidate baseline inspected here | `a1abbc41dd7973a7c6e63e7bf054369e15842cbc` | Point-in-time committed source baseline; later documentation does not make it a final release |
| Current integration candidate | Moving release branch; final SHA pending | One migration head at `0018`, hosted configuration schema v2, exact provider routes, physical provider-attempt tracing, closed call/input/USD admission, and an explicit staging-only extended campaign window; not deployed |
| GitHub `main` | `23490ea` | Older deployed release |
| GitLab `main` | `23490ea` | Exact mirror of the older release |
| Railway staging/production source | `23490ea` | Healthy prior Web/Runner/Scheduler/PostgreSQL baseline |
| Railway database revision | `0013` | Prior schema |
| Candidate migration graph | one head at `0018` | Source capability only; not applied to Railway |
| Headshot Langfuse staging observations | `0` | The new agent-observability path has not run in staging |

The prior release proves basic health, readiness, protected-route denial, and the Railway topology.
It does **not** prove the candidate hosted-agent implementation, migrations `0014`-`0018`, the final
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
  and role adapters. Schema v2 binds the exact endpoint tag and its exact supported output-token
  parameter into each role hash: Orchestrator `amazon-bedrock/eu-west-1` + `max_tokens`, Red Team
  `atlas-cloud/fp8` + `max_tokens`, Judge `google-vertex/global` + `max_tokens`, and Documentation
  `azure/eu` + `max_completion_tokens`. Fallbacks and token-parameter substitution are disabled.
  In hosted mode the candidate Runner composes all four roles. Qwen makes one traced proposal per
  selected frozen seed, but the proposal is hash-recorded and explicitly
  `quarantined_not_dispatched`; only the byte-exact authorized SeedReplay case reaches the target.
  This is tested source behavior, not deployed four-role evidence, and it is not a
  generation-to-review-to-reauthorization workflow.
- A closed hosted workload envelope. The candidate admits at most 400 physical provider attempts;
  the exact 100-case worst case is 100 Orchestrator + 100 Red Team + 100 Judge + up to 100
  Documentation attempts with zero provider retries. Enabling one retry for that shape requires 800
  attempts and is refused. Before any provider side effect, the Runner also proves every encoded
  request fits its authorization-bound input limit and that the exact worst-case reservation across
  all required attempts fits both per-role and global USD caps. Oversize input, insufficient
  cumulative authority, or an unrepresentable exact decimal is a typed fail-closed refusal.
- Server-owned campaign windows. The standard profile remains the browser default, derives the
  exact grant as `floor(run timeout) + 301` seconds, and retains the 3,600-second maximum grant.
  Only a staging campaign whose target advertises a larger timeout may explicitly select
  `staging_extended`, bounded to a 14,400-second run and 14,701-second grant. Local, production, and
  live-probe use reject it. The current 1,800-second target catalog exposes no extended option.
  This is focused source-test evidence only, not a deployed or completion-capable campaign.
- A per-physical-send authority guard in candidate commit `b14d2bd`. The Runner anchors
  one start-plus-run-timeout deadline, renews and proves its exact queue claim, reloads the immutable
  authorization, and requires the complete transport timeout to end strictly before the run,
  approval, and delegated-session deadlines before every hosted provider attempt or target send.
  Equality refuses. A provider refusal occurs after pacing but before credential resolution,
  lineage/ledger reservation, or HTTP; the target's durable reservation remains the final callback
  before its adapter send, preserving ambiguous-I/O no-replay behavior. Typed refusal reasons are
  persisted. Focused tests pass, but this candidate control is not deployed or live-verified.
- Deterministic-oracle precedence. Oracle/canary confirmation and evidence errors are decisive.
  A model Judge is advisory unless the exact Judge identity has a valid, enabled calibration
  artifact. Failed or unavailable calibration does not convert an exploit into a safe result.
- PostgreSQL-authoritative agent and physical-request accounting plus Langfuse Cloud projection.
  Every physical OpenRouter send/retry is a `provider.openrouter.attempt` child generation under
  its owning role AGENT. Physical generations carry provider-event identity, order, model/provider,
  latency, tokens, errors, and measured cost when supplied; hosted logical runtime generations are
  metadata-only for tokens/cost to avoid double counting. Raw credentials and evidence bodies are
  not exported. An SDK flush remains `queued`; only exact remote query-back can mark a row `exported`.
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
- Obtain the security owner's final commit and exact frozen 100-case corpus/Judge identities, then
  have a human authorize the exact target and provider budget; no default corpus or inferred cap may
  replace either input.
- Publish the authorized 100-case performance evidence and complete the interim numeric cost
  analysis with the account owner's Langfuse plan/invoice and actual development-spend inputs.
  Attach the real demo and social-post URLs only after the user supplies them.
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
   credential/session lease, and revalidates immediately before every physical provider/target
   send. The complete transport timeout must fit strictly inside the anchored run deadline, approval
   expiry, and any delegated-session expiry. Target coordinates are durably reserved immediately
   before the adapter call and ambiguous sends are never blindly replayed.
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
| Clinical Co-Pilot | Runner-only session resolved from an environment-scoped opaque reference; Clerk tokens are never forwarded | Exact HTTPS host/path/method, request/response size and content-type limits, campaign rate/budget/timeout/physical caps; each send must fit strictly within run/grant/session deadlines; typed retry is bounded by the authorized policy and hard-aborts on exhaustion or session expiry |
| OpenRouter | Runner-only provider key resolved from a role-unique opaque reference | Exact model and upstream provider, fallbacks disabled, global and per-role call/token/USD/rate/concurrency caps, at most one configured retry, bounded `Retry-After`; each physical attempt re-proves the queue/grant and deadline before credential resolution or HTTP |
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

Focused candidate tests cover loss of queue ownership, immutable-authorization drift, invalid or
boundary-equal transport deadlines, and delegated-session expiry for provider and target sends. They
do not replace a staged lease-loss/deadline drill on the final release.

PostgreSQL indexes cover queue claims/reaping/depth, organization/run lookups, finding severity,
category and target version, audit cursors, agent trace/delivery/provider-request lookup, and
work-unit reservations. A final representative 100-case run must still measure query and regression
SLOs.

## Contracts and migrations

The runtime package contains versioned JSON Schemas in
[`src/agentforge/contracts/v1`](src/agentforge/contracts/v1), including typed success, evidence,
verdict, report, regression, tool, and error shapes. Producer/consumer and compatibility tests run
against that registry. Reviewer-facing copies are now published at [`contracts/v1`](contracts/v1);
byte-equality and registry tests prevent the package and root publications from drifting.

The candidate Alembic graph has exactly one head at `0018`. Revisions `0014`-`0018` add physical
work-unit reservations, append-only hosted configuration sets, exact Langfuse delivery verification,
provider/model/Judge lineage, and the authoritative physical provider-call ledger. These revisions
are additive, but database downgrade can discard evidence; normal code rollback retains the expanded
schema and deploys a compatible prior image. Production database rollback remains blocked until a
backup/restore point is configured and confirmed.

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
