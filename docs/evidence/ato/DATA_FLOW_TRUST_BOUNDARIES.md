# Data flows and trust boundaries

## Campaign data flow

```mermaid
flowchart TD
    Human["Authenticated Operator"] -->|"request exact scope"| Web["Web control plane"]
    Approver["Different authenticated Approver"] -->|"approve or reject same stored scope hash"| Web
    Web -->|"append authorization request/decision"| DB[("PostgreSQL system of record")]
    Web -->|"enqueue authorized work only"| DB

    DB -->|"lease job + immutable scope"| Orchestrator["Orchestrator"]
    Orchestrator -->|"CampaignDirective v1"| RedTeam["Red Team - untrusted"]
    RedTeam -->|"AttackAttempt v1; no credential"| Gateway["Policy Gateway - trusted"]
    Gateway -->|"allowlist + synthetic + caps + timeout + abort + reservation"| Adapter["Target adapter"]
    Adapter -->|"HTTPS request with scoped target credential"| Target["External target"]
    Target -->|"hostile response data"| Recorder["Execution Recorder - trusted"]
    Recorder -->|"hashed AttemptResult + request ledger"| DB
    DB -->|"re-read and hash verify"| Envelope["Typed evidence envelope"]
    Envelope -->|"trusted oracle fields + hostile transcript field"| Judge["Judge - governed"]
    Judge -->|"Verdict v1"| DB
    DB -->|"confirmed, sanitized evidence only"| Documentation["Documentation - gated"]
    Documentation -->|"draft report; publication blocked"| DB
    DB -->|"verified coverage/findings/cost/order"| Orchestrator

    Orchestrator -.->|"agent/generation observation"| Langfuse["Langfuse Cloud"]
    RedTeam -.->|"agent/generation observation"| Langfuse
    Judge -.->|"agent/generation observation"| Langfuse
    Documentation -.->|"agent/generation observation"| Langfuse
    Gateway -.->|"physical request observation"| Langfuse
```

## Trust zones

| Zone | Components/data | Allowed authority | Explicitly prohibited |
|---|---|---|---|
| Human identity | Browser, Clerk session, immutable Principal | Request operations carrying verified custom permissions | Supplying organization, role, permission, target, or approval authority as client-controlled truth |
| Trusted control plane | Web command handlers, Orchestrator policy, Policy Gateway, Execution Recorder | Bind exact scope, enforce policy, release scoped target credential, persist evidence | Treat authentication alone as campaign authorization; accept optimistic UI state as fact |
| Untrusted generation | Red Team output and all attack content | Propose typed attempts within the authorized corpus/policy | Hold target credentials, send target traffic directly, write authoritative evidence, judge itself |
| Governed evaluation | Judge, Documentation, regression admission | Evaluate typed evidence; draft or admit only under deterministic gates | Override a conclusive oracle, execute target actions, publish critical findings, remediate |
| Authoritative storage | PostgreSQL rows, hashes, FKs, audit cursors, queue leases | Source of truth for campaign state, evidence, findings, cost, and lineage | Infer missing rows from UI state or Langfuse |
| External observation | Langfuse Cloud | Observe safe metadata, hashes, usage, cost, order, and timing | Become evidence or authorization authority; receive credentials or raw clinical/adversarial bodies |
| External target/provider | Clinical Co-Pilot and model providers | Return responses for exact authorized requests | Expand scope or become trusted evidence without recorder verification |

## Data classification and handling

| Data class | Examples | Storage/export rule |
|---|---|---|
| Synthetic clinical fixture | Fabricated patient/context records and canaries | Allowed in the target/evidence path; must carry synthetic provenance and `contains_real_phi=false` |
| Hostile adversarial content | Attack turns and target response text | Quarantined as hostile evidence; size bounded; not exported to Langfuse; sanitized before Documentation |
| Credential material | Clerk bearer token, target session value, provider/Langfuse secret key | Runtime-only at its owning boundary; never committed, logged, traced, or stored in evidence |
| Credential reference | `secretref://` handle or a digest binding | May appear only where required for immutable scope; no secret value is embedded |
| Integrity metadata | Content hash, prompt/policy/configuration hashes, request ID | Persisted and safe to export where it reveals no secret/body |
| Human attribution | Minimal user/session/organization identifiers | Persisted for audit and separation of duties; raw claims/token are not retained |
| Usage/accounting | Input/output/reasoning tokens, retries, latency, provider-reported cost | Persisted when actually supplied; missing values remain unavailable, never zero-filled |

## Authoritative lineage

The durable join keys are Organization ID, campaign/run ID, attempt ID, agent execution ID and parent
execution ID, finding ID, target/surface/version, content hash, and provider request ID when a provider
returns one. Migration `0017` adds configuration, role-policy, model/provider, token, retry, Judge
calibration, oracle agreement, and decision-authority fields to the agent execution ledger.

Langfuse delivery is not considered complete when the SDK merely flushes. Migration `0016` requires
an exact remote query-back before a durable row may be marked `exported`; until then it remains
`queued`, `disabled`, or `error`. PostgreSQL remains authoritative if Langfuse is unavailable.

## Data model and quality controls

| Domain | Principal records | Quality/access controls |
|---|---|---|
| Target catalog | Target/surface identity, immutable versions, lifecycle events | Server-owned catalog, exact version references, relative-path and allowlist validation |
| Human control plane | Authorization requests/decisions, command idempotency, audit events | Organization scope, immutable launcher/approver, scope hash, expiry, distinct-person trigger |
| Campaign/queue | Campaign runs/events/attempts, jobs, physical work-unit reservations | Versioned payloads, unique idempotency keys, bounded leases, dead-letter state, immutable physical coordinates |
| Evidence/evaluation | Attack cases, AttemptResult, Verdict, finding-evidence links | Required fields, content hashes, replay uniqueness, FKs, provenance, deterministic precedence |
| Reporting/regression | Findings, finding decisions, draft reports, dispositions, replay plans/results, case versions | Unique IDs, append-only draft evidence, confirmation/reproduction/right-reason gates, human publication block |
| Agent/hosted lineage | Agent configuration versions, hosted configuration sets, agent executions | Exactly four roles, append-only configuration, constrained lifecycle, complete terminal provider/accounting tuple |
| Observability | Outbound request ledger, runtime status, Langfuse delivery/verification fields | Pre-send row, one-way terminal update, safe hashes/metadata only, exact query-back before exported |

Common query indexes include finding severity, category, target version, Organization/state; campaign
run/attempt; queue depth/claim order; unobserved work reservations; agent role/status/start time; and
provider request identity. Concrete final regression/query SLO evidence remains pending.

## Boundary verification still pending

A final deployed trace must demonstrate the exact ordered agent chain, one-to-one physical requests,
provider/model identity, attempts/retries, evidence hashes, finding/report behavior, and Langfuse
observations for one authorized campaign. Historical manifests that predate the durable `0016`/`0017`
ledger cannot be backfilled and are not accepted as that proof.
