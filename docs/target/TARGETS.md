# Authorized live target — Clinical Co-Pilot

**Reconciled:** 2026-07-26

**Current deployment and run:** [`../CURRENT_STATE.md`](../CURRENT_STATE.md)

AgentForge's first target is the owner's external synthetic-data OpenEMR Clinical Co-Pilot at
`https://agent-production-9f62.up.railway.app`. No target source exists in this repository.

“Production” in that hostname describes the target deployment. It does not mean an AgentForge
production campaign. The latest governed calls came from AgentForge **staging** under a staging
target definition, credential generation, lease, and authorization. AgentForge production is
currently release-skewed and cannot launch.

## Authoritative target definitions

Tracked, secret-free catalogs:

- `config/live-target-catalog.staging.json`
- `config/live-target-catalog.production.json`
- `config/targets/clinical-copilot-20260724.json` — compatibility subset
- `config/targets.json` — historical only; never live authority

The tracked catalogs contain primary/alias definitions for two owner-provided synthetic sessions:

| Primary ID | Alias | Tracked version | Enabled live surface |
|---|---|---:|---|
| `copilot-week1` | `clinical-copilot-week1` | `1.0.0` | authenticated `POST /chat` |
| `copilot-week2` | `clinical-copilot-week2` | `1.0.0` | authenticated `POST /chat` |

App, evidence-search, and document-upload surfaces are represented for review but disabled in the
tracked live catalog. Their presence is not proof that the current governed campaign exercises RAG,
upload, or write-back endpoints directly.

The control plane creates immutable target/surface versions when safety/workload authority changes.
The latest staging campaign bound matching target and chat-surface version `1.0.1`; do not assume the
tracked base version is the currently authorized database version. The console/API read model and
authorization request must show the exact version used.

## Transport contract

| Property | Current contract |
|---|---|
| Origin | exact HTTPS host; redirects and private destinations denied |
| Chat path | `POST /chat` |
| Body | `{"session_id": "<sealed value>", "message": "<one authored turn>"}` |
| Auth | patient-pinned SMART session in the body; Clerk bearer is never forwarded |
| Response | bounded allowed content type/size; hostile data until recorded |
| Session-expired signal | typed HTTP `401` detail recognized by adapter; no blind retry |
| Rate | authorization-bound, latest workload 0.5 target requests/second |
| Target retries | zero for live-100 workloads |
| Data | synthetic fixtures and canaries only |

Every authored turn is a separately metered physical target call. The frozen 100-case workload has 121
turns and is split into:

| Workload | Cases | Exact target calls | Target retries |
|---|---:|---:|---:|
| `headshot-live-100-batch-01` | 34 | 41 | 0 |
| `headshot-live-100-batch-02` | 33 | 40 | 0 |
| `headshot-live-100-batch-03` | 33 | 40 | 0 |

The latest failed batch created 12 attempts and 16 target calls, proving multi-turn cases are not
collapsed into one request.

## Credential boundary

Catalogs contain only opaque `secretref://…` handles. Runner-only
`AGENTFORGE_CREDENTIAL_BINDINGS_JSON` maps each handle to the name of a sealed Railway variable;
Runner-only `AGENTFORGE_SESSION_LEASES_JSON` binds generation, expiry, and a one-way value hash. Raw
session values never belong in source, database rows, Web, the browser, CI, docs, shell history, logs,
or Langfuse.

One campaign uses one immutable credential generation and one campaign-owned HTTP client. A process
restart, generation change, policy/configuration change, or lease update requires fresh readiness and
fresh campaign authorization.

## Network-free validation

```bash
python scripts/validate_target_catalog.py
```

This validates both tracked environment catalogs and opens no target connection. It does not prove a
credential, session lease, target route, or campaign authorization is live.

## Live-use gate

Before a target call:

1. verify the external target health/readiness read-only;
2. resolve the exact database target/surface version;
3. require an approved immutable live-100 batch and exact manifest digest;
4. prove the sealed credential value matches its generation metadata;
5. prove the lease covers the entire run timeout;
6. prove synthetic fixtures/canaries and exact target caps;
7. prove Web/Runner/Scheduler release and policy parity;
8. prove the hosted model configuration has sufficient exact capacity; and
9. obtain a fresh decision from a different authenticated Headshot user.

Direct scripts must not bypass the authenticated control plane and private Runner.
