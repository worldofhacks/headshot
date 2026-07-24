# Headshot ATO-style evidence packet

- Packet date: 2026-07-24
- Canonical requirements: [`../../../Week_3_AgentForge.pdf`](../../../Week_3_AgentForge.pdf)
- Source baseline inspected: `17019f28c606e9d3a799073f80f2437ee2e98ff6`

## Authorization decision

**Status: not approved for final production promotion.**

The reviewed source contains the four canonical agent roles, deterministic Policy Gateway, durable
PostgreSQL control plane, single Alembic head at `0017`, hosted-agent lineage, and Langfuse delivery
verification logic. Selected local contract, authentication, campaign-authorization, migration, and
hosted-lineage checks passed during assembly of this packet.

Those facts are not deployment evidence. The repository's read-only live review records staging and
production at commit `23490ea`, migration `0013`, zero durable canonical agent executions, and zero
canonical Langfuse observations. Therefore the newest implementation is **implemented and locally
tested, but not live-verified**. Final staging acceptance, the authorized final campaign, Langfuse
query-back, performance/load evidence, exact release CI, and production rollback binding remain
pending.

## Evidence classification

| Label | Meaning |
|---|---|
| **Implemented** | The control exists in the source baseline named above. |
| **Tested** | A named check exercised the control. Historical test evidence is dated and is not silently promoted to final-release evidence. |
| **Live-verified** | A deployed observation is bound to an exact commit, deployment, environment, and migration. |
| **Unavailable** | The system explicitly reports no observation or the required artifact does not exist. |
| **Pending** | An external, human, deployment, or final-integration gate remains. |

## Packet contents

| Artifact | Reviewer question answered | Status |
|---|---|---|
| [`ARCHITECTURE_DEPLOYMENT.md`](ARCHITECTURE_DEPLOYMENT.md) | What runs where, and what is public? | Source architecture implemented; final deployment pending |
| [`DATA_FLOW_TRUST_BOUNDARIES.md`](DATA_FLOW_TRUST_BOUNDARIES.md) | What data crosses each boundary and which component is authoritative? | Implemented design and persistence paths; final live trace pending |
| [`AUTHORIZATION_MODEL.md`](AUTHORIZATION_MODEL.md) | Who and what may invoke targets, providers, storage, or publication paths? | Backend controls implemented/tested; real-environment Clerk verification pending |
| [`DEPENDENCY_INVENTORY.md`](DEPENDENCY_INVENTORY.md) | Which runtimes, libraries, tools, and images are in the reviewed artifact? | Manifest-grounded; Python resolution is not fully locked |
| [`SECURITY_AND_EVAL_EVIDENCE.md`](SECURITY_AND_EVAL_EVIDENCE.md) | What was scanned/evaluated and what remains unproven? | Local evidence available; exact final-release scan and live campaign pending |
| [`SECURITY_TOOL_EVIDENCE.md`](SECURITY_TOOL_EVIDENCE.md) | What did the pinned platform scanners produce? | Historical evidence retained with scope caveats |
| [`AUDIT_AND_ROLLBACK.md`](AUDIT_AND_ROLLBACK.md) | How are actions reconstructed, failures drilled, and a release contained or rolled back? | Procedures implemented/documented; final rollback binding pending |
| [`SAMPLE_INCIDENT_POSTMORTEM.md`](SAMPLE_INCIDENT_POSTMORTEM.md) | Can the team reason through a security-relevant failure without claiming it occurred? | Clearly marked tabletop sample |

## Control summary

| Control family | Implemented evidence | Current live evidence | Residual or gate |
|---|---|---|---|
| External attack authorization | Exact target/surface/corpus/caps/nonce scope, distinct decision, target-bound credential, synthetic assertion, timeout and abort | Prior deployment exists, but not the reviewed source | New final-release campaign authorization required |
| Judge independence | Recorder-owned evidence, deterministic oracle precedence, typed verdicts, model authority bounded by calibration | No final-release execution row | Calibration identity and final campaign evidence pending |
| Agent separation | Orchestrator, Red Team, Judge, Documentation roles and parent execution lineage | Deployed database has zero canonical agent executions | Deploy `0017` and query the resulting ledger |
| Human access | Networkless Clerk JWT verification, exact organization, backend custom permissions, distinct approver check | Protected-route denial exists; full real-user configuration not accepted here | Lowest-priority external verification, still not claimed complete |
| Storage integrity | Append-only evidence, role grants, content hashes, FKs, uniqueness, work-unit reservations | Prior schema is only `0013` | Apply one linear head through `0017` in staging |
| Observability | PostgreSQL authoritative ledger, typed Langfuse observations, explicit remote query-back before `exported` | Zero canonical Langfuse observations | Separate environment project/key binding and query-back required |
| Software assurance | Contract tests, corpus validators, SAST, dependency audits, secret scan, container and migration gates | Historical CI/local evidence | GitHub CI must pass on the exact final commit |
| Privacy | Synthetic fixtures, `contains_real_phi=false`, no prompt/response bodies exported to Langfuse | No final campaign to reconcile | Recheck corpus and target binding before launch |

## Release evidence placeholders

These values are intentionally absent until they exist:

- final release commit and identical GitHub/GitLab `main` SHAs;
- authoritative GitHub Actions run URL and green result;
- staging and production Railway deployment IDs for that exact commit;
- deployed migration head after final staging promotion;
- final authorized campaign/run/evidence identifiers;
- Langfuse expected/observed/missing/extra totals and recorded verification timestamp;
- authorized 100-case performance/load report;
- numeric final cost table;
- demo video URL and social-post URL;
- human production-deploy grant and confirmed rollback deployment/database binding.

No credential value, session identifier, bearer token, target secret, or Langfuse key belongs in this
packet.
