# Headshot ATO-style evidence packet

- Packet date: 2026-07-24
- Canonical requirements: [`../../../Week_3_AgentForge.pdf`](../../../Week_3_AgentForge.pdf)
- Last committed candidate source inspected through:
  `a1abbc41dd7973a7c6e63e7bf054369e15842cbc`
- Later documentation: does not create a final release SHA or deployment evidence
- Final release commit: **unavailable while integration is moving**

## Authorization decision

**Status: not approved for final production promotion.**

The reviewed candidate contains the four canonical agent roles, deterministic Policy Gateway,
durable PostgreSQL control plane, one Alembic head at `0018`, exact hosted-provider routes, physical
provider-call lineage, and Langfuse delivery/query-back verification. Local backend and focused
hosted/trace tests passed on the named base before the final integration edits; exact-release CI
has not yet passed.

Those facts are not deployment evidence. Read-only review records staging and production at commit
`23490ea`, migration `0013`; that release cannot prove the candidate's four-agent, physical-call, or
Langfuse implementation. Therefore the candidate is **implemented and locally tested, but not
live-verified**. Final staging acceptance, the frozen-corpus authorized campaign, Langfuse
query-back, 100-case performance/security evidence, and exact-release CI are unavailable. Production
is blocked by the missing human deploy grant and the absence of a confirmed database backup/restore
binding.

## Evidence classification

| Label | Meaning |
|---|---|
| **Implemented** | The control exists in the source baseline named above. |
| **Tested** | A named check exercised the control. Historical test evidence is dated and is not silently promoted to final-release evidence. |
| **Live-verified** | A deployed observation is bound to an exact commit, deployment, environment, and migration. |
| **Unavailable** | The system explicitly reports no observation or the required artifact does not exist. |
| **Blocked** | A named safety, human, deployment, authorization, or recovery gate prevents promotion or execution. |

## Packet contents

| Artifact | Reviewer question answered | Status |
|---|---|---|
| [`ARCHITECTURE_DEPLOYMENT.md`](ARCHITECTURE_DEPLOYMENT.md) | What runs where, and what is public? | Candidate architecture implemented; final deployment unavailable |
| [`DATA_FLOW_TRUST_BOUNDARIES.md`](DATA_FLOW_TRUST_BOUNDARIES.md) | What data crosses each boundary and which component is authoritative? | Implemented/tested design; final live trace unavailable |
| [`AUTHORIZATION_MODEL.md`](AUTHORIZATION_MODEL.md) | Who and what may invoke targets, providers, storage, or publication paths? | Backend controls tested; real-environment Clerk verification unavailable |
| [`DEPENDENCY_INVENTORY.md`](DEPENDENCY_INVENTORY.md) | Which runtimes, libraries, tools, and images are in the reviewed artifact? | Manifest-grounded; Python resolution is not fully locked |
| [`SECURITY_AND_EVAL_EVIDENCE.md`](SECURITY_AND_EVAL_EVIDENCE.md) | What was scanned/evaluated and what remains unproven? | Historical/local evidence scoped; frozen 100/final campaign unavailable |
| [`SECURITY_TOOL_EVIDENCE.md`](SECURITY_TOOL_EVIDENCE.md) | What did the pinned platform scanners produce? | Historical evidence retained with scope caveats |
| [`AUDIT_AND_ROLLBACK.md`](AUDIT_AND_ROLLBACK.md) | How are actions reconstructed, failures drilled, and a release contained or rolled back? | Procedures documented; production DB rollback binding blocked |
| [`SAMPLE_INCIDENT_POSTMORTEM.md`](SAMPLE_INCIDENT_POSTMORTEM.md) | Can the team reason through a security-relevant failure without claiming it occurred? | Clearly marked tabletop sample |

## Control summary

| Control family | Implemented evidence | Current live evidence | Residual or gate |
|---|---|---|---|
| External attack authorization | Exact target/surface/corpus/caps/nonce scope, distinct decision, target-bound credential, synthetic assertion, timeout and abort | Prior deployment exists, but not the reviewed source | New final-release campaign authorization required |
| Judge independence | Recorder-owned evidence, deterministic oracle precedence, typed verdicts, model authority bounded by calibration | No final-release execution row | Exact runtime calibration/human enablement unavailable; model advisory |
| Agent separation | Orchestrator, Red Team, Judge, Documentation roles, parent execution lineage, exact routes | Current deployed release predates these candidate paths | Deploy `0018` and query the resulting ledger |
| Human access | Networkless Clerk JWT verification, exact single Headshot Organization, backend custom permissions, distinct approver check | Protected-route denial exists; full real-user configuration not accepted | Lowest-priority external verification, still not claimed complete |
| Storage integrity | Append-only evidence, role grants, content hashes, FKs, uniqueness, work-unit/provider-call reservations | Prior schema is only `0013` | Apply one linear head through `0018` in staging |
| Judge authority | Deterministic oracle/canary precedence; typed evidence; model authority separately calibrated | Exact final route identity not calibration-bound or human-enabled | Keep model advisory/fail-closed; deterministic oracles decisive |
| Observability | PostgreSQL authoritative ledger; role AGENT plus physical provider GENERATION; query-back before `exported`; logical usage metadata-only | Candidate path not deployed/query-verified | Staging query-back and DB reconciliation required |
| Software assurance | Contract tests, corpus validators, SAST, dependency audits, secret scan, container and migration gates | Historical CI/local evidence | GitHub CI must pass on the exact final commit |
| Privacy | Synthetic fixtures, `contains_real_phi=false`, no prompt/response bodies exported to Langfuse | No frozen final corpus/campaign to reconcile | Recheck corpus hash and target binding before launch |

## Release evidence placeholders

These values are intentionally absent until they exist:

- final release commit and identical GitHub/GitLab `main` SHAs;
- authoritative GitHub Actions run URL and green result;
- staging Railway deployment IDs for that exact commit;
- deployed migration head after final staging promotion;
- final authorized campaign/run/evidence identifiers;
- Langfuse expected/observed/missing/extra totals and recorded verification timestamp;
- authorized 100-case performance/load report;
- numeric final cost table;
- demo video URL and social-post URL;
- production Railway identities after a human grant, plus a confirmed rollback deployment and
  database backup/restore binding.

No credential value, session identifier, bearer token, target secret, or Langfuse key belongs in this
packet.
