# Headshot ATO-style evidence packet

- Packet status: **pre-release; not an authorization decision**
- Packet preparation base: `f39e22722d3b4e256110ac5be5ce160a0ad654e4`
- Canonical requirements: [`../../../Week_3_AgentForge.pdf`](../../../Week_3_AgentForge.pdf)

## Authorization decision

**Status: technical packet assembled; final release identity and live evidence pending.**

The preparation base contains the four canonical agent-role implementations, deterministic Policy
Gateway, durable PostgreSQL control plane, one Alembic head at `0021`, hosted-agent lineage, and
Langfuse delivery verification logic. The intended release adds revision `0022`; it is not part of
this packet branch and must be integrated and reverified before release binding.

Those source facts are not final deployment evidence. Staging historically proved a Runner-first
`0013 → 0021` migration and shell/auth-boundary checks at `2069036e`. Production remains on
`23490ea` / `0013`. Neither deployment proves the pending final `0022` release or its four-role
campaign. Final GitHub CI, exact GitLab mirror, image digest, staging/production proof, governed
campaign, Langfuse query-back, performance, and cost/invoice evidence remain pending.

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
| [`ARCHITECTURE_DEPLOYMENT.md`](ARCHITECTURE_DEPLOYMENT.md) | What runs where, and what is public? | Source architecture and historical staging proof documented; final deployment pending |
| [`DATA_FLOW_TRUST_BOUNDARIES.md`](DATA_FLOW_TRUST_BOUNDARIES.md) | What data crosses each boundary and which component is authoritative? | Implemented design and persistence paths; final live trace pending |
| [`AUTHORIZATION_MODEL.md`](AUTHORIZATION_MODEL.md) | Who and what may invoke targets, providers, storage, or publication paths? | Backend controls implemented/tested; real-environment Clerk verification pending |
| [`DEPENDENCY_INVENTORY.md`](DEPENDENCY_INVENTORY.md) | Which runtimes, libraries, tools, and images are in the preparation base? | Manifest-grounded; final-SHA hashes pending |
| [`SECURITY_AND_EVAL_EVIDENCE.md`](SECURITY_AND_EVAL_EVIDENCE.md) | What was scanned/evaluated and what remains unproven? | Local evidence available; exact final-release scan and live campaign pending |
| [`SECURITY_TOOL_EVIDENCE.md`](SECURITY_TOOL_EVIDENCE.md) | What did the pinned platform scanners produce? | Historical evidence retained with scope caveats |
| [`AUDIT_AND_ROLLBACK.md`](AUDIT_AND_ROLLBACK.md) | How are actions reconstructed, failures drilled, and a release contained or rolled back? | Procedures implemented/documented; final rollback binding pending |
| [`SAMPLE_INCIDENT_POSTMORTEM.md`](SAMPLE_INCIDENT_POSTMORTEM.md) | Can the team reason through a security-relevant failure without claiming it occurred? | Clearly marked tabletop sample |
| [`manifest.sha256`](manifest.sha256) | Are these packet files content-addressed? | Regenerate after any packet edit; verified by the submission-integrity test |

## Control summary

| Control family | Implemented evidence | Current live evidence | Residual or gate |
|---|---|---|---|
| External attack authorization | Exact target/surface/corpus/caps/nonce scope, distinct decision, target-bound credential, synthetic assertion, timeout and abort | No final-release governed campaign | Distinct authenticated launcher/approver and a new exact operation hash required |
| Judge independence | Recorder-owned evidence, deterministic oracle precedence, typed verdicts, model authority bounded by calibration | No final-release execution row | Final Judge identity/calibration and campaign evidence pending |
| Agent separation | Orchestrator, Red Team, Judge, Documentation roles and parent execution lineage | No final-release four-role ledger | Integrate `0022`, deploy, execute, and query the ledger |
| Human access | Networkless Clerk JWT verification, exact organization, backend custom permissions, distinct approver check | Protected-route denial exists; full real-user configuration not accepted here | Lowest-priority external verification, still not claimed complete |
| Storage integrity | Append-only evidence, role grants, content hashes, FKs, uniqueness, work-unit reservations | Staging historically reached `0021`; production is `0013` | Apply the final single `0022` head on the exact image |
| Observability | PostgreSQL authoritative ledger, typed Langfuse observations, explicit remote query-back before `exported` | Zero canonical Langfuse observations | Separate environment project/key binding and query-back required |
| Software assurance | Contract tests, corpus validators, SAST, dependency audits, secret scan, container and migration gates | Historical CI/local evidence | GitHub CI must pass on the exact final commit |
| Privacy | Synthetic fixtures, `contains_real_phi=false`, no prompt/response bodies exported to Langfuse | No final campaign to reconcile | Recheck frozen corpus and exact target binding before launch |

## Release evidence placeholders

These values are intentionally absent until they exist:

- final release commit and identical GitHub/GitLab `main` SHAs;
- authoritative GitHub Actions run URL and green result;
- final image digest and staging/production Railway deployment IDs;
- deployed single migration head `0022` at both stages;
- final authorized campaign/run/evidence identifiers;
- Langfuse expected/observed/missing/extra totals and recorded verification timestamp;
- deterministic baseline and authorized batched 100-case performance result;
- actual development/run cost and redacted invoice/usage exports;
- demo video URL and social-post URL;
- final manifest hash and compatible rollback image identity.

No credential value, session identifier, bearer token, target secret, or Langfuse key belongs in this
packet.

The bindable finalization ledger is
[`../../submission-artifacts/RELEASE_BINDING.md`](../../submission-artifacts/RELEASE_BINDING.md).
