# Headshot final submission index

This is the reviewer-facing index for Headshot / AgentForge. The canonical requirements are
[`Week_3_AgentForge.pdf`](Week_3_AgentForge.pdf). Evidence is classified as:

- **Implemented** - present in the reviewed source snapshot.
- **Tested** - exercised by a named automated or manual check.
- **Live-verified** - observed on the deployed environment and bound to an exact release.
- **Pending** - unavailable, externally gated, or not yet verified. Pending work is not represented
  as complete.

## Release status

| Item | Status | Evidence |
|---|---|---|
| Source implementation baseline inspected for this packet | **Implemented** through `ed41c6e20b7793c656c45aa6d05f8b9a0c476d1b`; later documentation commits do not imply deployment | ATO packet root: [`docs/evidence/ato/README.md`](docs/evidence/ato/README.md) |
| Source migration graph | **Tested**; one head at `0018` | [`docs/evidence/ato/AUDIT_AND_ROLLBACK.md`](docs/evidence/ato/AUDIT_AND_ROLLBACK.md) |
| Final release commit, dual-remote identity, and authoritative GitHub CI | **Pending** | Must be recorded after final integration; the GitLab repository is a passive exact mirror |
| Deployed platform | **Live but stale**; repository evidence records `23490ea` and migration `0013`, not this source baseline | [Staging](https://web-staging-8e30.up.railway.app) - [Production](https://web-production-44528.up.railway.app) - [`docs/security/LANGFUSE_AGENT_OBSERVABILITY_REVIEW_2026-07-24.md`](docs/security/LANGFUSE_AGENT_OBSERVABILITY_REVIEW_2026-07-24.md) |
| Final staging acceptance, authorized campaign, and Langfuse query-back | **Pending** | The current deployed release has zero canonical `agent_executions` and no canonical Langfuse observations |
| Production promotion | **Pending human grant and rollback binding** | [`docs/evidence/ato/AUDIT_AND_ROLLBACK.md`](docs/evidence/ato/AUDIT_AND_ROLLBACK.md) |

The public deployment links above prove that a prior Headshot release exists. They do **not** prove
that the current four-agent, hosted-provider, migration `0018`, or Langfuse delivery implementation is
deployed.

## Required submission artifacts

| Deliverable | Link | Current evidence status |
|---|---|---|
| GitHub repository | [worldofhacks/headshot](https://github.com/worldofhacks/headshot) | Repository exists; final `main` SHA and authoritative CI URL pending |
| Setup and deployed links | [`README.md`](README.md) | Implemented; deployment identity requires final refresh |
| Threat model | [`THREAT_MODEL.md`](THREAT_MODEL.md) | Implemented |
| Users and workflows | [`USERS.md`](USERS.md) | Implemented |
| Architecture | [`ARCHITECTURE.md`](ARCHITECTURE.md) | Implemented; final deployment claims require reconciliation |
| Published inter-agent contracts | [`contracts/v1/`](contracts/v1/) | Implemented; byte-identical to the packaged runtime authority and enforced by contract tests |
| ATO evidence packet | [`docs/evidence/ato/README.md`](docs/evidence/ato/README.md) | Implemented as an evidence index; live-acceptance fields remain pending |
| Integration packet | [`docs/integration/INTEGRATION_PACKET.md`](docs/integration/INTEGRATION_PACKET.md) | Updated through source migration `0018`; deployed end-to-end proof pending |
| Eval corpus | [`evals/`](evals/) and [`docs/evidence/OWASP_COVERAGE_MATRIX.md`](docs/evidence/OWASP_COVERAGE_MATRIX.md) | Locally schema-validated; active seed records remain marked `NOT_EXECUTED` |
| Eval results | [`evals/results/README.md`](evals/results/README.md) | Classified historical artifacts; no result is presented as final-release Langfuse-reconciled evidence |
| Vulnerability reports | [`docs/vulnerabilities/README.md`](docs/vulnerabilities/README.md) | See the report owners' index; this submission index does not restate or alter its conclusions |
| Security-tool evidence | [`docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md`](docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md) | Historical pinned local/CI evidence; exact final-release scan pending |
| Cost analysis | [`docs/cost/COST_ANALYSIS.md`](docs/cost/COST_ANALYSIS.md) | Final measured analysis pending outside this packet |
| Performance and 100-case load evidence | [`docs/evidence/performance/README.md`](docs/evidence/performance/README.md) | **Pending**; only pre-run baselines exist and no authorized final-release 100-case live result is available |
| Demo video (3-5 minutes) | URL not supplied | **Pending**; no URL is available in the repository or task context |
| Deployed Clinical Co-Pilot target | [OpenEMR Clinical Co-Pilot](https://agent-production-9f62.up.railway.app) | Existing external target; a new attack run still requires exact authorization |
| Social post | URL not supplied; [`draft copy`](docs/demo/SOCIAL_POST_DRAFT.md) | **Pending**; a draft is not publication evidence |

## Evidence packets

- [ATO scope, status, and reviewer guide](docs/evidence/ato/README.md)
- [Architecture and deployment](docs/evidence/ato/ARCHITECTURE_DEPLOYMENT.md)
- [Data flows and trust boundaries](docs/evidence/ato/DATA_FLOW_TRUST_BOUNDARIES.md)
- [Human and workload authorization model](docs/evidence/ato/AUTHORIZATION_MODEL.md)
- [Dependency and version inventory](docs/evidence/ato/DEPENDENCY_INVENTORY.md)
- [Security, eval, and synthetic-data evidence](docs/evidence/ato/SECURITY_AND_EVAL_EVIDENCE.md)
- [Audit, failure drills, and rollback](docs/evidence/ato/AUDIT_AND_ROLLBACK.md)
- [Sample incident and postmortem](docs/evidence/ato/SAMPLE_INCIDENT_POSTMORTEM.md)
- [Requirements scorecard](docs/requirements/REQUIREMENTS_MATRIX.md)
- [Development log](docs/DEVLOG.md)
- [Executable demo script](docs/demo/MVP_DEMO_SCRIPT.md)
- [Performance evidence index](docs/evidence/performance/README.md)

## Final evidence still required

The submission is not release-complete until one exact commit is on both `origin/main` and
`gitlab/main`, GitHub CI is green for that commit, Railway staging exposes that same commit and the
latest single migration head, and an independently authorized synthetic campaign produces ordered
four-agent records plus exact Langfuse query-back reconciliation. Production remains blocked until a
human grants deployment and names a compatible rollback deployment and database recovery point. Demo
and social-post URLs must be supplied by the user; they will not be invented.
