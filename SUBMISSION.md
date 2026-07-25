# Headshot final submission index

This is the reviewer-facing index for Headshot / AgentForge. The canonical requirements are
[`Week_3_AgentForge.pdf`](Week_3_AgentForge.pdf). This package is intentionally **pre-release**:
final-SHA, deployment, campaign, performance, invoice, and publication values stay pending until
their retained artifacts exist.

Evidence labels mean:

- **Implemented** — present in the named source snapshot.
- **Tested** — exercised by a named check on a named commit.
- **Live-verified** — observed in an environment and bound to an exact commit, image, migration, and
  retained result.
- **Historical** — genuine retained evidence that is not evidence for the final release.
- **Pending** — unavailable or not yet verified. Pending work is never represented as complete.

## Release status

| Item | Status | Evidence |
|---|---|---|
| Packet preparation base | **Implemented** from `f39e22722d3b4e256110ac5be5ce160a0ad654e4`; this is not the shipped release | [`docs/evidence/ato/README.md`](docs/evidence/ato/README.md) |
| Preparation-base migration graph | **Tested** locally; one head at `0021` | [`docs/evidence/ato/AUDIT_AND_ROLLBACK.md`](docs/evidence/ato/AUDIT_AND_ROLLBACK.md) |
| Intended release migration | `0022`, **pending integration and single-head verification** | Final binding ledger: [`docs/submission-artifacts/RELEASE_BINDING.md`](docs/submission-artifacts/RELEASE_BINDING.md) |
| Final release commit, GitHub CI, and GitLab mirror | **Pending** | Populate only after GitHub CI is green on the exact candidate and GitLab resolves to the same SHA |
| Staging | **Historical deployment proof:** `2069036e`, schema `0021`; not the final release | [Staging](https://web-staging-8e30.up.railway.app) and [`ARCHITECTURE.md`](ARCHITECTURE.md) §12 |
| Production | **Older release:** `23490ea`, schema `0013`; final release not promoted | [Production](https://web-production-44528.up.railway.app) |
| Final four-role campaign and Langfuse query-back | **Pending** | No historical result is promoted to final-release evidence |
| Production promotion | **Authorized operationally, not yet executed** | Requires the exact assembled candidate, green GitHub CI, exact GitLab mirror, Runner-first migration/health proof, then Web |

The deployment links prove that Headshot services exist. They do **not** prove that the pending
`0022` release, final four-role composition, final corpus, measured performance, or final campaign
has been deployed or executed.

## Required submission artifacts

| Deliverable | Link | Current evidence status |
|---|---|---|
| GitHub repository | [worldofhacks/headshot](https://github.com/worldofhacks/headshot) | Repository exists; final `main` SHA and GitHub Actions URL pending |
| Setup and deployed links | [`README.md`](README.md) | Implemented; final deployment identity requires refresh |
| Threat model | [`THREAT_MODEL.md`](THREAT_MODEL.md) | Implemented; final target observations require reconciliation |
| Users and workflows | [`USERS.md`](USERS.md) | Implemented |
| Architecture and AI disclosure | [`ARCHITECTURE.md`](ARCHITECTURE.md) | Implemented; final runtime/deployment fields remain bindable |
| ATO-style packet | [`docs/evidence/ato/README.md`](docs/evidence/ato/README.md) | Packet structure complete; exact-release evidence pending |
| Sample incident/postmortem | [`docs/evidence/ato/SAMPLE_INCIDENT_POSTMORTEM.md`](docs/evidence/ato/SAMPLE_INCIDENT_POSTMORTEM.md) | Complete tabletop sample, explicitly not an actual incident |
| Integration packet | [`docs/integration/INTEGRATION_PACKET.md`](docs/integration/INTEGRATION_PACKET.md) | Current through preparation head `0021`; append final `0022`/SHA/CI/deploy evidence after integration |
| Requirements matrix | [`docs/requirements/REQUIREMENTS_MATRIX.md`](docs/requirements/REQUIREMENTS_MATRIX.md) | Conservative pre-release audit; final live rows remain pending |
| Eval corpus | [`evals/`](evals/) and [`docs/evidence/OWASP_COVERAGE_MATRIX.md`](docs/evidence/OWASP_COVERAGE_MATRIX.md) | Mapping is not demonstrated coverage; final frozen corpus manifest/run pending |
| Eval results | [`evals/results/`](evals/results/) | Historical artifacts only unless a file explicitly binds itself to the final release |
| Vulnerability reports | [`docs/vulnerabilities/README.md`](docs/vulnerabilities/README.md) | Findings 004 Medium, 005 Low, 006 Low; publication/final-run linkage remains explicit per report |
| Security-tool evidence | [`docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md`](docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md) | Historical pinned evidence; exact final-release scan pending |
| Cost analysis and invoice input | [`docs/cost/COST_ANALYSIS.md`](docs/cost/COST_ANALYSIS.md), [`docs/submission-artifacts/COST_INPUTS.md`](docs/submission-artifacts/COST_INPUTS.md) | Actual development/run spend and invoice export pending; configuration ceilings are not spend |
| Performance baseline and 100-case result | `docs/performance/` | **Pending**; do not infer measurements from test fixtures |
| Demo video (3–5 minutes) | Final URL pending | Human-owned and recorded after the final run |
| Deployed Clinical Co-Pilot target | [OpenEMR Clinical Co-Pilot](https://agent-production-9f62.up.railway.app) | Existing external target; any new campaign still requires the application’s exact two-principal authorization |
| Social post | [`docs/submission-artifacts/SOCIAL_POST_DRAFT.md`](docs/submission-artifacts/SOCIAL_POST_DRAFT.md) | Draft only; final facts, media, URL, and publication pending |

## Evidence packets

- [ATO scope, status, and reviewer guide](docs/evidence/ato/README.md)
- [Architecture and deployment](docs/evidence/ato/ARCHITECTURE_DEPLOYMENT.md)
- [Data flows and trust boundaries](docs/evidence/ato/DATA_FLOW_TRUST_BOUNDARIES.md)
- [Human and workload authorization model](docs/evidence/ato/AUTHORIZATION_MODEL.md)
- [Dependency and version inventory](docs/evidence/ato/DEPENDENCY_INVENTORY.md)
- [Security, eval, and synthetic-data evidence](docs/evidence/ato/SECURITY_AND_EVAL_EVIDENCE.md)
- [Audit, failure drills, and rollback](docs/evidence/ato/AUDIT_AND_ROLLBACK.md)
- [Sample incident and postmortem](docs/evidence/ato/SAMPLE_INCIDENT_POSTMORTEM.md)
- [Final release binding checklist](docs/submission-artifacts/RELEASE_BINDING.md)

## Final evidence still required

Release completion requires one exact commit with a single Alembic head at `0022`, green GitHub CI
on that commit, and an exact GitLab mirror. Deploy that same image Runner-first to staging and then
production; retain migration, health/readiness, protected-route, and console evidence. A live
campaign additionally requires distinct authenticated launcher and approver principals and must
produce content-addressed four-role, target-request, finding, cost, and Langfuse query-back evidence.
Actual billing exports, measured performance, the demo URL, and the published social URL remain
pending until supplied; none will be inferred.
