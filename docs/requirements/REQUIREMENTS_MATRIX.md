# Final requirements matrix

Audit date: `2026-07-24`
Audited source implementation baseline: `ed41c6e20b7793c656c45aa6d05f8b9a0c476d1b`
Canonical row-level ledger: [`REQUIREMENTS_MATRIX.csv`](REQUIREMENTS_MATRIX.csv)
Fresh baseline: [`../evidence/baseline/2026-07-22-final-integration.md`](../evidence/baseline/2026-07-22-final-integration.md)
Release audit: [`../evidence/baseline/2026-07-23-role-agent-release-audit.md`](../evidence/baseline/2026-07-23-role-agent-release-audit.md)

This is a review view of the canonical CSV. The CSV records, for every requirement, its source, checkpoint, status, owner, automated verification, evidence path, and remaining work. Status is deliberately strict:

- `complete`: implemented and supported by current evidence.
- `partial`: material implementation or proof remains.
- `missing`: the required capability or artifact does not yet exist.
- `blocked`: the remaining step requires a genuine human gate or external authorization; it is not inferred as complete.

## Status summary

| Scope | Complete | Partial | Missing | Blocked | Total |
|---|---:|---:|---:|---:|---:|
| Canonical PRD | 16 | 16 | 2 | 3 | 37 |
| Optional engineering deliverables | 7 | 10 | 0 | 1 | 18 |
| User deployment constraints | 1 | 5 | 0 | 1 | 7 |
| Implementation-lead acceptance | 0 | 8 | 0 | 2 | 10 |
| **All requirements** | **24** | **39** | **2** | **7** | **72** |

At this audit, candidate source was `ed41c6e` with one migration head at `0018`, while GitHub
`main`, GitLab `main`, and Railway were still the older `23490ea` release with schema `0013`.
The prior topology and protected-route denial are verified; the candidate hosted-agent/Langfuse path
is not deployed or live-proved. Source tests now compose hosted
`Orchestrator -> Red Team -> Judge -> Documentation` provider parentage. The Red Team generates one
traced variant per selected frozen seed, but quarantines/discards that unreviewed text and dispatches
only the byte-exact authorized seed. The security-owner model calibration is not human-enabled and
its identities drift from the candidate's exact provider routes, so the model Judge remains
advisory/fail-closed and deterministic oracles are decisive. GitHub Actions is the release CI
authority; GitLab is an exact passive mirror. Nothing below treats passive health, file presence,
SDK flush, replay planning, taxonomy mapping, or source tests as live evidence.

## Canonical PRD

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| PRD-01 | partial | Clinical Co-Pilot is testable locally and deployed | Add evidence for local testability or document the approved deployed-only exception. |
| PRD-02 | partial | Document changes required to make the target testable | The readiness/session contract is documented; measure issuer lifetime, exact expiry response, cookie requirements, and transport ceilings during an authorized synthetic-only run. |
| PRD-03 | blocked | Submit the deployed target URL and run live at every checkpoint | A distinct human Approver must authorize a bounded staging campaign; retain its authoritative trace. |
| PRD-04 | complete | Threat model covers all six mandated attack-surface categories | Keep the living model synchronized with measured behavior. |
| PRD-05 | partial | Each threat category records surface, impact, difficulty, and defenses | Replace defense hypotheses with measured evidence or an explicit not-exercisable reason. |
| PRD-06 | complete | Threat model begins with the required findings and coverage summary | None. |
| PRD-07 | partial | Adversarial suite has results across at least three categories | Persist results for the security owner's exact frozen corpus; checked-in cases do not prove a live campaign. |
| PRD-08 | complete | Every case has all required result fields | Continue schema validation locally and in authoritative GitHub CI. |
| PRD-09 | blocked | Cases are reproducible/extensible and an agent runs live | Obtain distinct-Approver authorization and execute without exposing the Runner-only secret reference. |
| PRD-10 | complete | Architecture defines every agent role, responsibility, input, output, and coordination | Keep it synchronized with the deployed composition. |
| PRD-11 | complete | Architecture covers communication, priority, regression, gates, deterministic checks, cost, limits, and state | Keep implementation/live-proof status explicit. |
| PRD-12 | complete | Architecture has the required summary and interaction diagram | Add a render-staleness gate before release. |
| PRD-13 | complete | System is genuinely multi-agent with distinct trust levels | Retain the four durable role identities and independent Judge boundary. |
| PRD-14 | partial | System generates, mutates, runs, judges, prioritizes, halts low-signal spend, and triggers regression | Hosted generation is traced but quarantined; add reviewed-corpus promotion, bounded novelty/search, and target-version-triggered regression execution. |
| PRD-15 | complete | Independent Judge never downgrades a deterministic confirmed exploit | Retain deterministic-oracle precedence. |
| PRD-16 | partial | Model choices are deliberate and account for refusal, capability, cost, and independence | Exact routes/token parameters and all four roles are composed in source; prove returned identities and physical attempts in one authorized deployment. |
| PRD-17 | partial | Red Team generates meaningful novel, mutated, multi-turn attacks | One traced variant is quarantined per seed; add reviewed-corpus promotion, novelty scoring, clustering, refinement, minimization, and live evidence. |
| PRD-18 | partial | Judge is consistently calibrated and drift-guarded | The owner calibration is not enabled and its identities drift from candidate routes; keep the model advisory/fail-closed and deterministic oracles decisive. |
| PRD-19 | complete | Orchestrator directs campaigns from verified observability | Retain hash verification, exact caps, and circuit breakers in deployed proof. |
| PRD-20 | complete | Documentation Agent converts confirmed exploits into reports | Draft generation is complete; publication remains human-gated. |
| PRD-21 | complete | Reports contain every mandated field | Keep every generated report contract-valid and unpublished by default. |
| PRD-22 | partial | A senior engineer can reproduce, validate, and fix from each report | Report files exist; consume owner validation and independently reproduce each claimed genuine result. |
| PRD-23 | partial | Versioned exploit store auto-replays and detects reappearance/cross-category regression | Storage and target-version planning exist; execute authorization-bound replays and add reappearance/cross-category analysis. |
| PRD-24 | partial | Regression admission/pass requires deterministic reproduction and the right reason | Admission is fail-closed; implement deterministic replay and the expected-safe oracle. |
| PRD-25 | complete | Humans can answer coverage, status, resilience, lifecycle, cost, and order questions | Deploy through `0018`, query Langfuse back ID-for-ID, and retain unavailable/null/estimated states. |
| PRD-26 | complete | Observability is the Orchestrator decision substrate | Continue excluding raw spans and hash-invalid rows. |
| PRD-27 | partial | Human gates prevent autonomous critical publication/remediation | Connect Documentation/remediation to approval and run a two-real-user staging smoke. |
| PRD-28 | partial | Cases map relevant OWASP Web and LLM risks | Expand relevant category mappings; add API and MITRE ATLAS where applicable. |
| PRD-29 | complete | Repository includes setup, architecture, deployed links, and live-run instructions | Validate the documented expiry/rotation runbook during the first authorized run. |
| PRD-30 | complete | `USERS.md` defines users, workflows, use cases, and automation rationale | None. |
| PRD-31 | missing | A 3–5 minute demo shows live attacks and key decisions | Record after an authorized campaign, with no PHI or credentials. |
| PRD-32 | partial | At least three distinct genuine vulnerability reports exist | Six files exist; count only owner-validated, independently reproducible reports backed by authorized evidence. |
| PRD-33 | partial | Actual cost and nonlinear 100/1K/10K/100K projections exist | The nonlinear D17 model exists; populate it with actual development spend and measured runtime inputs. |
| PRD-34 | blocked | Public platform runs live tests against the deployed target | Platform and target are healthy; distinct human approval remains required. |
| PRD-35 | missing | Final social post describes the platform and tags GauntletAI | Draft now; human publication follows live demo evidence. |
| PRD-36 | partial | Platform discovers, evaluates, reproduces, documents, prevents regressions, and adapts | Complete deterministic regression replay, calibration, and deployed feedback-loop proof. |
| PRD-37 | complete | No real PHI appears anywhere | Keep all live campaigns synthetic-only. |

## Optional engineering deliverables

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| OPT-01 | complete | Every case is boundary, invariant, or regression | None. |
| OPT-02 | partial | Build-versus-configure record covers tools, platforms, coverage, cost, governance, and gaps | Add licensing, CI, portability, healthcare/privacy, and remaining-gap rows for every named product and Burp tier. |
| OPT-03 | complete | Triage at least ten simulated findings | Preserve simulated provenance separately from genuine findings. |
| OPT-04 | partial | Arbitration, contracts, migration notes, review, packets, and drills exist | Packets and notes through `0018` exist; attach final results, remaining drills, and a deployed trace. |
| OPT-05 | partial | Build one component, inherit one, and lead a contract-only integration | Update the packet and prove the independent boundary on deployed staging. |
| OPT-06 | complete | Inter-agent communication uses versioned contracts with both-sided tests | None; retain CI-enforced byte identity between the package authority and published root `/contracts`. |
| OPT-07 | partial | ATO packet contains diagrams, auth, dependencies, scans, evals, and postmortem | Structure is assembled; replace pre-release placeholders with exact final evidence. |
| OPT-08 | partial | Architecture discloses AI roles, verification/gates, residual risk, and drift correction | Quarantined generation and Judge identity drift are disclosed; attach final owner evidence and deployed identities. |
| OPT-09 | partial | Integration packet has diffs, ADRs, tests, dependency map, and proof | Current `0018` routes, parentage, lineage, and query-back are documented; attach final results and the authorized deployed trace. |
| OPT-10 | complete | Breaking changes require versioning, migration, compatibility analysis, and both-sided tests | Human approval remains required if proposed. |
| OPT-11 | complete | Every agent defines typed success and known errors | Expand with new agents/scanners. |
| OPT-12 | partial | Pagination, rate limits, auth, and backoff/queue/abort are enforced | Exact workload/target ceilings and bounded browser expiry are tested; add general REST pagination and measure external limits. |
| OPT-13 | complete | Exploit storage enforces quality, uniqueness, integrity, privacy, and duplicate rejection | Retain draft-only state and content-addressed evidence linkage. |
| OPT-14 | complete | API versioning, migrations, durable queue, and workflow state exist | Retain expand/contract discipline. |
| OPT-15 | partial | Data model documents ingestion, validation, lineage, access, reporting, and publication | ATO flow/auth artifacts exist; bind them to final live lineage, grants, retention, and publication evidence. |
| OPT-16 | partial | Indexes and reproducible query/regression SLOs are verified | Measure and enforce query and regression SLOs in CI. |
| OPT-17 | partial | CPU, memory, latency, and throughput baseline exists for 100 cases/full regression | Pre-run Railway/storage baselines exist; integrate the owner's representative 100-case result. |
| OPT-18 | blocked | Authorized 100-case live stress run records required metrics and scaling change | Requires explicit load authorization and distinct approval. |

## User deployment constraints

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| USR-01 | partial | Host the full platform on Railway | The older release is healthy; deploy and verify one exact final commit/schema on every service. |
| USR-02 | complete | Clerk protects meaningful human-facing access | Perform an authenticated smoke without recording tokens. |
| USR-03 | partial | Backend-verified custom Organization permissions enforce RBAC | Verify exactly the Operator and Approver staging role assignments and remove retired roles; this is a human/admin-console action. |
| USR-04 | blocked | Two different humans launch and approve | Perform the two-user staging approval and campaign without sharing credentials. |
| USR-05 | partial | Staging and production are isolated | Prove separate databases, keys, origins, organizations, allowlists, and credentials. |
| USR-06 | partial | Only Railway Web is public | The older release met the boundary; re-prove it for the exact final release. |
| USR-07 | partial | Authentication is never campaign authorization | Exact target, allowlist, synthetic, workload, budget/rate/timeout/expiry, and abort bindings are source-tested; complete deployed denial drills and one separately authorized success trace. |

## Implementation-lead acceptance

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| LEAD-01 | partial | Authoritative deployed slice persists evidence, verdict, finding, regression disposition, observability, and abort partials | Four-role/provider lineage is composed in source; obtain distinct human approval for deployed proof. |
| LEAD-02 | partial | Common attack/coverage engine supports state, content, lineage, mappings, novelty, clustering, minimization, replay, and bounded search | Extend the attack model and Red Team accordingly. |
| LEAD-03 | partial | Tool ecosystem has governed adapters, normalized findings, hashes, visibility, signals, and self-security | Add orchestration/correlation, retention, SBOM/container/IaC/license/TLS/header, and release-integrity evidence. |
| LEAD-04 | partial | All four agents satisfy their independent responsibilities | Four hosted roles are composed with quarantined Red-Team output; consume final Judge/corpus evidence and prove exact deployed identities/order. |
| LEAD-05 | partial | Regression, storage, queue, and observability implement durability, lineage, triggers, alerts, cost, trends, and reappearance | Implement regression execution/admission, triggers, detection, budget alerts, and measured SLOs. |
| LEAD-06 | partial | Contracts and failure drills cover producer/consumer behavior fail-closed | Add typed errors and the enumerated failure paths. |
| LEAD-07 | partial | Submission, ATO, integration, cost, performance, demo, devlog, and story artifacts are complete | Structures exist; attach final release/campaign/query-back evidence and real demo/social URLs. |
| LEAD-08 | partial | All test, deployment, security, migration, UI, browser, load, container, and release gates pass | Run all gates on the exact final SHA; GitHub Actions is authoritative and GitLab is its exact mirror. |
| LEAD-09 | blocked | Every live campaign enforces the full authorization/safety envelope | Human Approver must authorize exact staging scope; retain a secret-free audit trail. |
| LEAD-10 | blocked | Deployed loop, calibration, tools, tests, evidence, remotes, and authoritative CI satisfy Final | Complete partial/missing rows, obtain green GitHub Actions, mirror the SHA, and deploy staging; production still needs a human grant and confirmed DB rollback binding. |

## Hard blockers that cannot be manufactured

The matrix deliberately leaves the following incomplete until they genuinely happen: a frozen
security-owner 100-case corpus/result; a distinct-person live-campaign approval; real Clerk role
assignment and two-user smoke; authorization for active ZAP or 100-case live load; target/provider
session material supplied by secret reference; critical publication/remediation approval; three
confirmed and independently reproducible vulnerabilities; actual cost inputs; demo/video and social
URLs; a production deploy grant; and a confirmed database rollback binding. Passive probes, mocks,
deterministic fixtures, source tests, and simulated triage evidence do not satisfy these rows.
