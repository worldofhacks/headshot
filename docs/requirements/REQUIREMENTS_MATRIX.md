# Final requirements matrix

Audit timestamp: `2026-07-22T23:06:25Z`  
Audited commit: `7749fd598dee1a16ad4fd4d04a6ec37855c0ac2c`  
Canonical row-level ledger: [`REQUIREMENTS_MATRIX.csv`](REQUIREMENTS_MATRIX.csv)  
Fresh baseline: [`../evidence/baseline/2026-07-22-final-integration.md`](../evidence/baseline/2026-07-22-final-integration.md)

This is a review view of the canonical CSV. The CSV records, for every requirement, its source, checkpoint, status, owner, automated verification, evidence path, and remaining work. Status is deliberately strict:

- `complete`: implemented and supported by current evidence.
- `partial`: material implementation or proof remains.
- `missing`: the required capability or artifact does not yet exist.
- `blocked`: the remaining step requires a genuine human gate or external authorization; it is not inferred as complete.

## Status summary

| Scope | Complete | Partial | Missing | Blocked | Total |
|---|---:|---:|---:|---:|---:|
| Canonical PRD | 17 | 11 | 6 | 3 | 37 |
| Optional engineering deliverables | 7 | 9 | 1 | 1 | 18 |
| User deployment constraints | 1 | 5 | 0 | 1 | 7 |
| Implementation-lead acceptance | 0 | 7 | 1 | 2 | 10 |
| **All requirements** | **25** | **32** | **8** | **7** | **72** |

The public platform, target health boundary, deterministic suites, production container, security-tool baseline, dual remotes, and both `main` CI systems are verified. The authoritative offline slice now includes verified-signal Orchestration, a typed Red Team handoff, independent judging, draft-only Documentation, and blocked regression disposition. The decisive remaining path is deterministic regression execution and Judge calibration, followed by a distinct human Approver for one bounded synthetic staging campaign. Nothing below treats passive health checks as live-test authorization.

## Canonical PRD

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| PRD-01 | partial | Clinical Co-Pilot is testable locally and deployed | Add evidence for local testability or document the approved deployed-only exception. |
| PRD-02 | partial | Document changes required to make the target testable | The readiness/session contract is documented; measure issuer lifetime, exact expiry response, cookie requirements, and transport ceilings during an authorized synthetic-only run. |
| PRD-03 | blocked | Submit the deployed target URL and run live at every checkpoint | A distinct human Approver must authorize a bounded staging campaign; retain its authoritative trace. |
| PRD-04 | complete | Threat model covers all six mandated attack-surface categories | Keep the living model synchronized with measured behavior. |
| PRD-05 | partial | Each threat category records surface, impact, difficulty, and defenses | Replace defense hypotheses with measured evidence or an explicit not-exercisable reason. |
| PRD-06 | complete | Threat model begins with the required findings and coverage summary | None. |
| PRD-07 | partial | Adversarial suite has results across at least three categories | Persist authoritative deployed results for the nine cases; current results are local. |
| PRD-08 | complete | Every case has all required result fields | Continue schema validation in both CIs. |
| PRD-09 | blocked | Cases are reproducible/extensible and an agent runs live | Obtain distinct-Approver authorization and execute without exposing the Runner-only secret reference. |
| PRD-10 | complete | Architecture defines every agent role, responsibility, input, output, and coordination | Update after Orchestrator and Documentation implementations land. |
| PRD-11 | complete | Architecture covers communication, priority, regression, gates, deterministic checks, cost, limits, and state | Reconcile implementation drift before Final. |
| PRD-12 | complete | Architecture has the required summary and interaction diagram | Add a render-staleness gate before release. |
| PRD-13 | complete | System is genuinely multi-agent with distinct trust levels | Retain the four durable role identities and independent Judge boundary. |
| PRD-14 | partial | System generates, mutates, runs, judges, prioritizes, halts low-signal spend, and triggers regression | Add bounded novelty/search and target-version-triggered regression execution. |
| PRD-15 | complete | Independent Judge never downgrades a deterministic confirmed exploit | Retain deterministic-oracle precedence. |
| PRD-16 | complete | Model choices are deliberate and account for refusal, capability, cost, and independence | Record deployed model/version lineage in the first authorized campaign. |
| PRD-17 | partial | Red Team generates meaningful novel, mutated, multi-turn attacks | Add novelty scoring, clustering, refinement, minimization, and live evidence of novel variants. |
| PRD-18 | partial | Judge is consistently calibrated and drift-guarded | Implement dual-judge calibration, thresholds, false-negative/calibration metrics, kill-switch, invalidation, and human re-enable. |
| PRD-19 | complete | Orchestrator directs campaigns from verified observability | Retain hash verification, exact caps, and circuit breakers in deployed proof. |
| PRD-20 | complete | Documentation Agent converts confirmed exploits into reports | Draft generation is complete; publication remains human-gated. |
| PRD-21 | complete | Reports contain every mandated field | Keep every generated report contract-valid and unpublished by default. |
| PRD-22 | missing | A senior engineer can reproduce, validate, and fix from each report | Independently reproduce each genuine report; simulated triage does not count. |
| PRD-23 | missing | Versioned exploit store auto-replays and detects reappearance/cross-category regression | Implement store, worker, target-version trigger, and detection. |
| PRD-24 | partial | Regression admission/pass requires deterministic reproduction and the right reason | Admission is fail-closed; implement deterministic replay and the expected-safe oracle. |
| PRD-25 | complete | Humans can answer coverage, status, resilience, lifecycle, cost, and order questions | Deploy migration 0011; retain unavailable/null states when provider telemetry was not observed. |
| PRD-26 | complete | Observability is the Orchestrator decision substrate | Continue excluding raw spans and hash-invalid rows. |
| PRD-27 | partial | Human gates prevent autonomous critical publication/remediation | Connect Documentation/remediation to approval and run a two-real-user staging smoke. |
| PRD-28 | partial | Cases map relevant OWASP Web and LLM risks | Expand relevant category mappings; add API and MITRE ATLAS where applicable. |
| PRD-29 | complete | Repository includes setup, architecture, deployed links, and live-run instructions | Validate the documented expiry/rotation runbook during the first authorized run. |
| PRD-30 | complete | `USERS.md` defines users, workflows, use cases, and automation rationale | None. |
| PRD-31 | missing | A 3–5 minute demo shows live attacks and key decisions | Record after an authorized campaign, with no PHI or credentials. |
| PRD-32 | missing | At least three distinct genuine vulnerability reports exist | Continue authorized testing; count only confirmed, independently reproducible findings. |
| PRD-33 | missing | Actual cost and nonlinear 100/1K/10K/100K projections exist | Merge/recreate measured cost evidence including compute, storage, egress, CI, power, and human time. |
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
| OPT-04 | partial | Arbitration, contracts, migration notes, review, packets, and drills exist | Complete ATO/integration packets, current diffs/migrations, and the failure-drill matrix. |
| OPT-05 | partial | Build one component, inherit one, and lead a contract-only integration | Update the packet and prove the independent boundary on deployed staging. |
| OPT-06 | complete | Inter-agent communication uses versioned contracts with both-sided tests | Use contract stewardship for every change. |
| OPT-07 | partial | ATO packet contains diagrams, auth, dependencies, scans, evals, and postmortem | Assemble the full evidence-grounded packet. |
| OPT-08 | partial | Architecture discloses AI roles, verification/gates, residual risk, and drift correction | Reconcile deployed roles/models and link calibration/drift evidence. |
| OPT-09 | partial | Integration packet has diffs, ADRs, tests, dependency map, and proof | Refresh branch/commit/counts/interfaces and attach the deployed trace. |
| OPT-10 | complete | Breaking changes require versioning, migration, compatibility analysis, and both-sided tests | Human approval remains required if proposed. |
| OPT-11 | complete | Every agent defines typed success and known errors | Expand with new agents/scanners. |
| OPT-12 | partial | Pagination, rate limits, auth, and backoff/queue/abort are enforced | Add bounded list cursors and measured target/provider limits. |
| OPT-13 | complete | Exploit storage enforces quality, uniqueness, integrity, privacy, and duplicate rejection | Retain draft-only state and content-addressed evidence linkage. |
| OPT-14 | complete | API versioning, migrations, durable queue, and workflow state exist | Retain expand/contract discipline. |
| OPT-15 | partial | Data model documents ingestion, validation, lineage, access, reporting, and publication | Complete write authorities and ATO data dictionary/auth matrix. |
| OPT-16 | partial | Indexes and reproducible query/regression SLOs are verified | Measure and enforce query and regression SLOs in CI. |
| OPT-17 | missing | CPU, memory, latency, and throughput baseline exists for 100 cases/full regression | Add deterministic benchmark, raw metrics, environment, and later authorized Railway measurements. |
| OPT-18 | blocked | Authorized 100-case live stress run records required metrics and scaling change | Requires explicit load authorization and distinct approval. |

## User deployment constraints

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| USR-01 | partial | Host the full platform on Railway | Verify private Runner, Scheduler, PostgreSQL topology and record revisions. |
| USR-02 | complete | Clerk protects meaningful human-facing access | Perform an authenticated smoke without recording tokens. |
| USR-03 | partial | Backend-verified custom Organization permissions enforce RBAC | Verify exactly the Operator and Approver staging role assignments and remove retired roles; this is a human/admin-console action. |
| USR-04 | blocked | Two different humans launch and approve | Perform the two-user staging approval and campaign without sharing credentials. |
| USR-05 | partial | Staging and production are isolated | Prove separate databases, keys, origins, organizations, allowlists, and credentials. |
| USR-06 | partial | Only Railway Web is public | Record domain inventory proving private services have no public domain. |
| USR-07 | partial | Authentication is never campaign authorization | Complete deployed denial drills and one separately authorized success trace. |

## Implementation-lead acceptance

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| LEAD-01 | partial | Authoritative deployed slice persists evidence, verdict, finding, regression disposition, observability, and abort partials | Offline slice is complete; obtain distinct human approval for deployed proof. |
| LEAD-02 | partial | Common attack/coverage engine supports state, content, lineage, mappings, novelty, clustering, minimization, replay, and bounded search | Extend the attack model and Red Team accordingly. |
| LEAD-03 | partial | Tool ecosystem has governed adapters, normalized findings, hashes, visibility, signals, and self-security | Add orchestration/correlation, retention, SBOM/container/IaC/license/TLS/header, and release-integrity evidence. |
| LEAD-04 | partial | All four agents satisfy their independent responsibilities | All four participate in the offline slice; finish Red Team novelty and Judge calibration. |
| LEAD-05 | partial | Regression, storage, queue, and observability implement durability, lineage, triggers, alerts, cost, trends, and reappearance | Implement regression execution/admission, triggers, detection, budget alerts, and measured SLOs. |
| LEAD-06 | partial | Contracts and failure drills cover producer/consumer behavior fail-closed | Add typed errors and the enumerated failure paths. |
| LEAD-07 | missing | Submission, ATO, integration, cost, performance, demo, devlog, and story artifacts are complete | Complete each with genuine, current evidence. |
| LEAD-08 | partial | All test, deployment, security, migration, UI, browser, load, container, and CI gates pass | Add performance/load gates and rerun after missing runtime work lands. |
| LEAD-09 | blocked | Every live campaign enforces the full authorization/safety envelope | Human Approver must authorize exact staging scope; retain a secret-free audit trail. |
| LEAD-10 | blocked | Deployed loop, calibration, tools, tests, evidence, remotes, and CIs satisfy Final | Complete partial/missing rows, then perform the genuine human-gated actions. |

## Hard blockers that cannot be manufactured

The matrix deliberately leaves the following incomplete until they genuinely happen: a distinct-person live-campaign approval; real Clerk role assignment and two-user smoke; authorization for active ZAP or 100-case live load; target/provider session material supplied by secret reference; critical publication/remediation approval; three confirmed and independently reproducible vulnerabilities; demo/video/social publication. Passive probes, mocks, deterministic fixtures, and simulated triage evidence do not satisfy these rows.
