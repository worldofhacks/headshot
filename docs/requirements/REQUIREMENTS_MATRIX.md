# Pre-release requirements matrix

Packet preparation base: `f39e22722d3b4e256110ac5be5ce160a0ad654e4`
Canonical row-level ledger: [`REQUIREMENTS_MATRIX.csv`](REQUIREMENTS_MATRIX.csv)

This is a conservative source-and-evidence audit, not a final release attestation. It incorporates
the merged report corrections through PR #48, the staging `2069036e` / `0021` deployment proof, and
the current `0021` preparation-base source. It deliberately leaves the incoming `0022` runtime,
final SHA/CI/mirror, exact-image deployment, governed campaign, performance, cost/invoice, demo, and
publication rows incomplete.

Historical target captures exist, but no historical prose, fixture, mock, cassette, or taxonomy
mapping is treated as final-release evidence. Reports 004–006 contain embedded offline derivations;
no independent reviewer log or separately retained reproduction manifest closes the reproduction
rows. All six report files are human-authored. The runtime Documentation agent has not produced a
retained final-release report.

This is a review view of the canonical CSV. The CSV records, for every requirement, its source, checkpoint, status, owner, automated verification, evidence path, and remaining work. Status is deliberately strict:

- `complete`: implemented and supported by current evidence.
- `partial`: material implementation or proof remains.
- `missing`: the required capability or artifact does not yet exist.
- `blocked`: the remaining step requires a genuine human gate or external authorization; it is not inferred as complete.

## Status summary

| Scope | Complete | Partial | Missing | Blocked | Total |
|---|---:|---:|---:|---:|---:|
| Canonical PRD | 15 | 18 | 1 | 3 | 37 |
| Optional engineering deliverables | 6 | 10 | 1 | 1 | 18 |
| User deployment constraints | 0 | 6 | 0 | 1 | 7 |
| Implementation-lead acceptance | 0 | 8 | 0 | 2 | 10 |
| **All requirements** | **21** | **42** | **2** | **7** | **72** |

The preparation base has one migration head at `0021`. Staging historically proves Runner-first
deployment mechanics through `0021`; production is still `23490ea` / `0013`. Source tests cover four
durable role identities, but governed production composition and revision `0022` are incoming.
Deterministic oracles remain authoritative unless the exact model Judge calibration is enabled.
GitHub Actions is the release CI authority; GitLab is an exact passive mirror. Nothing below treats
passive health, file presence, SDK flush, replay planning, or taxonomy mapping as live evidence.

## Canonical PRD

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| PRD-01 | partial | Clinical Co-Pilot is testable locally and deployed | Add evidence for local testability or document the approved deployed-only exception. |
| PRD-02 | partial | Document changes required to make the target testable | The readiness/session contract is documented; measure issuer lifetime, exact expiry response, cookie requirements, and transport ceilings during an authorized synthetic-only run. |
| PRD-03 | blocked | Submit the deployed target URL and run live at every checkpoint | A distinct human Approver must authorize a bounded staging campaign; retain its authoritative trace. |
| PRD-04 | complete | Threat model covers all six mandated attack-surface categories | Keep the living model synchronized with measured behavior. |
| PRD-05 | partial | Each threat category records surface, impact, difficulty, and defenses | Replace defense hypotheses with measured evidence or an explicit not-exercisable reason. |
| PRD-06 | complete | Threat model begins with the required findings and coverage summary | None. |
| PRD-07 | partial | Adversarial suite has results across at least three categories | Historical live captures exist; persist final-SHA recorder/Judge results for the frozen corpus without promoting `INDETERMINATE` to safe. |
| PRD-08 | complete | Every case has all required result fields | Continue schema validation in GitHub CI and mirror the exact green commit to GitLab. |
| PRD-09 | blocked | Cases are reproducible/extensible and an agent runs live | Obtain distinct-Approver authorization and execute without exposing the Runner-only secret reference. |
| PRD-10 | complete | Architecture defines every agent role, responsibility, input, output, and coordination | Keep it synchronized with the deployed composition. |
| PRD-11 | complete | Architecture covers communication, priority, regression, gates, deterministic checks, cost, limits, and state | Keep implementation/live-proof status explicit. |
| PRD-12 | complete | Architecture has the required summary and interaction diagram | Add a render-staleness gate before release. |
| PRD-13 | complete | System is genuinely multi-agent with distinct trust levels | Retain the four durable role identities and independent Judge boundary. |
| PRD-14 | partial | System generates, mutates, runs, judges, prioritizes, halts low-signal spend, and triggers regression | Add bounded novelty/search and target-version-triggered regression execution. |
| PRD-15 | complete | Independent Judge never downgrades a deterministic confirmed exploit | Retain deterministic-oracle precedence. |
| PRD-16 | partial | Model choices are deliberate and account for refusal, capability, cost, and independence | Hosted Red Team generation is not composed into the Runner; prove all returned identities in one authorized deployment. |
| PRD-17 | partial | Red Team generates meaningful novel, mutated, multi-turn attacks | Add novelty scoring, clustering, refinement, minimization, and live evidence of novel variants. |
| PRD-18 | partial | Judge is consistently calibrated and drift-guarded | Consume the security owner's exact-identity calibration evidence; until enabled, keep the model advisory and deterministic oracles decisive. |
| PRD-19 | complete | Orchestrator directs campaigns from verified observability | Retain hash verification, exact caps, and circuit breakers in deployed proof. |
| PRD-20 | partial | Documentation Agent converts confirmed exploits into reports | The code path is tested, but no retained final-release report was generated by the runtime agent; all current report files are human-authored. |
| PRD-21 | complete | Reports contain every mandated field | Keep every generated report contract-valid and unpublished by default. |
| PRD-22 | partial | A senior engineer can reproduce, validate, and fix from each report | Report files exist; consume owner validation and independently reproduce each claimed genuine result. |
| PRD-23 | partial | Versioned exploit store auto-replays and detects reappearance/cross-category regression | Storage and target-version planning exist; execute authorization-bound replays and add reappearance/cross-category analysis. |
| PRD-24 | partial | Regression admission/pass requires deterministic reproduction and the right reason | Admission is fail-closed; implement deterministic replay and the expected-safe oracle. |
| PRD-25 | complete | Humans can answer coverage, status, resilience, lifecycle, cost, and order questions | Deploy the single `0022` head, query Langfuse back, and retain unavailable/null/estimated states. |
| PRD-26 | complete | Observability is the Orchestrator decision substrate | Continue excluding raw spans and hash-invalid rows. |
| PRD-27 | partial | Human gates prevent autonomous critical publication/remediation | Add distinct raiser/approver and missing-lineage rejection for finding approval in application and database, then run a two-user smoke. |
| PRD-28 | partial | Cases map relevant OWASP Web and LLM risks | Expand relevant category mappings; add API and MITRE ATLAS where applicable. |
| PRD-29 | complete | Repository includes setup, architecture, deployed links, and live-run instructions | Validate the documented expiry/rotation runbook during the first authorized run. |
| PRD-30 | complete | `USERS.md` defines users, workflows, use cases, and automation rationale | None. |
| PRD-31 | missing | A 3–5 minute demo shows live attacks and key decisions | Record after an authorized campaign, with no PHI or credentials. |
| PRD-32 | partial | At least three distinct genuine vulnerability reports exist | Six files exist; count only owner-validated, independently reproducible reports backed by authorized evidence. |
| PRD-33 | partial | Actual cost and nonlinear 100/1K/10K/100K projections exist | The nonlinear D17 model exists; populate it with actual development spend and measured runtime inputs. |
| PRD-34 | blocked | Public platform runs live tests against the deployed target | Platform and target are healthy; distinct human approval remains required. |
| PRD-35 | partial | Final social post describes the platform and tags GauntletAI | Evidence-bound draft exists; fill only from the final manifest, then publish after the demo. |
| PRD-36 | partial | Platform discovers, evaluates, reproduces, documents, prevents regressions, and adapts | Complete deterministic regression replay, calibration, and deployed feedback-loop proof. |
| PRD-37 | complete | No real PHI appears anywhere | Keep all live campaigns synthetic-only. |

## Optional engineering deliverables

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| OPT-01 | complete | Every case is boundary, invariant, or regression | None. |
| OPT-02 | partial | Build-versus-configure record covers tools, platforms, coverage, cost, governance, and gaps | Add licensing, CI, portability, healthcare/privacy, and remaining-gap rows for every named product and Burp tier. |
| OPT-03 | complete | Triage at least ten simulated findings | Preserve simulated provenance separately from genuine findings. |
| OPT-04 | partial | Arbitration, contracts, migration notes, review, packets, and drills exist | Packets and compatibility references through `0021` exist; attach incoming `0022`, final results, remaining drills, and a deployed trace. |
| OPT-05 | partial | Build one component, inherit one, and lead a contract-only integration | Update the packet and prove the independent boundary on deployed staging. |
| OPT-06 | partial | Inter-agent communication uses versioned contracts with both-sided tests | Package contracts/tests exist; publish the required literal repository-root `/contracts` copy. |
| OPT-07 | partial | ATO packet contains diagrams, auth, dependencies, scans, evals, and postmortem | Structure is assembled; replace pre-release placeholders with exact final evidence. |
| OPT-08 | partial | Architecture discloses AI roles, verification/gates, residual risk, and drift correction | Source status is reconciled; attach final Judge and deployed-identity evidence. |
| OPT-09 | partial | Integration packet has diffs, ADRs, tests, dependency map, and proof | Bind exact final results and attach the authorized deployed trace/query-back. |
| OPT-10 | complete | Breaking changes require versioning, migration, compatibility analysis, and both-sided tests | Human approval remains required if proposed. |
| OPT-11 | complete | Every agent defines typed success and known errors | Expand with new agents/scanners. |
| OPT-12 | partial | Pagination, rate limits, auth, and backoff/queue/abort are enforced | SSE has a cursor and REST has fixed windows; add general list pagination where needed and measure external limits. |
| OPT-13 | complete | Exploit storage enforces quality, uniqueness, integrity, privacy, and duplicate rejection | Retain draft-only state and content-addressed evidence linkage. |
| OPT-14 | complete | API versioning, migrations, durable queue, and workflow state exist | Retain expand/contract discipline. |
| OPT-15 | partial | Data model documents ingestion, validation, lineage, access, reporting, and publication | ATO flow/auth artifacts exist; bind them to final live lineage, grants, retention, and publication evidence. |
| OPT-16 | partial | Indexes and reproducible query/regression SLOs are verified | Measure and enforce query and regression SLOs in CI. |
| OPT-17 | missing | CPU, memory, latency, and throughput baseline exists for 100 cases/full regression | The report library has tests but no retained representative producer output; capture and retain the deterministic baseline and final batched run. |
| OPT-18 | blocked | Authorized 100-case live stress run records required metrics and scaling change | Requires exact authorization by distinct principals; batch under `HOSTED_MAX_PHYSICAL_CALLS=56` and aggregate rather than raising the cap. |

## User deployment constraints

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| USR-01 | partial | Host the full platform on Railway | Staging historically reached `2069036e` / `0021`; deploy and verify the exact final `0022` commit/image on every service and environment. |
| USR-02 | partial | Clerk protects meaningful human-facing access | Source enforcement and unauthenticated denial are tested; perform the signed-in exact-Organization/custom-permission smoke without recording tokens. |
| USR-03 | partial | Backend-verified custom Organization permissions enforce RBAC | Verify exactly the Operator and Approver staging role assignments and remove retired roles; this is a human/admin-console action. |
| USR-04 | blocked | Two different humans launch and approve | Perform the two-user staging approval and campaign without sharing credentials. |
| USR-05 | partial | Staging and production are isolated | Prove separate databases, keys, origins, organizations, allowlists, and credentials. |
| USR-06 | partial | Only Railway Web is public | The older release met the boundary; re-prove it for the exact final release. |
| USR-07 | partial | Authentication is never campaign authorization | Complete deployed denial drills and one separately authorized success trace. |

## Implementation-lead acceptance

| ID | Status | Requirement | Remaining work / proof |
|---|---|---|---|
| LEAD-01 | partial | Authoritative deployed slice persists evidence, verdict, finding, regression disposition, observability, and abort partials | Offline slice is complete; obtain distinct human approval for deployed proof. |
| LEAD-02 | partial | Common attack/coverage engine supports state, content, lineage, mappings, novelty, clustering, minimization, replay, and bounded search | Extend the attack model and Red Team accordingly. |
| LEAD-03 | partial | Tool ecosystem has governed adapters, normalized findings, hashes, visibility, signals, and self-security | Add orchestration/correlation, retention, SBOM/container/IaC/license/TLS/header, and release-integrity evidence. |
| LEAD-04 | partial | All four agents satisfy their independent responsibilities | Four durable roles are tested; compose hosted Red Team generation, consume final Judge evidence, and prove deployment. |
| LEAD-05 | partial | Regression, storage, queue, and observability implement durability, lineage, triggers, alerts, cost, trends, and reappearance | Implement regression execution/admission, triggers, detection, budget alerts, and measured SLOs. |
| LEAD-06 | partial | Contracts and failure drills cover producer/consumer behavior fail-closed | Add typed errors and the enumerated failure paths. |
| LEAD-07 | partial | Submission, ATO, integration, cost, performance, demo, devlog, and story artifacts are complete | ATO/postmortem/submission structures exist; attach final release/campaign/query-back/performance/invoice evidence and real demo/social URLs. |
| LEAD-08 | partial | All test, deployment, security, migration, UI, browser, load, container, and release gates pass | Run all gates on the exact final SHA; GitHub Actions is authoritative and GitLab is its exact mirror. |
| LEAD-09 | blocked | Every live campaign enforces the full authorization/safety envelope | Human Approver must authorize exact staging scope; retain a secret-free audit trail. |
| LEAD-10 | blocked | Deployed loop, calibration, tools, tests, evidence, remotes, and authoritative CI satisfy Final | Complete partial/missing rows, obtain green GitHub Actions, mirror the SHA, then perform genuine human-gated actions. |

## Hard blockers that cannot be manufactured

The matrix deliberately leaves the following incomplete until they genuinely happen: a distinct-person live-campaign approval; real Clerk role assignment and two-user smoke; authorization for active ZAP or 100-case live load; target/provider session material supplied by secret reference; critical publication/remediation approval; three confirmed and independently reproducible vulnerabilities; demo/video/social publication. Passive probes, mocks, deterministic fixtures, and simulated triage evidence do not satisfy these rows.
