# Console page-truth remediation plan

Status: planner draft for adversarial review
Planning base: `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
Requirements authority: `Week_3_AgentForge.pdf`
Build posture: production-grade
Ticket namespaces: `T-F19a` through `T-F19e` (tool-plan producers), `T-F19f` (authorized final
operational runs), and `T-F18a` through `T-F18p` (console consumers and release proof)

## Outcome

The console must answer the Week 3 observability questions from persisted, organization-scoped
evidence without turning configuration, global aggregates, or absence of evidence into a successful
execution claim. This plan removes the standalone Resilience page, but it does **not** remove
resilience or regression functionality. Those requirements move into **Coverage & Regression**,
which remains a first-class page because the PRD explicitly requires coverage, pass/fail by target
version, resilience-over-time, and regression state.

The route and page decisions are:

| Current surface | Final decision | Evidence rule |
|---|---|---|
| `/live` | Keep; stabilize selection and event reconciliation | Campaign and ScanPlan IDs remain durable across refreshes |
| `/findings` | Keep; expose the complete vulnerability report | Report fields come from the validated stored contract, never summary reconstruction |
| `/approvals` | Keep; add typed preflight, exact refusal reason, and confirmation | Launch remains disabled until server preflight and two-person authorization pass |
| `/coverage` | Rename to **Coverage & Regression** and merge regression history | Distinct case coverage and versioned regression results are separate measures |
| `/resilience` | Remove from navigation and page switch; temporary replace-redirect to `/coverage` | No regression records are deleted |
| `/tooling` | Keep; rebuild as a target/surface/campaign ScanPlan ledger | Every applicable tool has a persisted state and reason |
| Birdseye on `/live` | Keep; correct never-run and false-complete states | Health requires fresh evidence; edges require an observed handoff |
| `/agents` | Keep; consume T-F17f | Configured, staged, and provider-observed prompt/model facts remain separate |
| `/traces` | Keep; include target requests, agent executions, provider calls, and handoffs | Each row identifies its span kind and lineage |
| `/costs` | Keep; reconcile measured target and provider accounting | Unknown tokens/cost remain unknown; no inferred tokens-times-rate values |
| `/targets` | Keep; show canonical targets and enabled-surface readiness | Duplicate aliases and disabled-surface templates block launch |
| `/config` | Keep; rebuild as deployment/configuration truth | Installed, configured, activated, heartbeat, and execution evidence remain separate |
| `/audit` API | Keep permission-gated; subsume into Configuration | No separate navigation item; paged append-only history is part of the Config control-plane view |
| Shared tables/resources | Keep; add retry, cursor pagination, stable filters, and keyboard selection | High-volume views are bounded and accessible |

The Agents page and its OpenRouter prompt/model lineage are owned by T-F17f. Final-target
surface fanout is owned by T-F16f. Per-tool plan construction, execution fanout, authorization,
evidence, and event production are separately owned by T-F19a through T-F19e. T-F18 is a consumer
of those landed contracts and does not duplicate their implementation scopes.

## Requirements trace

| Requirement | Console proof | Tickets |
|---|---|---|
| PRD-21/22: complete, reproducible vulnerability reports | Finding detail exposes every required report field, evidence, trace, and validation disposition | T-F18f |
| PRD-23/24: versioned regression and right-reason validation | Coverage & Regression distinguishes cases, attempts, verdicts, dispositions, versions, and reappearance | T-F18c |
| PRD-25: coverage, pass/fail, resilience, findings, cost, agent order | Coverage, Birdseye, Findings, Traces, and Costs use authoritative projections | T-F18c, T-F18e, T-F18f, T-F18i, T-F18j, T-F18p |
| PRD-27/USR-04/USR-07: human gates and attack authorization | Approval detail runs preflight and preserves server refusal reasons; launch requires confirmation | T-F18g |
| OPT-12: pagination, rate limits, auth | Shared cursor/filter/retry controls and bounded collection APIs | T-F18b |
| LEAD-03: governed tool visibility and retained evidence | Tooling is scoped to exact target/version/surface/campaign/plan/tool | T-F18d |
| LEAD-05: durable lineage, cost, trends, reappearance | Birdseye, trace, cost, and coverage projections reconcile persisted records | T-F18c, T-F18e, T-F18i, T-F18j, T-F18p |
| Full page/module inventory | Agents, Configuration, embedded Audit, route registry, production UI proof, and final runs are explicit | T-F17f, T-F18m, T-F18l, T-F18n, T-F19f |

## Truth invariants

1. `never_observed` is not `ready`, `healthy`, `complete`, or `passed`.
2. Configured capability is not execution evidence.
3. A tool execution count may be shown only for its exact organization, target, target version,
   surface, campaign, ScanPlan, and tool identity.
4. A scan is complete only when every applicable plan item is terminal and plan/request/Judge/report
   counts reconcile. `skipped`, `not_applicable`, `blocked`, and `failed` remain distinct.
5. Coverage counts distinct authorized case identities. Retries and multiple physical requests are
   shown separately and cannot inflate coverage.
6. Regression status includes the target version and deterministic validation disposition. A model
   behavior change alone is not a right-reason pass.
7. A Birdseye handoff edge is active or complete only when a persisted source execution points to the
   persisted child execution or outbound request.
8. A report view is populated from the stored, schema-validated vulnerability report contract and
   remains visibly unpublished until the human gate is satisfied.
9. Command failures preserve the server `reason_code` and correlation/acknowledgement identifier.
10. Launch, abort, approval, denial, publication, resolution, and other spend-causing or destructive
    commands require an explicit confirmation step.
11. Unknown, malformed, unauthorized, stale, or unpaged data fails closed and offers a bounded retry.
12. Canonical navigation replaces invalid routes and `/resilience`; it does not silently render Live
    under a misleading URL.
13. `installed`, `configured`, `generated`, `executed`, and `evidenced/adjudicated` are independent
    tool facts. No one fact implies another.

## ScanPlan producer and fanout contract

T-F16f owns one authorized target's surface children. It does not own per-tool execution.
T-F19a through T-F19e close that distinct boundary:

1. T-F19a versions and persists the immutable per-tool ScanPlan, plan-item, event, artifact, candidate
   review, and reconciliation contracts.
2. T-F19b inventories pinned installations/configurations and runs the offline generation and
   exact-release assurance brokers for Garak, PyRIT, Giskard, Promptfoo, Semgrep, pip-audit,
   npm-audit, Gitleaks, and the Headshot workbench.
3. T-F19c owns separate two-person authorization and the bounded passive ZAP broker.
4. T-F19d fans plan items through private Runner workers, binds reviewed case hashes to authorized
   live attempts, persists artifacts/findings/errors, and reconciles every terminal state.
5. T-F19e instruments real control-plane, security-tool repository, outbound telemetry, and
   scheduler writes to emit persisted campaign, attempt, tool, agent, finding, approval, and
   component events plus a bounded authoritative polling fallback.

The console consumes that immutable ScanPlan. Until T-F19e is integrated and the selected campaign
has a plan, Tooling and Birdseye must say `blocked: scan_plan_not_persisted`; they must not synthesize
an all-tools success state.

Each displayed plan item requires:

- `scan_plan_id`, `campaign_run_id`, target and surface version identities;
- tool identifier/version/configuration hash and applicability decision;
- state: `planned | running | complete | skipped | not_applicable | blocked | failed`;
- bounded reason code and separate-authorization reference when applicable;
- broker/process identity, run nonce, timestamps, artifact hash/locator, candidate counts;
- accepted case hashes and corresponding live attempt/physical-request lineage;
- freshness and reconciliation state.

The user-requested “use all tools” behavior is satisfied only when every **applicable and authorized**
tool is present in the plan and reaches a truthful terminal state. Repository assurance tools remain
exact-release-SHA evidence; offline generators contribute reviewed cases; passive ZAP has its own
authorization. The console may not imply that those different modes are equivalent.

For each tool, the plan and console independently record:

- **installed**: pinned binary/package identity and verification source;
- **configured**: activated configuration hash and required credential-reference readiness;
- **generated**: candidate/artifact production and independent accepted/rejected review counts;
- **executed**: broker/process or authorized target-attempt lineage and terminal state;
- **evidenced/adjudicated**: retained artifact hash, normalized finding/error, Judge/report
  disposition, and freshness.

Negative tests must prove every combination in which one dimension exists and the next does not.

## Global ticket inventory and merge order

| Global wave | Ticket | Concern | Mechanical dependencies |
|---:|---|---|---|
| 29 | T-F18j | Backend-only known/partial/not-observed accounting/Birdseye bridge | T-F17b, T-F17c |
| 30 | T-F17e | Hosted capability/deployment gate | T-F17d, T-F18j |
| 31 | T-F17f | Agents configured-versus-observed UI | T-F17e |
| 32 | T-F19a | Versioned per-tool ScanPlan/persistence | T-F16f, T-F17f |
| 33 | T-F19b | Installation/configuration inventory; offline generation/release assurance brokers | T-F19a |
| 34 | T-F19c | Separate passive-ZAP authorization and broker | T-F19b |
| 35 | T-F19d | Runner fanout, artifact/finding persistence, reconciliation | T-F19c |
| 36 | T-F19e | Durable resource-event producers and polling fallback | T-F19d |
| 37 | T-F18a, T-F18b | Canonical routes; collection request/envelope/interaction seam | T-F16f, T-F17f, T-F19e |
| 38 | T-F18o | Bounded stable database paging for residual collections | T-F18b, T-F17f, T-F19e |
| 39 | T-F18c | Coverage & Regression projection/page/paging | T-F18a, T-F18o |
| 40 | T-F18d | Target/surface/campaign-scoped Tooling evidence | T-F18c, T-F19e |
| 41 | T-F18e | Birdseye runtime truth and scan-fanout visibility | T-F18d, T-F19e |
| 42 | T-F18f | Complete vulnerability-report projection/UI/paging | T-F18e, T-F18o |
| 43 | T-F18g | Command registry, preflight, reason fidelity, confirmation | T-F18b, T-F18f, T-F17f |
| 44 | T-F18h | Canonical target identity and enabled-surface readiness | T-F18g, T-F16f |
| 45 | T-F18i | Unified trace lineage and filters | T-F18b, T-F18h, T-F17f |
| 46 | T-F18p | Complete Costs API/UI/filter/stable-paging projection | T-F18j, T-F17f, T-F18b, T-F18o, T-F18i |
| 47 | T-F18k | Stable Live selection and event/poll reconciliation | T-F18d, T-F18e, T-F18g, T-F18h, T-F18i, T-F18p, T-F19e |
| 48 | T-F18m | Configuration truth and embedded Audit | T-F18k, T-F18o, T-F17f, T-F19e |
| 49 | T-F18l | Deterministic page registry/accessibility matrix | T-F16f, T-F17f, T-F19e, T-F18a through T-F18k, T-F18m, T-F18o, T-F18p |
| 50 | T-F18n | Exact-SHA authenticated production console evidence | T-F16f, T-F17f, T-F19e, T-F18l |
| 51 | T-F19f | Separately approved final per-target 100-case/tool-plan execution | T-F16f, T-F17f, T-F19e, T-F18n |

T-F18j branches from accepted T-F17b/c and is accepted before T-F17e. The later console integration
branch must contain T-F16f, T-F17f, T-F19e, accepted T-F18j, and
`docs/planning/full-console-remediation.md`; it is rebased once onto that exact commit before any
T-F18a-i/k-p RED dispatch. This is a mechanical base gate, not a prose prerequisite.

The sequence is intentionally conservative. `src/agentforge/api/postgres.py`,
`src/agentforge/api/read_models.py`, `console/src/types.ts`, and
`console/src/api/read-models.ts` are shared by T-F17f and most later tickets. T-F17f lands before
T-F19a; T-F19a through T-F19e serialize; then T-F18 projection tickets serialize. Only T-F18a and
T-F18b share wave 37, and their file scopes are disjoint.

## TDD execution protocol

Every ticket follows the same separation of powers:

1. Create the ticket branch/worktree from the current console integration head and record `pwd`,
   worktree root, branch, status, and base SHA.
2. A Test Agent writes only criterion-tagged deterministic tests and records clean RED evidence.
   External runtime behavior is represented by contract/e2e evidence, not mocked success claims.
3. An independent Test Reviewer attacks the tests for missing negative cases and lazy
   implementations. The Test Agent repairs findings; the orchestrator then freezes the reviewed
   test commit.
4. A separate Implementation Agent receives no test-write permission and implements only the
   ticket file scopes. A test dispute returns `BLOCKED(TEST_DISPUTE)`.
5. The orchestrator reruns the ticket gate script. A self-reported pass is not evidence.
6. Independent Code and Security reviewers inspect the frozen-test-to-GREEN diff. Critical or
   Important findings return to the implementer and require re-review.
7. Wave integration runs the repository gates, architecture-drift review, secret scan, and affected
   browser tests. Integration failures become new repair tickets; the integrator does not patch.

No implementation ticket may claim a live tool run, provider call, target request, deployment, or
human approval from fixtures. T-F18n owns authenticated production console evidence; T-F19f owns
the separately approved final target runs. Both remain blocked until their external authorities are
present.

## Release gates

The console branch is releasable only when:

- all Python, console unit, contract, and Playwright suites pass from a clean install;
- the production bundle and forbidden-language checks pass;
- every list endpoint enforces a bounded limit and stable cursor/filter semantics;
- automated accessibility checks plus manual keyboard flow pass on every retained route;
- browser tests prove `/resilience` replace-redirects to `/coverage` and invalid URLs normalize;
- seeded database tests prove cross-organization/target/surface/campaign tool evidence cannot bleed;
- seeded tests prove never-run agents/tools and missing ScanPlans cannot appear healthy or complete;
- vulnerability-report fields and human publication state survive API-to-UI round-trip;
- launch remains disabled on failed/unavailable/stale preflight and exact reason codes are visible;
- trace, cost, coverage, request, tool, agent, and report counts reconcile for one immutable run;
- gitleaks/secret scans are clean and no SID, bearer token, session token, or synthetic document
  bytes enter source control or browser evidence;
- the exact commit is green in GitHub and GitLab CI, deployed by an authorized owner, and verified
  through an authenticated Headshot Organization browser session.

T-F18l owns only `docs/evidence/console/deterministic/**`. T-F18n exclusively owns authenticated
production console evidence under `docs/evidence/console/production/**`. T-F19f exclusively owns
the final run package under `docs/evidence/final-target-runs/**` after exact-SHA dual CI, owner
deployment, Headshot authentication, distinct target approvals, and all target/runtime/tool
prerequisites. Operational tickets cannot repair code; a failure files a repair ticket and blocks
release.

## External prerequisites and blockers

- T-F16f must land the canonical target surface fanout before T-F19a.
- T-F17f must land provider-confirmed model, request, prompt, token, cost, and Agents UI truth before
  T-F19a and every shared projection/UI consumer.
- T-F19e must land the complete per-tool plan/fanout/event chain before downstream T-F18a-i/k-p RED
  begins.
- A distinct Headshot Approver is still required for each live campaign. Console UX cannot waive the
  two-person invariant.
- Authenticated production browser access is required for the final visual/interaction pass.
