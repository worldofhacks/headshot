# Console page-truth remediation plan

Status: planner draft for adversarial review
Planning base: `1ac3ee02be7855b638dd1fa43bb0612a3db5f025`
Requirements authority: `Week_3_AgentForge.pdf`
Build posture: production-grade
Ticket namespace: `T-F18a` through `T-F18l`

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
| `/traces` | Keep; include target requests, agent executions, provider calls, and handoffs | Each row identifies its span kind and lineage |
| `/costs` | Keep; reconcile measured target and provider accounting | Unknown tokens/cost remain unknown; no inferred tokens-times-rate values |
| `/targets` | Keep; show canonical targets and enabled-surface readiness | Duplicate aliases and disabled-surface templates block launch |
| Shared tables/resources | Keep; add retry, cursor pagination, stable filters, and keyboard selection | High-volume views are bounded and accessible |

The Agents page and its OpenRouter prompt/model lineage are owned by the separate `T-F17*` runtime
plan. Final-target adapter execution is owned by `T-F16*`. This plan consumes those contracts but
does not duplicate their implementation scopes.

## Requirements trace

| Requirement | Console proof | Tickets |
|---|---|---|
| PRD-21/22: complete, reproducible vulnerability reports | Finding detail exposes every required report field, evidence, trace, and validation disposition | T-F18f |
| PRD-23/24: versioned regression and right-reason validation | Coverage & Regression distinguishes cases, attempts, verdicts, dispositions, versions, and reappearance | T-F18c |
| PRD-25: coverage, pass/fail, resilience, findings, cost, agent order | Coverage, Birdseye, Findings, Traces, and Costs use authoritative projections | T-F18c, T-F18e, T-F18f, T-F18i, T-F18j |
| PRD-27/USR-04/USR-07: human gates and attack authorization | Approval detail runs preflight and preserves server refusal reasons; launch requires confirmation | T-F18g |
| OPT-12: pagination, rate limits, auth | Shared cursor/filter/retry controls and bounded collection APIs | T-F18b |
| LEAD-03: governed tool visibility and retained evidence | Tooling is scoped to exact target/version/surface/campaign/plan/tool | T-F18d |
| LEAD-05: durable lineage, cost, trends, reappearance | Birdseye, trace, cost, and coverage projections reconcile persisted records | T-F18c, T-F18e, T-F18i, T-F18j |

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

## Scan fanout visibility contract

The console does not schedule tools. It consumes the immutable ScanPlan created by the separate
tool-orchestration workstream. Until that plan exists, Tooling and Birdseye must say
`blocked: scan_plan_not_persisted`; they must not synthesize an all-tools success state.

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

## Ticket inventory

| Ticket | Concern | Wave | Key dependency |
|---|---|---:|---|
| T-F18a | Navigation, Resilience redirect, URL normalization | 1 | none |
| T-F18b | Bounded collections, retry, filters, keyboard selection | 1 | none |
| T-F18c | Coverage & Regression projection and page | 2 | T-F18a, T-F18b |
| T-F18d | Target/surface/campaign-scoped Tooling evidence | 3 | T-F18b; persisted ScanPlan contract |
| T-F18e | Birdseye runtime truth and scan-fanout visibility | 4 | T-F18d |
| T-F18f | Complete vulnerability-report projection and UI | 5 | T-F18b |
| T-F18g | Approval preflight, reason fidelity, confirmation | 6 | T-F18b |
| T-F18h | Canonical target identity and enabled-surface launch readiness | 7 | T-F18g; T-F16 canonical catalog |
| T-F18i | Unified trace lineage and filters | 8 | T-F18b; T-F17 provider lineage |
| T-F18j | Measured cost/token reconciliation and filters | 9 | T-F18i; T-F17 provider accounting |
| T-F18k | Stable Live selection and targeted SSE reconciliation | 10 | T-F18d, T-F18e, T-F18g, T-F18h |
| T-F18l | Full-route browser/accessibility/release proof | 11 | T-F18a..T-F18k |

The sequence is intentionally conservative. The current backend projection code is concentrated in
`src/agentforge/api/postgres.py`, while several page contracts share
`src/agentforge/api/read_models.py`, `console/src/types.ts`, and
`console/src/api/read-models.ts`. Tickets that touch those files are serialized rather than
pretending they can safely merge in parallel. T-F18a and T-F18b are the only same-wave tickets and
their scopes are disjoint.

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

No ticket may claim a live tool run, provider call, target request, deployment, or human approval
from fixtures. Those are separately authorized release evidence.

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

## External prerequisites and blockers

- `T-F16*` must provide one canonical target identity per final target and enabled, reviewed surface
  definitions. This plan will not guess which duplicate alias is authoritative.
- `T-F17*` must persist provider-confirmed model, request, prompt, token, and cost lineage. Trace and
  cost pages remain `not_observed` until that data exists.
- Tool-orchestration work must persist the immutable ScanPlan and per-tool execution lineage. This
  plan fails closed without it; it does not fabricate fanout.
- A distinct Headshot Approver is still required for each live campaign. Console UX cannot waive the
  two-person invariant.
- Authenticated production browser access is required for the final visual/interaction pass.
