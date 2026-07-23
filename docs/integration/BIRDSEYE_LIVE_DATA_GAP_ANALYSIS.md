# Birdseye live-data gap analysis

## Scope

This analysis compares the `Headshot Adversarial Testing Console-handoff.zip` reference with the
current Headshot control plane. The reference is useful as an interaction and information-
architecture target. It is not a data source and none of its demo topology, counters, timings, or
attention records may reach production.

The production invariant is:

> A value is displayed only when it came from an authenticated, organization-scoped server
> projection or from a versioned server configuration record. Missing runtime evidence is shown as
> empty, stale, degraded, or unavailable; it is never replaced by sample data.

## Reference UI assessment

The strongest reference pattern is the single operational overview. The upgraded version keeps
that interaction model but changes its hierarchy to answer the evaluator's security questions
before showing infrastructure:

- an outcome posture for category coverage, observed results, resilience, findings, and cost;
- a category-by-target-version evidence matrix;
- a persisted parent-linked sequence of actual agent work;
- a server-prioritized attention rail;
- a trust-zone execution map with inspectable runtime nodes;
- named handoff contracts rather than decorative connector lines;
- an ordered activity timeline;
- a responsive mobile view using the same underlying model, with attention before detail.

The reference's fixed nine-node demo graph, animated demo flows, prefilled alerts, and phone-frame
presentation are not production-safe. Runtime topology must follow actual registration/heartbeat
evidence, animations must stop when evidence is stale, and mobile must be a responsive layout of the
same data rather than a separate simulation.

## Gap closure

| Capability | Prior platform state | Live integration | Authoritative source | Status |
|---|---|---|---|---|
| Campaign identity and state | Campaign table and attempt-stream selection | Birdseye campaign summary | `campaign_runs`, `campaign_run_events`, exact authorization scope | Closed |
| Category coverage | Aggregate counts did not answer which required categories had evidence | Required/tested category count and case count | `campaign_attempts` joined to integrity-verified `attempt_result` | Closed |
| Category and version outcomes | Pass/fail data was split across screens | Held, exploited, and review outcomes by category and target version | integrity-verified attempt evidence plus independent `verdict` | Closed |
| Resilience direction | A separate resilience screen required interpretation | Current-versus-previous verified regression hold-rate delta | regression-class attempts, target version, and independent `verdict` | Closed |
| Vulnerability lifecycle | Findings existed but lifecycle was not summarized in the overview | Open, validating, resolved, and critical-open posture | campaign `finding` and tool `security_tool_findings` state | Closed |
| Cost trajectory | Current spend and cap were visible without a scaling answer | measured cost per attempt, cost velocity, and cap projection | `campaign_run_summaries` and authorized attempt cap | Closed |
| Current test priority | No outcome-level reason for the next area of work | persisted orchestrator directive, with deterministic least-tested fallback | `campaign.orchestrated` audit decision and verified category coverage | Closed |
| Actual agent sequence | Agent roles could be mistaken for a fixed left-to-right pipeline | parent-linked executions with role, phase, category, verdict, and finding | `agent_executions` joined to campaign evidence | Closed |
| Budget and policy rate | Separate cost/config screens | Operational constraints and liveness panel | `campaign_run_summaries`, `outbound_http_requests`, authorized scope caps | Closed |
| Queue state | Not visible in the main overview | Queued, leased, dead-letter counts | organization-owned `jobs` joined through `campaign_runs` | Closed |
| Verdict posture | Available outside topology | Confirmed, likely, and review counts | independent `verdict` rows | Closed |
| Runtime topology | Flat components table; missing runner/Langfuse placeholders were timestamped as if current | Trust-zone graph containing request-proven services, registered components, and configured agent roles | request-proven Web/PostgreSQL dependencies, `runtime_component_status`, agent assignments and `agent_executions` | Closed |
| Component freshness | Heartbeat timestamp only | freshness age, fresh/stale state, instances, current task | server clock and component heartbeat | Closed |
| Handoff visibility | Raw event records | Named, stateful contracts shown only when both endpoints exist | registered endpoints plus queue/attempt/telemetry records | Closed |
| Attention ordering | Distributed findings and approvals screens | Integrity → approval → finding → runtime priority | server-side evidence hash verification, pending authorization, finding and heartbeat records | Closed |
| Timeline | Expandable raw SSE payloads | Concise durable ordered timeline with cursor | organization-scoped `audit_events` | Closed |
| Live convergence | Projection refresh on snapshot/gap only | Every ordered delta schedules a coalesced projection refresh | authenticated SSE `/api/v1/events` | Closed |
| Inspector | Flat table rows | Interactive per-node evidence inspector | Birdseye node projection | Closed |
| Mobile | General responsive tables | campaign identity → attention → outcome posture → evidence, with topology and operational detail below | identical Birdseye response used on desktop | Closed |
| Global server indicator | Static “Live server data” copy | current server snapshot state and timestamp | protected `/api/v1/birdseye` response | Closed |
| Missing components | Fabricated runner/Langfuse placeholder heartbeat used request time | omitted until a real registration exists | `runtime_component_status` only | Closed |

## Server contract

`GET /api/v1/birdseye` is protected by the existing Clerk organization and
`org:console:read` boundary. The server constructs one database-transaction snapshot containing:

- the latest active or most recent campaign;
- a security posture projection that summarizes required/tested categories, integrity-verified
  cases, held/exploited/review outcomes, resilience direction, finding lifecycle, measured cost
  trajectory, and the current category priority;
- category and target-version outcomes derived only from integrity-verified evidence and an
  independent verdict;
- the latest parent-linked agent executions, including persisted role, phase, evidence
  association, verdict, finding, timing, and error state;
- budget, measured cost, policy rate cap, queue, verdict, and component health instrumentation;
- registry-derived runtime nodes with trust zone, freshness, runtime state, latency, queue, and
  target-access posture, including the registered Orchestrator, Red Team, Judge, and Documentation
  roles and their latest organization-scoped execution;
- named handoff edges whose endpoints both exist;
- server-ranked integrity, approval, finding, and component attention;
- the latest 50 durable audit events and their cursor.

The projection is validated by strict Python and TypeScript read contracts. Unknown fields,
malformed enum values, invalid timestamps, and missing required values fail closed as an
unavailable/invalid-response state.

The interface never labels an observed hold as "safe" or treats a missing category as a pass.
Missing evidence remains zero/unavailable, and a confirmed or likely exploit is always presented
as exploited.

## Post-implementation design review

| Canonical observability question | User-visible answer |
|---|---|
| What categories were tested, and how many cases per category? | Category coverage summary and the category-by-version matrix |
| What passed or failed across categories and system versions? | Held, exploited, and review counts per category/version; held is explicitly scoped to observed evidence |
| Is resilience improving over time? | Current and previous regression hold rates with their direction and delta |
| What is the vulnerability lifecycle? | Open, validating, resolved, and critical-open finding counts |
| What did the run cost, and how does it scale? | Spend/cap plus measured cost per attempt, velocity, and attempt-cap projection |
| What is each agent doing, and in what order? | Actual parent-linked execution records; the role registry is explicitly not execution order |

The resulting user journey is now: identify the target and campaign, see urgent intervention,
understand outcome posture, inspect evidence by category/version, inspect actual agent causality,
then move into trust boundaries, instrumentation, contracts, and raw activity. This order matches
an evaluator or operator's decision sequence and keeps infrastructure evidence available without
making it the primary story.

## Whole-console live-data audit

The remaining console screens already use authenticated server resources and retain explicit
empty/unavailable behavior:

| Screen | Protected source |
|---|---|
| Live / Attempt stream | campaigns, attempts, evidence, components, ordered SSE |
| Findings | findings and human decision history |
| Approvals | exact authorization requests and decisions |
| Coverage | verified evidence classification projection |
| Resilience | durable regression attempts and verdict status |
| Traces | sanitized outbound request telemetry |
| Costs | persisted campaign run accounting |
| Agents | server-owned agent registry, active/staged assignments, executions, tokens, cost and activity |
| Tooling | target/surface applicability plus recorded candidate, attempt, scan and finding evidence |
| Targets | versioned target and surface registry |
| Configuration | server-composed configuration snapshot and audit history |

No screen falls back to demo records. Security-tool and configuration values are versioned
server-owned catalog/configuration data, not browser claims; runtime status is shown only when
there is runtime evidence. Commands continue to wait for server acknowledgements and never
optimistically mutate authoritative state.

## Operational acceptance criteria

- Deploy the API and console together on the public Railway Web service.
- Keep runner, scheduler, and PostgreSQL private.
- Confirm `/api/v1/birdseye` is `401` without a Clerk session and `403` without the exact Headshot
  organization/permission.
- Start a synthetic-data-only authorized campaign and confirm queue, attempt, verdict, cost,
  heartbeat, attention, and timeline changes converge without reloading.
- Stop a private component and confirm it becomes stale after the server threshold; it must not
  continue to appear active.
- Verify a user from another organization cannot affect campaign, queue, verdict, finding, or
  audit values in the snapshot.
- Verify desktop and mobile layouts against the same response and explicit empty/degraded states.
- Push the release commit to both GitHub and GitLab and require both CI systems to pass.
