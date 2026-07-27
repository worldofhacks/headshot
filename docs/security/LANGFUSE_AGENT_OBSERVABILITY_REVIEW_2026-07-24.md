# Langfuse agent observability review

> **Historical audit with a current correction (2026-07-26).** Preserve the findings below as evidence
> for the reviewed commit; do not treat its deployment snapshot as current. Release `456d6e5` now
> persists logical agent executions, physical provider invocations/events, target calls, tokens,
> measured provider cost, and attempt lineage in PostgreSQL. In run `50da57b…`, all 36 agent and 16
> target Langfuse deliveries remained `queued`, and the campaign verifier refuses non-completed runs.
> Physical provider attempts are not yet complete first-class Langfuse observations. See
> [`../CURRENT_STATE.md`](../CURRENT_STATE.md) and [`../../PLAN.md`](../../PLAN.md).

**Date:** 2026-07-24  
**Scope:** Canonical Orchestrator, Red Team, Judge, and Documentation execution;
physical target requests; Langfuse export/query-back; Live, Agents, Costs, and Traces
console surfaces.  
**Method:** Repository and read-only deployed-state review. No deployment, migration,
campaign launch, target request, credential rotation, publication, or other external
mutation was performed.

> **Supersession note — 2026-07-25:** the deployed-state table below is a 2026-07-24 snapshot, not
> current staging state. Candidate `2069036e` was subsequently deployed Runner-first to staging and
> its database reached `0021`; `/health`, `/ready`, unauthenticated denial, and the console shell were
> verified. No campaign or provider/target call ran, so four-role live acceptance and Langfuse
> query-back remain open. Production was not promoted or re-verified.

## Verdict

The reviewed code now has an end-to-end, durable accounting and Langfuse projection path
for all four canonical agent roles. Each execution receives a PostgreSQL identity and
terminal latency/accounting row, a typed Langfuse `AGENT` with a child `GENERATION`, and a
shared campaign trace. The live console distinguishes queued/awaiting-verification, remotely
observed, disabled, and failed delivery. Per-role p50, p95, and spend are computed from the
authoritative ledger and exposed on Live, Agents, Costs, and Traces.

This was not live acceptance. At the time of this review, the deployed staging and production release
was on migration `0013`, both databases had zero `agent_executions`, and the configured
Langfuse project had no canonical agent observations. The displayed “not observed” state was
therefore truthful for that reviewed release.

## Read-only live evidence

| Check | Staging | Production |
|---|---:|---:|
| Deployed release | `23490ea` | `23490ea` |
| Web readiness | HTTP 200 | HTTP 200 |
| Unauthenticated `/api/v1/agents` | HTTP 401 | HTTP 401 |
| Deployed migration | `0013` | `0013` |
| Durable `agent_executions` | 0 | 0 |
| Langfuse `agent.orchestrator` / runtime | 0 / 0 | Same configured project |
| Langfuse `agent.red_team` / runtime | 0 / 0 | Same configured project |
| Langfuse `agent.judge` / runtime | 0 / 0 | Same configured project |
| Langfuse `agent.documentation` / runtime | 0 / 0 | Same configured project |

At review time, staging and production used the same Langfuse project identity. That prevented
strong environment isolation even when observation metadata carried an environment label; the later
staging smoke did not re-audit this configuration.

## Implemented controls

- `agent_executions` is the authoritative lifecycle and accounting ledger. Agent starts
  precede work; success and failure paths write terminal status, duration, hashes, tokens,
  measured spend, and delivery state.
- Orchestrator → Red Team → Judge → Documentation uses durable parent execution IDs.
  Documentation is present only for a durable finding and is tied to that finding.
- Every attempted case has its own Orchestrator, Red Team, and Judge execution. Red Team is
  bound one-way to the attempt after selection creates the durable attempt identity.
- A physical target request carries the trusted Red Team execution identity and is projected
  as a native child of that same-attempt Red Team `AGENT`.
- Langfuse receives hashes and byte counts, not raw agent inputs/outputs or credentials.
- Deterministic executions report measured zero spend. Hosted executions without complete
  provider usage remain `unavailable`; missing billing is not displayed as `$0`.
- SDK flush leaves durable delivery `queued`; it does not prove remote delivery. Only
  authenticated, exact remote query-back with the explicit write flag can atomically set
  `langfuse_status = 'exported'` and `langfuse_verified_at`.
- The verifier reconciles exact durable IDs, roles, per-attempt causality, native Langfuse
  parentage, terminal state, model, duration, hashes, tokens, cost, target requests, tenant,
  run, metadata environment, and native Langfuse environment. Request duration and cost use
  the canonical values returned by PostgreSQL, avoiding float/Numeric drift. The verifier is
  read-only unless `--record-verification` is explicitly supplied after successful query-back.
- Role p50 and p95 are calculated in PostgreSQL over the complete tenant/campaign/role
  ledger before console row limits are applied.
- The production container includes the verifier and smoke-tests its CLI.

## Remaining gaps

### LF-01 — Critical: deployed state has not crossed live acceptance

At review time the fix was not deployed, the repository head migration was not applied, and no newly
authorized live campaign had produced/query-verified the four agent roles. The later staging smoke
closed only the deployment and migration subparts: no campaign ran and no four-role query-back was
recorded. Local tests and doubles validate contracts only; they are not live evidence.

**Close by:** deploy one reviewed commit to Web, Runner, and Scheduler; apply the repository's sole
Alembic head — **`0021_four_role_agent_acceptance`** as of base `107c11c` *(this section previously
named `0016`, which now under-specifies by five revisions: `0017` hosted agent-execution lineage,
`0018` provider-call lineage, `0019` recordable provider identity, `0020` agent-acceptance authority,
`0021` four-role agent acceptance)*; launch a newly authorized campaign against the deployed target URL
using synthetic non-PHI data; then run the environment-bound verifier with `--record-verification`.

The deployed-state observations above (release on `0013`, zero `agent_executions` in both databases,
no canonical agent observations in Langfuse) are retained as the recorded 2026-07-24 snapshot and must
not be read as current staging state. The later staging migration to `0021` did not run a campaign.
Repository evidence still contains no hosted campaign call: no `provider_request_id`,
`returned_model`, or `measured_cost` value appears anywhere under `docs/evidence/**` or
`evals/results/**`.

### LF-02 — High: staging and production share a Langfuse project

Environment metadata cannot turn one shared project or keypair into separate trust
boundaries. It also makes cross-environment query and cost contamination easier.

**Close by:** provision separate Langfuse projects and distinct keypairs, rotate the current
credentials, bind each only to its matching private Runner, and rerun acceptance separately.

### LF-03 — High: projection recovery is process-memory dependent

Open Langfuse handles, parent observation IDs, and the pre-flush projection sets live
in Runner memory. A crash can leave durable rows queued/error and cannot reconstruct native
parentage. The code fails visibly instead of claiming success, but there is no durable
outbox/reconciler.

**Close by:** add a transactional observation outbox containing safe immutable projection
payloads and provider IDs, an idempotent private reconciler, restart recovery, retry limits,
dead-letter state, and query-back reconciliation.

### LF-04 — High: hosted-provider lineage is incomplete

The hosted runtime contract can carry usage, but the production campaign composition still
uses deterministic role implementations. Provider request ID, provider-returned model,
physical retry identity, cache/reasoning token detail, and durable provider-call lineage are
not complete.

**Close by:** compose each approved hosted assignment through the mandatory lifecycle and
persist provider-native request/response accounting metadata before enabling hosted agents
in production.

### LF-05 — Medium: read surfaces have fixed windows

Agent activity, Costs, and Traces use fixed SQL limits. Aggregate p50/p95 and spend are now
authoritative, but an operator may not be able to enumerate every contributing execution
from a long history.

**Close by:** add stable cursor pagination, total counts, campaign/configuration filters, and
an explicit “showing N of M” contract to every drill-in.

### LF-06 — Medium: query-back is an operator action

Remote observation verification is deliberately explicit but is not yet scheduled. Without
an operator running the verifier, even remotely visible rows remain `queued` and display as
“awaiting remote verification,” not “observed.”

**Close by:** run the same read-only verifier logic from a private scheduled reconciler and
retain the explicit write gate for verified IDs only.

### LF-07 — Medium: role aggregates do not provide every diagnostic slice

The Agents view aggregates by organization/role, and Costs groups campaign/role/provider/
model/mode. Configuration-version, target-version, surface, and time-window comparisons are
not all available in one drill-in.

**Close by:** add explicit filters and comparison dimensions without changing the durable
row-level accounting source.

### LF-08 — Medium: tool subprocesses are not first-class Langfuse observations

Garak, PyRIT, Giskard, Promptfoo, and ZAP-derived work retains provenance and target HTTP
requests are traced, but each isolated tool execution is not represented as its own typed
Langfuse span.

**Close by:** add safe, non-authoritative tool execution spans with tool/version, candidate
bundle hash, duration, exit classification, and resource accounting; never export hostile
raw content or let a tool span authorize traffic.

## Live activation sequence

1. Provision separate staging and production Langfuse projects and rotate credentials.
2. Review and commit one exact source state; require GitHub CI to pass on that commit and mirror the
   same commit to GitLab. GitLab is passive and has no runner gate.
3. Deploy the same commit Runner-first to Runner, Web, and Scheduler in staging and apply the exact
   packaged Alembic head.
4. Obtain exact target/corpus/budget authorization and launch a new campaign against the
   deployed target URL with synthetic non-PHI data.
5. Run `scripts/verify_langfuse_campaign.py --expected-environment staging
   --record-verification` for that campaign.
6. Confirm Live, Agents, Costs, and Traces show all four roles, remotely observed counts,
   per-role p50/p95, and truthful measured/unavailable spend.
7. Repeat the independently authorized process in production only after staging acceptance.
