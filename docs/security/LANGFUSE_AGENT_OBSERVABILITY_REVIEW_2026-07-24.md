# Langfuse agent observability review

> **Supersession boundary — 2026-07-24.** The read-only deployment findings below remain valid for
> the observed `23490ea` / `0013` release. Its candidate-source conclusions were written before
> migration `0018`, durable physical provider-call lineage, exact route/token-parameter binding, and
> the current GitHub-authoritative/GitLab-mirror release rule. Use
> [`../evidence/ato/ARCHITECTURE_DEPLOYMENT.md`](../evidence/ato/ARCHITECTURE_DEPLOYMENT.md) and
> [`../integration/INTEGRATION_PACKET.md`](../integration/INTEGRATION_PACKET.md) for current source
> status. Nothing supersedes the need for a new staging deployment and exact Langfuse query-back.

**Date:** 2026-07-24  
**Scope:** Canonical Orchestrator, Red Team, Judge, and Documentation execution;
physical target requests; Langfuse export/query-back; Live, Agents, Costs, and Traces
console surfaces.  
**Method:** Repository and read-only deployed-state review. No deployment, migration,
campaign launch, target request, credential rotation, publication, or other external
mutation was performed.

## Verdict

The reviewed code now has an end-to-end, durable accounting and Langfuse projection path
for all four canonical agent roles. Each execution receives a PostgreSQL identity and
terminal latency/accounting row, a typed Langfuse `AGENT` with a child `GENERATION`, and a
shared campaign trace. The live console distinguishes queued/awaiting-verification, remotely
observed, disabled, and failed delivery. Per-role p50, p95, and spend are computed from the
authoritative ledger and exposed on Live, Agents, Costs, and Traces.

This is not yet live acceptance. The currently deployed staging and production release is
still on migration `0013`, both databases have zero `agent_executions`, and the configured
Langfuse project has no canonical agent observations. The displayed “not observed” state is
therefore truthful for the deployed release.

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

Staging and production currently use the same Langfuse project identity. That prevents
strong environment isolation even when observation metadata carries an environment label.

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

The fix is not deployed, migration `0016` is not applied, and no newly authorized live
campaign has produced/query-verified the four agent roles. Local tests and doubles validate
contracts only; they are not live evidence.

**Close by:** deploy one reviewed commit to Web, Runner, and Scheduler; apply `0016`; launch
a newly authorized campaign against the deployed target URL using synthetic non-PHI data;
then run the environment-bound verifier with `--record-verification`.

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
2. Review and commit one exact source state; push the same commit to both required remotes
   and require both CI systems to pass.
3. Deploy the same commit to Web, Runner, and Scheduler in staging and apply migration
   `0016`.
4. Obtain exact target/corpus/budget authorization and launch a new campaign against the
   deployed target URL with synthetic non-PHI data.
5. Run `scripts/verify_langfuse_campaign.py --expected-environment staging
   --record-verification` for that campaign.
6. Confirm Live, Agents, Costs, and Traces show all four roles, remotely observed counts,
   per-role p50/p95, and truthful measured/unavailable spend.
7. Repeat the independently authorized process in production only after staging acceptance.
