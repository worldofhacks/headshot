# Headshot cost analysis

## Status and evidence boundary

This document implements the method locked by
[DECISIONS.md D17](../planning/DECISIONS.md) and
[ARCHITECTURE.md §11](../../ARCHITECTURE.md) for **100, 1,000, 10,000, and 100,000 complete
test-runs**. A test-run is a bounded campaign execution, not an individual test case, model call, or
attempt. The number of attempts and agent calls inside a run must be measured rather than assumed.

**Evidence boundary re-stated 2026-07-25 at base `107c11c`** (the previous boundary was dated
2026-07-23 and two halves of it have since become false):

- **A live target *was* called.** Authorized synthetic-only runs against
  `https://agent-production-9f62.up.railway.app` are committed under `evals/results/` — four result
  groups, 39 adversarial verdict records. The earlier "no hosted model or live target was called"
  boundary no longer holds for the target half.
- **No hosted model has been called in a campaign.** No `provider_request_id`, `returned_model`, or
  `measured_cost` value appears anywhere in `docs/evidence/**` or `evals/results/**`. The one place a
  hosted role model is composed at all is a deliberately target-free acceptance harness
  (`src/agentforge/agent_acceptance.py`) whose output is recorded
  `quarantined_not_dispatched` with `target_call_limit: 0`.
- **The Railway staging baseline is now deployed, but not cost-measured.** Candidate `2069036e` was
  deployed Runner-first to the staging Web, Runner, Scheduler, and PostgreSQL topology; schema `0021`,
  `/health`, `/ready`, unauthenticated denial, and the console shell were verified. No campaign,
  provider call, or target call ran during that smoke, production remains unverified, and no signed-in
  Clerk acceptance was performed. No hosting, storage, egress invoice, billing export, or utilization
  record has been supplied for this release, so the platform-operations family remains unmeasured.

Still absent, and still the reason every number below is a symbol: any provider billing export, token
trace, local-capacity benchmark, deployed-platform invoice, or utilization measurement. Consequently:

- present MVP dollar spend is **TBD — unmeasured**;
- every tier total below is **projected, unmeasured**;
- symbols are required inputs, not disguised estimates; and
- test fixtures such as fake accounting values are not cost measurements.

A live-target execution boundary is not a monetary total. Developer tooling, hardware, labor, CI, and
hosting invoices have not been supplied, and **not one dollar figure in this repository comes from a
measured run.**

Two measurement-integrity defects that any future cost figure must route around:

1. **`measured_cost` for target requests is a configured constant, not a measurement.** The outbound
   telemetry layer defaults a per-request cost and multiplies it by request count. Any dollar figure
   derived from it describes an accounting cap, not spend. It was never exported to evidence in any
   case — the committed attempt manifests have no cost field at all.
2. **`target_version` is the adapter name, not a target build version**
   (`src/agentforge/policy/gateway.py:626`), so any per-version cost or regression comparison is keyed
   on a constant.

## Configured spend envelope (not a measurement)

These are the **committed ceilings** the code enforces. They bound spend; they do not report it. They
are recorded here because several documents priced roles that are not the configured ones — see
[`DECISIONS.md` D8 revision 2026-07-25](../planning/DECISIONS.md).

Hosted role set, frozen in code and rejected on deviation
(`src/agentforge/agents/hosted.py:31-38`, enforcement at `:352-353`):

| Role | Model ID (frozen) | Role spend ceiling (`hosted.py:39-45`) |
|---|---|---|
| `orchestrator` | `anthropic/claude-opus-4.8` | $1.50 |
| `red_team` | `qwen/qwen3.5-397b-a17b` | $1.00 |
| `judge` | `google/gemini-2.5-pro` | $4.00 |
| `documentation` | `openai/gpt-5.4` | $1.00 |

Envelope, same file: provider `openrouter` (`:26`), `HOSTED_MAX_PHYSICAL_CALLS = 56` (`:27`),
`HOSTED_MAX_MEASURED_USD = $10` (`:28`), `HOSTED_MAX_LOGICAL_RETRIES = 1` (`:29`),
`HOSTED_MAX_CONCURRENCY = 1` (`:30`). The four role ceilings sum to $7.50, inside the $10 envelope.

Campaign-side caps, committed at `docs/evidence/authorization-requests/caps.json` and mirrored in the
three target-catalog files: `budget_usd 1.00`, `max_attempts_per_run 40`, `logical_case_limit 40`,
`physical_request_limit 60`, `target_requests_per_second 0.5`, `run_timeout_seconds 1800`,
`target_retries_per_turn 1`.

**Per-model prices are not in this repository.** Runtime prices come from an operator-staged hosted
configuration set held in Postgres; `hosted.py` carries model IDs and ceilings but no prices. The only
committed per-model price literal is the `red_team` qwen entry in
[`docs/agents/RED_TEAM_MODEL_RESOLUTION.md`](../agents/RED_TEAM_MODEL_RESOLUTION.md) — a dated document
assertion, not a verified rate snapshot, and it covers one of four roles. Any tier projection must
therefore begin by capturing a dated rate snapshot for all four configured models; do not reuse a rate
quoted for a model this platform does not run.

## D17 method

Three cost families remain independent because they scale differently:

1. **Hosted-token inference** uses measured input/output tokens and the current provider's applicable
   on-demand, cached-input, and batch rates. Throughput is a latency/capacity constraint, not a token
   price divisor.
2. **Local or capacity-priced hosted-OSS inference** uses hardware amortization, power, operator time,
   reserved/burst accelerator time, and measured sustained capacity.
3. **Platform operations** keeps application hosting, Postgres/storage, observability, egress, and
   CI/development as separate fixed and variable lines.

Do not add token-priced and capacity-priced charges for the same inference workload. They are alternative
execution modes unless a measured run actually used both.

The forbidden shortcut is any form of `list price × assumed tokens × N` or
`list price / throughput`. Tier estimates must use measured aggregate workload for complete runs, current
rate snapshots, observed cache/batch classification, and measured infrastructure use.

## Required measurement inputs

Every input in this table is currently **TBD — projected, unmeasured** unless an owner supplies a dated,
authoritative measurement.

| Symbol | Required measured input |
|---|---|
| `N` | Complete test-runs in the tier: 100, 1,000, 10,000, or 100,000. |
| `A_N` | Total attempts adjudicated across the `N` complete runs. |
| `D_N` | Attempts conclusively decided by a trusted deterministic oracle/canary, requiring no primary LLM Judge call. |
| `X_N` | Attempts conclusively stopped before any LLM request by missing/malformed evidence, integrity failure, an uncalibrated category gate, or a pre-Judge timeout. Post-request timeouts, contradictions, and disagreements are not skips. |
| `E_N = A_N - D_N - X_N` | Measured attempts eligible for a primary LLM Judge request; validate that the three buckets are disjoint. Every initiated or billed request remains in the role call/token aggregates even when it times out or ends `INDETERMINATE`. |
| `s_N` | Approved, measured dual-judge sampling fraction over eligible non-oracle attempts; never implicitly 100%. |
| `Q_N` | Threshold-near/disputed attempts selected for secondary judging outside the random sample. |
| `G_N` | Actual total model-call count for scheduled ground-truth calibration at the tier/cadence, including every primary and independent calibration call. |
| `R_N`, `J_N`, `Doc_N`, `O_N` | Actual Red Team, Judge, Documentation, and Orchestrator model-call counts. |
| `U`, `C`, `Out` by role/mode | Measured uncached-input, cached-input, and output token aggregates. |
| `B` by provider/model/mode/date | Published token billing unit for the applicable rate; do not assume that every quote uses the same unit. |
| `P` by provider/model/mode/date | Current reporting-currency price per `B` input, cached-input, output, or batch tokens, captured with source/date and any dated FX conversion. |
| `W_r,N` | Measured role workload in one declared unit (for example, generated tokens at a fixed context mix) across the tier. |
| `Cap_r` | Measured sustained capacity in the same `W` units per accelerator-hour at the selected model, hardware, concurrency, and context mix. |
| `K_r,N`, `u_r,N` | Parallel accelerators assigned to the role and measured schedulable utilization in `(0, 1]`; `K × u` is effective parallel capacity for elapsed-time checks. |
| `F_N` | Confirmed, approved findings that trigger Documentation; do not substitute an assumed exploit rate. |
| `DBRows_N`, `DBIngestBytes_N` | Measured database rows and newly written database bytes. |
| `DBRetainedByteMonths_N`, `BackupByteMonths_N` | Measured database and backup byte-time over the projection accounting window. |
| `ObsEvents_N`, `ObsIngestBytes_N`, `ObsRetainedByteMonths_N` | Measured observability event count, ingested bytes, and retained byte-time. |
| `EgressBytes_N` | Measured billable outbound bytes, classified by destination/rate class. |
| `Peak_N`, `Window_N` | Measured peak concurrency and required completion window. |

Record distributions (at least median and tail), not only averages: long contexts, mutation loops, retries,
and multi-turn cases can make an average run non-representative.

## Family 1 — hosted-token inference

For each role `r` and pricing mode `m ∈ {on_demand, batch}`, use the measured token buckets for the
projected tier:

```text
Hosted_r(N) = Σ_m [
    (U_r,m,N   / B_input_r,m,date)  × P_input_r,m,date
  + (C_r,m,N   / B_cache_r,m,date)  × P_cached_input_r,m,date
  + (Out_r,m,N / B_output_r,m,date) × P_output_r,m,date
  + measured_request_or_tool_fees_r,m,N
]
```

Cache and batch effects appear only when traces show that input was actually cache-eligible/hit and work
was actually accepted in the applicable batch mode. No cache rate, discount, eligibility fraction, or
provider price is assumed here.

| Role | Workload accounting | Hosted cost status |
|---|---|---|
| Red Team | `R_N` includes only model-backed generation/mutation. Deterministic seed replay creates no inference call. Apply the hosted formula only when the Red Team uses token-priced hosted OSS. | `Hosted_RT(N)` = **TBD — projected, unmeasured** |
| Judge | Primary live subjects are `E_N`. Secondary live subjects are the deduplicated union of the approved sample from `E_N` and `Q_N`; never all live cases by default. Add the separate measured calibration calls `G_N`. Use actual billed calls, including only measured retries/fallbacks. Deterministic `D_N` and fail-closed `X_N` cases skip primary LLM judging. | `Hosted_Judge(N)` = **TBD — projected, unmeasured** |
| Documentation | `Doc_N = F_N` only when each approved finding produces one draft; otherwise use measured drafts/revisions. It scales with confirmed approved findings, not directly with `N`. | `Hosted_Doc(N)` = **TBD — projected, unmeasured** |
| Orchestrator | Use measured planning/prioritization calls `O_N`, including retry or fallback calls only when observed. Do not assume one call per run. | `Hosted_Orch(N)` = **TBD — projected, unmeasured** |

```text
HostedInference(S, N) = Σ_r∈S Hosted_r(N)

R_hosted(N) = the explicitly selected set of token-priced hosted roles
HostedInferenceSelected(N) = HostedInference(R_hosted(N), N)
```

If the Red Team uses local or capacity-priced hosted OSS, set its hosted-token line to “not selected” and
carry that workload in Family 2; do not call its price zero.

## Family 2 — local or hosted-OSS capacity

Throughput determines how much capacity and elapsed time are required. It does not alter a provider's
token price.

```text
RequiredAcceleratorHours_r(N) =
    W_r,N [work-units] / Cap_r [work-units / accelerator-hour]

EffectiveParallelAccelerators_r(N) = K_r,N × u_r,N
ElapsedHours_r(N) = RequiredAcceleratorHours_r(N)
                    / EffectiveParallelAccelerators_r(N)

AllocatedComputeHours_r(N) = measured capacity-hours assigned to the tier
                             and MUST be >= RequiredAcceleratorHours_r(N)

LocalFixed_r(N) = (hardware_purchase_price - residual_value)
                  / measured_useful_service_hours
                  × AllocatedComputeHours_r,N
LocalVariable_r(N) = measured_kWh_r,N × current_power_rate
                   + measured_operator_hours_r,N × approved_labor_rate

HostedOSSFixed_r(N) = reserved_accelerator_hours_r,N × current_reserved_rate
HostedOSSVariable_r(N) = burst_accelerator_hours_r,N × current_burst_rate
                       + measured_operator_hours_r,N × approved_labor_rate

CapacityFixed(N) = Σ_r [selected LocalFixed_r(N) or HostedOSSFixed_r(N)]
CapacityVariable(N) = Σ_r [selected LocalVariable_r(N) or HostedOSSVariable_r(N)]
CapacityInference(N) = CapacityFixed(N) + CapacityVariable(N)

CapacityInference_RT(N) = selected full local or hosted-OSS Red Team capacity cost
```

Hardware price, service life, residual value, power draw, labor rate, sustained capacity, context mix,
accelerator count/utilization, and hosted GPU rates are all **TBD — projected, unmeasured**. Report both
the capacity cost and whether `ElapsedHours_r(N) ≤ Window_N`; a cheap configuration that misses the
campaign window is not viable.

For the current architecture, Family 2 primarily models the Red Team switch. Any future local/capacity
deployment of Judge, Documentation, or Orchestrator must be measured and listed as a separate role rather
than silently pooled.

## Family 3 — platform, storage, observability, and egress

Keep fixed commitments separate from usage-driven charges:

Assign every invoice SKU and labor hour to exactly one family. Family 3 worker/compute lines exclude
inference accelerators charged in Family 2, and its CI/development labor excludes inference operator
labor charged in Family 2. Shared charges require a documented allocation rule; they must never be
copied into both families.

```text
Allocation_N = projection_accounting_window_N / each_service_billing_period

PlatformFixed(N) = Σ_service [minimum_commitment_service × Allocation_N,service]
                 + fixed_CI_and_dev_allocated_to_the_same_window

PlatformVariable(N) = measured_compute_overage(Peak_N, Window_N)
                    + measured_postgres_compute_overage
                    + (DBRows_N / B_db_rows) × P_db_rows
                    + (DBIngestBytes_N / B_db_ingest) × P_db_ingest
                    + (DBRetainedByteMonths_N / B_db_byte_month) × P_db_retention
                    + (BackupByteMonths_N / B_backup_byte_month) × P_backup
                    + (ObsEvents_N / B_obs_events) × P_obs_events
                    + (ObsIngestBytes_N / B_obs_ingest) × P_obs_ingest
                    + (ObsRetainedByteMonths_N / B_obs_byte_month) × P_obs_retention
                    + (EgressBytes_N / B_egress) × P_egress
                    + measured_CI_and_dev_overage

Platform(N) = PlatformFixed(N) + PlatformVariable(N)
```

Each platform `B_*` is the provider's published billing unit for that meter; each `P_*` is the
dated reporting-currency price per corresponding unit. A service with no row/event fee marks that line
“not applicable” rather than forcing it to zero or blending it into byte storage.

The projection accounting window must be stated for every tier. If a service cannot be prorated, allocate
its full minimum billing period rather than inventing a fractional charge. Normalize all lines into one
declared reporting currency using a dated, sourced conversion where providers bill in different currencies.

Database rows, evidence/transcript bytes, retention and PITR windows, trace volume, target/provider egress,
CI minutes, service sizes, utilization, and current prices are **TBD — projected, unmeasured**. Synthetic
data does not make storage or observability free; it makes the data posture permissible.

## Tier projections

Each row is a different architecture, not the same bill multiplied by volume. All monetary cells are
**TBD — projected, unmeasured**.

```text
TierFixed(N) = PlatformFixed(N) + CapacityFixed(N)
TierVariable(N) = HostedInferenceSelected(N)
                + CapacityVariable(N)
                + PlatformVariable(N)
TierTotal(N) = TierFixed(N) + TierVariable(N)
```

| Complete test-runs | Required architectural change | Fixed costs | Variable costs and formula | Projected total |
|---:|---|---|---|---|
| 100 | Baseline secure run. Instrument per-role tokens/calls, oracle skips, attempt distribution, latency, storage bytes, and peak concurrency. Keep one bounded worker/app and Postgres/observability baseline only after measurement confirms capacity. | `PlatformFixed(100) + CapacityFixed(100)` for the selected mode. **TBD — projected, unmeasured.** | Hosted inference for selected roles, `CapacityVariable(100)`, and `PlatformVariable(100)`. Preserve separate role lines. **TBD — projected, unmeasured.** | `TierTotal(100)` = **TBD — projected, unmeasured** |
| 1,000 | Add shared-context prompt caching where traces prove reuse and provider semantics permit it; route eligible asynchronous work through Batch. Measure hit/acceptance rates and latency impact. | Baseline commitments plus any minimum batch/worker capacity. **TBD — projected, unmeasured.** | Apply actual cached/uncached/batch token buckets, measured Judge skips and sampled dual-judging, storage/trace growth, and egress. **TBD — projected, unmeasured.** | `TierTotal(1K)` = **TBD — projected, unmeasured** |
| 10,000 | Move Red Team generation fully off frontier to measured hosted-OSS or local capacity; add durable queue backpressure and time-range partition the exploit database. Size capacity to the completion window. | Reserved/local accelerator capacity, worker floor, partitioned Postgres, platform/observability base. **TBD — projected, unmeasured.** | Capacity hours/power/operator time; hosted Judge/Documentation/Orchestrator tokens; queue/storage/observability/egress use. **TBD — projected, unmeasured.** | `TierTotal(10K)` = **TBD — projected, unmeasured** |
| 100,000 | Use stratified regression: every critical and recently reopened case on target change, sampled lower-risk cases, and a scheduled full suite. Add BRIN on timestamp, partial B-tree indexes on hot partitions, a dedicated worker, and bounded verdict caching keyed by target version plus case-content hash. | Dedicated worker/reserved capacity, partitioned/indexed Postgres, platform and observability commitments. **TBD — projected, unmeasured.** | Measured stratified workload rather than a 100K full-suite assumption; invalidated-cache misses, capacity hours, eligible hosted inference, retained evidence/traces, and egress. **TBD — projected, unmeasured.** | `TierTotal(100K)` = **TBD — projected, unmeasured** |

For each tier, report two totals when both deployment choices remain viable:

```text
R_all = {RT, Judge, Doc, Orch}
R_without_RT = {Judge, Doc, Orch}

TokenHostedScenario(N) = HostedInference(R_all, N) + Platform(N)

CapacityRedTeamScenario(N) = CapacityInference_RT(N)
                           + HostedInference(R_without_RT, N)
                           + Platform(N)
```

Neither scenario is currently populated because its authoritative inputs are unavailable.

## Present MVP cost versus future scale

### Present MVP — measured to date

One workload has produced **measured, retained, per-call hosted-inference cost**. It is small, but it
is real spend with a content-addressed source, so it is reported as measurement rather than estimate.

| Measured item | Value | Retained source |
|---|---|---|
| Judge-calibration capture (`judge-calibration-20260724`) | **$0.75823375** | `evals/results/judge-calibration-20260724/capture-manifest.json` → `ledger.measured_usd` |
| Physical provider calls | 54 (54 succeeded, 0 failed) | same, `executions` |
| Unresolved exposure | $0.00 | same, `ledger.unresolved_exposure_usd` |
| Model actually served | `google/gemini-2.5-pro` (requested == returned) | `captured-results.json` → `provenance` |
| Mean cost per label | $0.014041 | 54 per-sample `measured_cost_usd` values, summed independently |

The per-sample values sum to the manifest's own ledger figure exactly, so the total is reproducible
from the artifact rather than asserted by prose.

**The token profile matters more than the total.** That capture consumed 54,707 input, 9,675 output,
and **59,310 reasoning** tokens — reasoning exceeded visible output by **6.1×**. Any projection built
on observed output tokens therefore understates this Judge by roughly six-fold. This is a concrete
instance of why the forbidden shortcut above (`list price × assumed tokens × N`) fails here: the
dominant term is invisible to anyone reading the transcripts.

Still genuinely unmeasured, and therefore **TBD — not zero**:

- **Provider invoice.** No dated billing export is committed; the figure above is the provider's
  per-call reported cost, not a reconciled invoice.
- **Langfuse usage.** The calibration capture is offline and, by its own manifest, *does not export to
  Langfuse* — so no Langfuse record of it exists. This line is pending by design, not by oversight.
- **Railway compute, storage, and egress**, across both environments.
- **CI/development infrastructure**, hardware/power allocation, and labor.
- **The final authorized campaign**, which has not run. Its reservation ceiling is **not** its cost —
  see the caps envelope in the capacity write-up; a `$50` hard cap is a refusal threshold, not spend.

The five committed live attempts in `evals/results/platform-live-run-20260724/` add **no** hosted
inference to this total: that run used deterministic seed-replay for the Red Team and the
deterministic oracle-precedence Judge, so no model was billed to us. The target's own inference cost
is borne by the target owner and is out of scope.

### Future projections

The four tiers become numeric only after a representative authorized synthetic-data campaign captures
the inputs above. Recompute from measurements at each tier; do not extrapolate a single average across
architecture changes. Preserve the deterministic/oracle skip ratio and sampled dual-judge policy in the
measurement export so cost optimization cannot silently weaken Judge safety.

## Inputs required to replace TBDs

1. Dated billing/rate snapshots and trace exports with per-role input, cached-input, output, batch,
   request, retry, and model/provider fields.
2. Complete-run distributions: attempts, mutation depth, deterministic confirmations, eligible Judge
   calls, sampled secondary judgments, disputed cases, findings, and agent calls.
3. Local/dedicated benchmark: exact model and hardware, sustained capacity by context/concurrency,
   measured power, duty cycle, useful service life, operator time, and completion SLO.
4. Platform invoices and usage: app/worker compute, Postgres compute/storage/PITR, observability
   ingest/retention, CI/dev, and egress.
5. Retention policy and measured bytes per attempt, Verdict, trace, and result artifact.

Until those inputs exist, this document is a transparent projection model, not a cost quote.
