# Headshot cost analysis

## Status and accounting boundary

This is an evidence-bounded interim analysis for the 2026-07-24 release candidate. It contains
actual attributable spend that can be reconciled today and numeric scale sensitivities for 100,
1,000, 10,000, and 100,000 test runs. It is not a final production quote: the frozen 100-case
campaign, its Langfuse query-back, and the account-owner billing values listed below do not yet
exist in this branch.

For this analysis, one **test run** is one completed logical adversarial evaluation: one
authorization-bound case dispatched once to the target and adjudicated once. A campaign may contain
many test runs. This definition aligns the four requested tiers with the required 100-case evidence;
it does not count a retry, model call, trace, or entire multi-case campaign as another test run.

The method follows [DECISIONS.md D17](../planning/DECISIONS.md): measured provider usage,
capacity-priced inference, and platform operations remain separate. A cache discount, batch
discount, local-compute price, zero-dollar provider call, or per-run infrastructure cost appears
only when evidence supports it. Budgets and token ceilings are controls, not spend.

Primary evidence:

- [cost-input evidence](../evidence/cost/COST_INPUTS_2026-07-24.md);
- [pre-run Railway metrics](../evidence/performance/PRE_RUN_RAILWAY_METRICS_2026-07-24.md);
- [pre-run PostgreSQL/storage baseline](../evidence/performance/PRE_RUN_STORAGE_BASELINE_2026-07-24.md);
- [Langfuse predeployment baseline](../evidence/langfuse/PREDEPLOYMENT_BASELINE_2026-07-24.md); and
- the security owner's measured Judge-calibration bundle at commit
  `8ce852be79212d184d49c9f84c593c9495629332`, which remains
  owner-controlled until its final evidence commit is integrated.

## Actual development spend observed so far

| Item | USD | Evidence state | Included in attributable subtotal |
|---|---:|---|---|
| Headshot Railway July resource usage | 0.8168202853840123 | Measured by Railway CLI for the Headshot project | Yes |
| Reconciled 54-call Judge calibration | 0.75823375 | Provider-reported per-call cost sums exactly to the capture ledger | Yes |
| Open-source security-tool licenses | 0.00 | No paid scanner license found | Yes |
| Public-repository GitHub-hosted CI compute | 0.00 | GitHub documents these standard runner minutes as non-billable | Yes |
| Additional configured-key usage | 0.22988625 | Arithmetic difference between key usage `0.98812000` and the reconciled calibration; no durable workload lineage yet | No |
| Langfuse Cloud invoice | Unavailable | Public API exposes observations, not the account plan or invoice | No; owner input required |
| Development AI subscriptions/API use outside the configured key | Unavailable | Repository and runtime have no billing access | No; owner input required |
| Human labor and local hardware/power allocation | Unavailable | No approved hours, rates, power measurement, or allocation policy | No; owner input required |

The **confirmed attributable cash-usage subtotal is
`$1.5750540353840123`** (`$0.8168202853840123 + $0.75823375`). This is a measured
subtotal, not the complete development spend. The same configured OpenRouter key reported
`$0.00` at the pre-run baseline and `$0.98812000` at the later read-only check. If the owner
confirms that the key was dedicated to Headshot for that interval, the provider line becomes
`$0.98812000` and the known subtotal becomes **`$1.8049402853840123`**. Until that
confirmation, the `$0.22988625` difference remains unreconciled rather than being silently assigned
to Headshot or treated as zero.

The deployed target project's `$21.7638898181247` Railway usage is excluded. It is a separately
deployed system under test, not Headshot platform spend.

## Measured Judge calibration proxy

The only complete provider-cost distribution currently available is the security owner's
54-sample Judge calibration:

- 54 started, 54 succeeded, 54 physical attempts, 0 retries, and no unresolved exposure;
- 54,707 input tokens, 9,675 visible output tokens, and 59,310 reasoning tokens;
- provider-reported spend `$0.75823375`; and
- requested/returned model `google/gemini-2.5-pro`.

| Measurement per physical call | Minimum | p10 | Median | Mean | p90 | p95 | Maximum |
|---|---:|---:|---:|---:|---:|---:|---:|
| Input tokens | 868 | 900 | 1,004 | 1,013.0926 | 1,134 | 1,201 | 1,233 |
| Visible output tokens | 121 | 133 | 186 | 179.1667 | 216 | 235 | 256 |
| Reasoning tokens | 467 | 605 | 1,071 | 1,098.3333 | 1,597 | 1,636 | 2,195 |
| Cost (USD) | 0.007135 | 0.008995 | 0.0136175 | 0.0140413657407 | 0.0193475 | 0.01980125 | 0.02519 |

For the same calibration workload, the conventional 95% confidence interval around the mean is
`$0.0130996629` to `$0.0149830686` per call. That interval covers sampling variation inside this
54-item calibration only; it does not cover production corpus mix, prompt-size drift, price changes,
or a different upstream route.

This proxy has **low confidence for production projection**. It is calibration traffic, not the
missing frozen 100-case campaign. Its recorded Judge route identity and Red-Team identity also
differ from the release candidate's exact `google-vertex/global` and `atlas-cloud/fp8` routes.
The calibration is valid evidence of development spend, but it cannot prove current-route cost,
runtime enablement, or live performance.

## Actual runtime call model

Let:

- `N` be completed logical test runs;
- `F`, where `0 ≤ F ≤ N`, be deterministic confirmed findings that trigger Documentation;
- `C`, where `1 ≤ C ≤ N`, be the number of campaign traces containing those runs; and
- `P` be physical provider attempts, including charged failures and retries.

The registered hosted generation policy requires:

```text
logical Orchestrator calls = N
logical Red Team calls      = N
logical Judge calls         = N, except a malformed/integrity ERROR can stop before provider I/O
logical Documentation calls = F
logical model calls L       = 3N + F
physical model calls P      = L through 2L because the closed retry cap is one
target calls                = N, with zero target retries in the exact workload
```

Deterministic-oracle precedence determines verdict authority; it does **not** currently eliminate a
valid hosted Judge call. The runtime evaluates deterministic evidence first, calls the model for
every non-ERROR case, and then reconciles with the deterministic result remaining decisive. A cost
model that subtracts all oracle-decided cases from Judge calls would undercount the implementation.

Documentation is conditional on a deterministic confirmed finding. A model-only
`EXPLOIT_LIKELY`, advisory assessment, or failed calibration cannot create that cost path.

## Langfuse billable-unit model

For each logical hosted role execution, the current projection creates one AGENT observation and
one logical runtime GENERATION. Each physical provider attempt creates another GENERATION, including
retries and charged failures. One unique trace is billed per campaign trace; the current code does
not create Langfuse scores.

```text
Langfuse units U = 2L + P + C
                 = 2(3N + F) + P + C

minimum current shape = 9N + 1
maximum authorized shape = 17N
```

The minimum uses no findings, no retries, and one campaign. The maximum uses a Documentation call
and one retry for every run, with one trace per run. If the final query-back finds scores or a
different trace grouping, its exact observed count replaces this envelope.

The July 2026 published plan snapshot used for sensitivity is Hobby at `$0` with 50,000 included
units, and Core at `$29/month` with 100,000 included units plus `$8/100,000` additional units.
The actual account plan and invoice remain unavailable. A workload above the Hobby allowance is
**blocked on Hobby**, not a zero-dollar overage. The Core figures below linearly prorate the
published additional-unit rate; invoice rounding, credits, tax, and contractual terms require the
owner's billing record.

## Provider exact-route price sensitivity

The [redacted public-catalog preflight](../evidence/provider/OPENROUTER_CATALOG_PREFLIGHT_2026-07-24.md)
passed for all four exact endpoint tags on 2026-07-24. The table below applies its observed
endpoint rates to the policy's per-call input, visible-output, and reasoning bounds. These are
dated **rate sensitivities**, not provider-reported usage, an invoice, deployment evidence, or
campaign authorization.

| Role | Input/output/reasoning token bound | Maximum first-attempt cost at observed exact-route rates |
|---|---:|---:|
| Orchestrator | 65,536 / 2,048 / 8,192 | $0.64204800 |
| Red Team | 4,096 / 2,048 / 1,024 | $0.01300480 |
| Judge | 100,000 / 2,048 / 8,192 | $0.22740000 |
| Documentation | 16,384 / 4,096 / 4,096 | $0.18022400 |

At those dated public rates, three unconditional roles total `$0.88245280` per run. Documentation
on every run raises that to `$1.06267680`; retrying every call would raise the respective
sensitivity figures to `$1.76490560` and `$2.12535360`. The preflight separately verifies the
looser configured price ceilings and role caps used for authorization. Those reservations are
safety controls and must not be presented as expected spend. Real requests are billed from
provider-reported physical-attempt usage and reconciled after the run.

## Interim numeric scale sensitivity

This table is deliberately multi-dimensional. The Judge column is an empirical proxy; the provider
column is a token-ceiling control envelope; and the Langfuse column is a plan sensitivity. Adding
them would mix an observed mean with mutually exclusive ceilings, so none is labeled a production
total.

| Completed test runs | Logical model calls | Physical provider calls | Judge-only proxy, p10 / mean / p90 (USD) | Provider token-ceiling scenario, no-doc/no-retry → all-doc/all-retry (USD) | Langfuse units | Published-plan sensitivity |
|---:|---:|---:|---:|---:|---:|---|
| 100 | 300–400 | 300–800 | 0.8995 / 1.4041 / 1.9348 | 88.25–212.54 | 901–1,700 | Hobby `$0` if the actual plan is confirmed |
| 1,000 | 3,000–4,000 | 3,000–8,000 | 8.9950 / 14.0414 / 19.3475 | 882.45–2,125.35 | 9,001–17,000 | Hobby `$0` if the actual plan is confirmed |
| 10,000 | 30,000–40,000 | 30,000–80,000 | 89.9500 / 140.4137 / 193.4750 | 8,824.53–21,253.54 | 90,001–170,000 | Hobby cannot cover it; Core scenario `$29.00–$34.60` |
| 100,000 | 300,000–400,000 | 300,000–800,000 | 899.5000 / 1,404.1366 / 1,934.7500 | 88,245.28–212,535.36 | 900,001–1,700,000 | Hobby cannot cover it; Core scenario `$93.00–$157.00` |

The Judge proxy multiplies the observed calibration p10/mean/p90 only to show sensitivity of that
single role. It is not the required nonlinear total. The provider envelope changes with findings
and retries and retains all four roles. The eventual total must add measured platform, storage,
egress, observability, security-tool execution, and operations without double counting.

## Platform, storage, egress, and operational assumptions

| Cost family | Measured input | Current treatment |
|---|---|---|
| Railway platform | `$0.8168202853840123` Headshot July resource usage | Actual development spend. It is neither a monthly minimum nor a per-tier fixed fee; the CLI project breakdown does not expose attributable per-meter amounts. |
| CPU and memory | Seven-day summary plus point-in-time idle samples | Baseline only. They are not utilization distributions, load capacity, or replica-sizing evidence. |
| PostgreSQL | 11,425,471-byte pre-run database on migration `0013` | Delta baseline only. The final 100-case run must provide database and named-relation growth before bytes/run or retention costs can be projected. |
| Backup/PITR | No Headshot-specific bill or byte-month allocation | Unavailable; must remain separate from database storage. Production is release-blocked without a confirmed database rollback binding. |
| Observability | Zero predeployment Headshot staging observations | No run cost can be inferred from zero activity. Use exact query-back units and the owner-confirmed plan. |
| Egress | Workspace meter exists, but Headshot project allocation is absent | Unavailable; do not copy the workspace total or infer it from idle traffic. |
| Target traffic | Exact workload requires one target call per run and no target retry | Target-side Railway spend is excluded. Any contracted per-request target fee is unavailable; the code's configurable per-request amount is a budget estimate, not an invoice. |
| Security tools | OSS licenses and eligible public GitHub CI are `$0.00` direct | Tool execution still consumes runner/platform compute and operator time. Those inputs are unavailable, not zero. |
| Labor and operations | No hours/rates/on-call allocation | Unavailable. Do not apply an arbitrary percentage uplift. |
| Local/capacity inference | No measured accelerator throughput, power, duty cycle, or hosted-GPU invoice | Not selected in the numeric table. “Local” never means free; add it only after a same-workload benchmark. |

All projections use USD. The accounting window for a final tier must be explicit. A service that
cannot be prorated receives its whole minimum billing period; a one-time July usage subtotal must
not be copied into every tier as a fictional fixed charge.

## Architecture at each scale

| Completed test runs | Required architecture and accounting treatment |
|---:|---|
| 100 | Candidate source admits exactly 400 physical calls for the zero-provider-retry worst case; one retry everywhere would require 800 and is refused. Stage and authorize the exact frozen-corpus call/token/USD/time envelope. Use the final campaign to measure the existing Web/Runner/Scheduler/Postgres footprint, queue wait, storage growth, egress, and Langfuse units. |
| 1,000 | Process durable, bounded waves through PostgreSQL backpressure. Do not claim a completion window from the present concurrency of one; size concurrency only from measured role/target latency and upstream rate limits. Hobby can fit the observation envelope, but the actual plan still requires confirmation. |
| 10,000 | Upgrade observability capacity before the run, partition/time-bound evidence retention, and add worker capacity only from measured utilization. A hosted-OSS/local Red-Team switch is a candidate optimization, but has no numeric price until the same workload is benchmarked for accelerator-hours, power, and operator time. |
| 100,000 | Project and execute 100,000 complete logical runs for the required tier. Dedicated workers, queue partitions, storage lifecycle, indexed/time-partitioned PostgreSQL, and an approved completion window require measurement-based sizing. A stratified regression schedule may be reported separately as an operational optimization; it is not a substitute for the 100,000-run projection. |

No prompt-cache or provider-batch discount is applied because no trace proves a cache hit or
accepted batch request. Their sensitivity may be added only with measured hit/acceptance rates,
latency effects, and the exact dated rate. Concurrency changes elapsed time and platform capacity;
it does not divide token price.

## Final projection method after the frozen 100-case result

The final calculation must resample **whole case bundles**, preserving correlated Orchestrator,
Red-Team, Judge, conditional Documentation, retry, error, target, storage, and observability
behavior. For each tier:

1. Stratify the frozen 100 cases by category and outcome without changing their observed
   proportions.
2. Bootstrap complete case bundles to produce p05, median, and p95 provider, latency, storage,
   egress, and Langfuse totals.
3. Add the fixed service commitment for the declared accounting window once.
4. Size worker/database capacity from measured utilization and the required completion window.
5. Apply no cache, batch, local-capacity, or retry improvement unless a separate measured scenario
   supports it.
6. Reconcile provider physical-request rows, Langfuse observations, and PostgreSQL IDs before
   accepting the cost totals.

This method is nonlinear: findings trigger Documentation, failures and retries add physical calls,
Langfuse changes plan tier, retention creates byte-months, and worker/database capacity changes at
scale. It is not “tokens per average case × N.”

## Confidence and sensitivity

| Result | Confidence | Main sensitivity |
|---|---|---|
| `$1.5750540353840123` attributable subtotal | High for the two included usage sources; incomplete as total development spend | Account invoice adjustments and the excluded owner inputs |
| Judge calibration distribution | High for the captured 54 calls; low as a current production proxy | Corpus mix, prompt size, exact route, price drift |
| Runtime call-count envelope | Medium-high | Finding fraction, integrity-error skips, retry rate, campaign grouping |
| Langfuse unit envelope | Medium | Exact query-back shape, retries, traces, future scores, actual account plan |
| Provider token-ceiling envelope | Low as a forecast; useful only as a safety bound | Dated public endpoint snapshot, deliberately loose token ceilings, finding/retry extremes |
| Railway/storage/egress/operations tier totals | Unavailable | Missing final-run deltas, accounting window, capacity SLO, invoices, labor |

Sensitivity variables retained in the final model are finding fraction `F/N`, role-specific retry
rate, physical-call failure cost, campaign count `C`, provider price/route drift, cache/batch state,
completion window, worker concurrency/utilization, database and backup retention, Langfuse units,
egress class, and operator hours. Missing values remain unavailable; they are never coerced to zero.

## Exact external inputs still required

From the security owner’s final 100-case evidence:

- frozen corpus identity/hash, completed count, and whole-case ordering;
- per-role logical calls and physical attempts, including charged failures and retries;
- input/output/reasoning tokens, returned route/model, and provider-reported cost per attempt;
- confirmed-finding count and Documentation call count;
- target requests, queue/orchestration/provider/database/end-to-end latency, and concurrency;
- database/relation/artifact growth, Langfuse trace/observation/score totals, and egress; and
- the owner-authored bottleneck and architecture recommendation, consumed without re-derivation.

From the account owner:

- Langfuse Cloud plan plus the actual billed amount, credits, overage, tax, and billing window;
- confirmation whether the configured OpenRouter key was Headshot-dedicated for the measured
  interval and attribution of the `$0.22988625` difference;
- actual development AI-tool/API/subscription spend outside that key;
- the intended labor/hardware/power accounting policy and exact amounts, including an explicit
  zero if those families are intentionally excluded; and
- the final Railway invoice if credits, subscription allocation, or tax differ from resource usage.

From final staging acceptance:

- a redacted exact-endpoint price/cap snapshot for the deployed configuration;
- exact provider/PostgreSQL/Langfuse reconciliation;
- post-run Railway utilization and database/storage deltas; and
- the declared completion and retention windows for each projection tier.

Until those inputs are supplied, the numeric table above is the most specific defensible
sensitivity analysis. It must not be relabeled as a measured 100-case result, an invoice, or a
production total.
