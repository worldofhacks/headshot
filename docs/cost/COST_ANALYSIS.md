# AgentForge cost analysis

**Reconciled:** 2026-07-26

**Evidence run:** staging campaign `50da57b037d44b3c93a10e4c2edf61a8` on release `456d6e5`

**Platform state:** [`../CURRENT_STATE.md`](../CURRENT_STATE.md)

This analysis replaces the pre-hosted-run projection. AgentForge now has measured per-provider-call
cost, token, and latency evidence for 12 attempted cases. It still does not have a complete 34- or
100-case campaign, a Railway/Langfuse invoice allocation, or enough repeated runs to characterize tail
cost. Figures below separate measured facts, configured accounting, and linear demand baselines.

## Unit definition and evidence boundary

A **test run** in the required 100/1,000/10,000/100,000 scale table means one complete 100-case suite:
the three authorized 34/33/33 campaign shards together. It does not mean one case or one model call.

The evidence run:

- attempted 12 cases before one schema-invalid Judge response failed the campaign;
- made 36 physical provider calls: 12 Orchestrator, 12 Red Team, and 12 Judge;
- made 16 physical target calls because multi-turn cases create more than one target call;
- completed 11 verdicts, all `INDETERMINATE`;
- made no Documentation call because no exploit was confirmed;
- recorded `$0.60731395` of measured provider cost; and
- recorded `$0.16` of target accounting at the configured `$0.01` per physical target call.

The provider figure is measured runtime billing metadata. The target figure is a configured internal
accounting value, not a target-provider invoice. The combined `$0.76731395` is therefore an operational
accounting total, not a cash-spend claim.

## Measured role workload

| Role | Calls | Input tokens | Output tokens | Reasoning tokens | Measured provider cost | Mean latency | Maximum observed |
|---|---:|---:|---:|---:|---:|---:|---:|
| Orchestrator | 12 | 16,103 | 4,873 | 1,622 | `$0.24289000` | 7.7 s | 10.1 s |
| Red Team | 12 | 3,457 | 47,071 | 12 | `$0.14276145` | 37.3 s | 65.9 s |
| Judge | 12 | 94,970 | 1,653 | 8,642 | `$0.22166250` | 8.9 s | 10.6 s |
| Documentation | 0 | 0 | 0 | 0 | `$0` | n/a | n/a |
| **Provider total** | **36** | **114,530** | **53,597** | **10,276** | **`$0.60731395`** | — | — |

The Judge row includes the failed HTTP-`200` structured-output call. Failed or retried physical calls
are billable work and must not disappear from cost reporting.

Observed end-to-end throughput was about 72 seconds per case at concurrency one. A 34-case shard is
therefore roughly 41 minutes and the serial 100-case suite roughly two hours before retry, recovery, or
Documentation work. This is a capacity constraint, not a token-price divisor.

## Full-suite demand baseline

The incomplete run averaged `$0.0506094958` of provider cost per attempted case. A straight-line
100-case provider baseline is `$5.06094958`. The authored 100-case workload contains 121 target turns,
so configured target accounting adds `$1.21`. The current all-in operational baseline is therefore
`$6.27094958` per complete 100-case suite.

For the 34-case shard, the same provider average is `$1.72072286`; its authorized 41 target turns add
`$0.41`, for a `$2.13072286` operational baseline.

These are demand baselines, not forecasts:

- only 12 cases were observed;
- one call failed and no retry occurred;
- Documentation cost is absent because no finding was confirmed;
- the case mix may have different context and multi-turn distributions;
- cached/batch pricing was not observed;
- future structured-output retries add physical calls when exercised; and
- Railway, PostgreSQL, Langfuse, CI, storage, egress, and labor are excluded.

| Complete 100-case test runs | Provider inference baseline | Target accounting baseline | Combined variable baseline |
|---:|---:|---:|---:|
| 100 | `$506.09` | `$121.00` | `$627.09` |
| 1,000 | `$5,060.95` | `$1,210.00` | `$6,270.95` |
| 10,000 | `$50,609.50` | `$12,100.00` | `$62,709.50` |
| 100,000 | `$506,094.96` | `$121,000.00` | `$627,094.96` |

Do not present this table as a quote. Recompute it from completed-suite distributions and dated invoices
before a purchasing or pricing decision.

## Fixed and variable cost model

The complete cost of a tier is:

```text
Total(N) =
    measured provider inference(N)
  + measured target/API charges(N)
  + allocated Railway commitments(N)
  + Railway compute overage(N)
  + PostgreSQL compute + storage + backup(N)
  + Langfuse ingest + retention(N)
  + object/artifact storage and egress(N)
  + allocated CI, development, operations, and incident-response labor(N)
```

Classify every invoice SKU once:

- **Fixed:** minimum Railway/service commitments, reserved capacity, committed observability/storage,
  and amortized hardware or engineering commitments for the accounting window.
- **Variable:** physical provider and target calls, token usage, retries, dynamic compute, database
  writes/retention, Langfuse observations, egress, and tier-specific operator time.

Do not add token-priced and capacity-priced charges for the same inference. If qwen or another role
moves to dedicated accelerator capacity, replace that role's provider line with measured accelerator
hours, utilization, power, and operations—not both.

Required measured inputs for a priced forecast:

| Input | Required measurement |
|---|---|
| Suite distribution | case/turn/call count, duration, retry count, and p50/p95/p99 per completed suite |
| Role usage | physical calls, input/output/reasoning/cache tokens, returned model/upstream, and cost |
| Findings | confirmed findings and Documentation calls/revisions |
| Target | physical calls and any actual target/API invoice rate |
| Database | rows, ingest bytes, retained byte-months, backup byte-months, and compute |
| Langfuse | observations, ingest bytes, retention, and plan/overage charges |
| Runtime | Railway service-hours, memory/CPU, replicas, egress, and minimum commitments |
| Delivery | CI minutes, artifact storage, engineering, security, and operations labor |

## Architecture required at each scale

### 100 complete suites

- land structured-output retry, case-local failure containment, and exact-once resume;
- run shards through the existing durable PostgreSQL queue with explicit concurrency and rate limits;
- reconcile every completed and failed campaign to Langfuse;
- capture at least p50/p95/p99 suite cost and duration.

At current serial throughput this tier is about 200 runner-hours before overhead, so concurrency and
provider/target rate authority—not only cost—must be planned.

### 1,000 complete suites

- partition work by campaign/shard and bound per-provider concurrency;
- use deterministic/oracle decisions before an LLM Judge where valid;
- exploit provider prompt caching or batch modes only when traces prove eligibility and savings;
- automate resumable backfill and observability reconciliation;
- establish database retention and archive policies.

### 10,000 complete suites

- capacity-test the queue, database indexes, outbox/projector, Langfuse ingestion, and target rate
  envelope;
- separate interactive control-plane capacity from worker capacity;
- partition or archive high-volume provider/target events;
- purchase reserved capacity only from measured utilization and tail demand.

### 100,000 complete suites

- treat model routing as a capacity/procurement decision, including dedicated hosted-OSS or local
  inference where benchmarked total cost and quality justify it;
- use multi-region or failure-domain-aware workers only if target authorization and evidence lineage
  remain exact;
- move bulky immutable evidence out of transactional PostgreSQL while retaining hashes and indexes;
- continuously audit sampling, calibration, retry amplification, retention, and unit economics.

No scale tier may weaken the Policy Gateway, two-person approval, synthetic-data requirement,
independent Judge, immutable evidence lineage, or “Judge never approves a confirmed exploit” invariant.

## Cost acceptance criteria

A future report may call a suite cost “measured” only when:

1. the suite terminalized with all three shards accounted for;
2. every logical role and every physical provider/target attempt has durable lineage;
3. token and provider-cost totals reconcile with the authoritative database;
4. failed calls and retries are included;
5. Langfuse delivery is verified or explicitly reported incomplete;
6. target accounting is labeled as configured or invoice-backed; and
7. fixed platform charges are separately allocated with the billing window and source.
