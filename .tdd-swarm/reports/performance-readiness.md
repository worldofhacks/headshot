# Performance readiness: legitimate deterministic 100-case baseline

Status: **BLOCKED: implementation and measurement pending.**  This is a read-only
readiness assessment, not a measured benchmark.  It must not be cited as a CPU,
memory, latency, throughput, cost, database-SLO, or live-load result.

Audit scope: `Week_3_AgentForge.pdf` page 12 (visually reviewed), `T-F06a`,
`T-F07a`, `T-F07b`, `T-F08`, current runner/regression/telemetry/storage code,
migrations, CI, and existing benchmark/load artifacts.  Audited checkout: branch
`swarm/final-submission-gap-closure`, commit
`6fcfa0c80c80a81bafc788b1878a8477b7d52fd6` at review time.

## Requirement boundary

The PRD requires:

1. documented SQL indexes for common severity/category/system-version patterns,
   a defined full-exploit-database regression time budget, and CI verification;
2. baseline platform CPU, memory, latency, and throughput under a representative
   **100 attack case plus full regression suite** run; and
3. a separately authorized staging load test of **100 consecutive cases** against
   the live target, recording agent-orchestration latency, LLM-call latency, and
   exploit-storage throughput, followed by evidence-based bottleneck/remediation.

It does **not** provide numeric SLO limits.  `IMPLEMENTATION_PLAN.md` likewise
requires a two-number full-suite/critical-subset promotion gate, but gives no
numbers.  Therefore no numeric pass/fail target may be invented in this report.
The only valid numeric thresholds are those later recorded in a human-approved,
content-hashed `.tdd-swarm/baselines.md`, with the exact environment class and
metric definitions.  Until then, the baseline run can validate completeness and
reproducibility but cannot pass an SLO/promotion gate.

## What the repository can and cannot measure today

| Measure | Current evidence source | Readiness / limitation |
|---|---|---|
| CPU time / peak RSS | None | Not instrumented.  No benchmark script or process sampler exists. |
| Platform per-case latency | `agent_executions.duration_ms` in migration `0011` | Potentially available for persisted agent executions, measured by PostgreSQL `clock_timestamp`; no local benchmark collector, no 100-case fixture workload, and no percentile aggregation. |
| Target HTTP / provider-facing latency | `outbound_http_requests.duration_ms`, set with `time.perf_counter` in `telemetry/outbound.py` | Available only for physical target HTTP requests. It is target transport latency, not a model-provider latency metric. A network-disabled local run must report provider latency as `unavailable`, not zero. |
| p50 / p95 | Raw duration fields above | No percentile implementation, convention, raw sample export, or reviewer recomputation artifact. |
| Throughput | Timestamps plus persisted records could be derived | No denominator/window definition or collector.  Do not infer it from a future report's row count alone. |
| Storage throughput / growth | Postgres tables and manifest files exist | No before/after database-size query, manifest-byte counter, per-table delta, or aggregation. |
| Error rate / retries | `outbound_http_requests.status`/`error_code`; runner/gateway errors; queue state | Some raw signals exist, but no benchmark aggregation and a cassette run has no real HTTP/provider retry signal. |
| Per-agent timing / cost | `agent_executions` stores duration, input/output token fields, `measured_cost`; completion API persists them | Timing is usable once benchmarked. Cost is not a populated local measurement. Target request `measured_cost` derives from configured `per_request_cost_usd` (default `$0.01`) and is a cap/accounting estimate, not an immutable provider invoice. |
| Provider latency/tokens/cost | No provider-call ledger identified | The code has target HTTP telemetry and optional Langfuse projection only. It does not establish measured OpenRouter/LLM provider latency for the local fixture run. T-F08 must retain unavailable values until immutable provider inputs exist. |
| Regression full / critical-subset duration | T-F06a AC-5 requires it | Missing. `regression/replay.py` creates plans and evaluates supplied observations; it does not create a fresh campaign, call an adapter, or emit either duration. |
| Regression/query SLO | Index migrations exist | Missing: no defined budgets, benchmark, CI gate, or query-plan/latency measurement. |
| Reproducibility / SHA lineage | corpus content hashes, contract hashes, manifests, Git SHA, Alembic head are available building blocks | Missing benchmark manifest, command/environment capture, raw metric artifact hashes, and comparator. |

Existing indexes include the original `finding` severity/category/target-version
indexes (`0001`), target-version and replay-plan/result indexes (`0010`),
campaign/attempt indexes (`0005`/`0006`), telemetry run/attempt and org/time
indexes (`0007`), and agent-execution timing indexes (`0011`).  This establishes
that indexes exist; it is not evidence that their target queries meet an SLO.

There is no `scripts/benchmark_platform.py`, `src/agentforge/performance/`,
`tests/performance/`, `docs/performance/`, `.tdd-swarm/baselines.md`, or load
script in this checkout.  GitHub and GitLab CI run lint, corpus validation,
pytest, contract, packaging, console, container, and security checks, but neither
has a performance job.  Existing `scripts/check.sh` likewise has no benchmark.

## Exact local workload to implement in T-F07a

This is a **network-disabled, synthetic, local platform benchmark**, not a live
target campaign and not a claim about target capacity.

### Inputs and deterministic composition

1. T-F07a must commit one versioned workload manifest, for example
   `tests/performance/fixtures/local-100-v1.json`, and its SHA-256.  The manifest
   must name `workload_version`, fixed seed string
   `agentforge-local-performance-100-v1`, `FULL_SCAN_CORPUS_ID`, its corpus hash,
   each source case ID/content hash, cassette hash, and exactly 100 ordered logical
   execution slots.
2. Build slots from `load_full_scan_corpus()` only after validating the corpus and
   its pinned reviewed-tool bundles.  The current implementation has exactly 14
   source cases; it is not itself a 100-case corpus.
3. Define the exact slot order without RNG: sort sources by `(case_id,
   content_hash)` and set slot `i` (one-based, `1..100`) to source
   `sources[(i - 1) % 14]`.  Thus the first two sorted sources occur eight times;
   the other twelve occur seven times.  Each slot gets a distinct logical instance
   ID `PB-100-<three-digit ordinal>` and canonical instance hash over
   `{workload_version, seed, ordinal, source_case_id, source_case_sha256}`.  The
   committed manifest, not a reimplementation of this prose, is authoritative.
4. Bind every slot to a synthetic cassette response and deterministic safe/unsafe
   oracle outcome.  Use `SyntheticCassetteAdapter`; patch/guard socket and HTTP
   transports so any network attempt fails the run before a request.  Do not use
   target credentials, provider credentials, Langfuse, or a live adapter.
5. Use a fresh disposable migrated PostgreSQL database and an empty run-artifact
   directory per warm-up/measurement repetition.  This prevents row growth from a
   prior repetition changing storage, query, or cache behavior.  The database URL
   is secret and must not be emitted; report only the DB engine/version and a
   non-secret environment class.

The repeat instances are deliberate workload slots, not a claim that the source
corpus contains 100 distinct adversarial discoveries.  The report must disclose
`source_case_count: 14`, `logical_execution_count: 100`, and the allocation rule.

### Run sequence and commands

T-F07a should provide the following command shape (paths/options are a required
interface, not a command executed by this assessment):

```sh
PYTHONPATH=src python scripts/benchmark_platform.py \
  --workload tests/performance/fixtures/local-100-v1.json \
  --repetitions 3 --warmups 1 --network disabled \
  --database-url "$BENCHMARK_DATABASE_URL" \
  --output "docs/performance/local/$(git rev-parse HEAD)"
```

Before the first warm-up, validate corpus/cassette/contract/workload hashes and
record the resolved command and a redacted allowlisted environment.  Perform one
complete warm-up (100 slots plus replay critical subset plus replay full suite),
discard all of its metric samples and artifacts from comparisons, then perform
three complete measured repetitions.  A repetition is invalid and exits **2** if
it has anything other than exactly 100 completed slots, the committed order or any
instance/source/cassette hash differs, network access is observed, a required raw
sample is missing, or a warm-up leaks into the measured set.

Each measured repetition must run both T-F06a executor modes against the same
fresh fixture state:

- **critical subset:** every fixture regression case classified critical (and,
  when T-F06a implements it, recently reopened cases); and
- **full suite:** every fixture regression case selected by the executor.

The benchmark must record the executor's explicit `critical_subset_duration_ms`
and `full_suite_duration_ms`; it must not time a planner/evaluator call and label
it a replay.  If either mode is unavailable, the benchmark exits 2 rather than
substituting a partial result.

### Measurement method

Use `time.perf_counter_ns()` for benchmark wall time and per-logical-slot elapsed
time; retain integer nanoseconds in raw JSON and derive displayed milliseconds.
Use process `resource.getrusage(RUSAGE_SELF)` CPU user/system seconds and peak RSS
with an OS-specific unit declaration.  If children are used, collect and label
`RUSAGE_CHILDREN` separately; do not merge it silently.  Sample RSS at start/end
and after every slot using a documented portable collector (for example `psutil`
if pinned); report the maximum observed sample as `peak_rss_bytes` and state the
sampling interval.  CPU/RSS must be marked unavailable if their collector cannot
run, not fabricated from wall time.

For every measured repetition retain:

- per-slot total platform elapsed time, per-agent execution elapsed times,
  success/error/retry counts, and total-wall-clock duration;
- `p50` and `p95` of the 100 total per-slot samples using the documented nearest-rank
  rule: sorted ascending samples `x`, percentile `p` is
  `x[ceil(p * n) - 1]` for `n=100`; retain the complete sorted vector so a reviewer
  can recompute it;
- logical throughput = `100 / total_wall_clock_seconds`; completed-slot throughput
  must never be calculated for an incomplete run;
- database bytes before/after and deltas using `pg_database_size(current_database())`,
  plus named relation/index sizes for benchmark-written tables using
  `pg_total_relation_size`; manifest/result bytes before/after from recursive file
  byte totals; storage throughput = each delta divided by measured wall-clock
  seconds, with DB and file figures never added together;
- query timings for the exact regression and common indexed query set, with
  `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` retained only for synthetic fixture
  parameters.  The report must name every query and the index/plan actually used;
- target/provider latency as `unavailable: network_disabled`; target/provider
  calls, tokens, and externally measured cost as zero calls / unavailable cost,
  not as zero latency or zero provider price.

Aggregate the three measured repetitions by reporting all three results and the
median of each scalar metric.  Percentiles are not pooled across repetitions:
retain each run's 100-sample p50/p95 and report the median of the three p50 values
and of the three p95 values.  Error rate is `failed_or_error_slots / 100`; retry
rate is `physical_retries / logical_slots`.  A valid deterministic fixture baseline
expects both rates to be zero, but this is an integrity expectation, **not** a PRD
latency/SLO threshold.

## Required artifact/report schema

Write only under `docs/performance/local/<git-sha>/`, atomically after all three
valid repetitions.  Suggested minimum artifact set:

```text
docs/performance/local/<sha>/
  manifest.json                 # immutable inputs, command, environment class
  workload.json                 # copied approved 100-slot manifest
  raw-run-01.json
  raw-run-02.json
  raw-run-03.json
  samples.csv                   # one row per run/slot/agent/query where applicable
  summary.json                  # definitions, per-run and aggregate metrics
  summary.csv                   # reviewer-friendly scalar view
  query-plans/*.json            # synthetic EXPLAIN ANALYZE outputs
  bottleneck.md                 # evidence-based or explicitly inconclusive
  SHA256SUMS
```

`manifest.json` must include: benchmark/workload/cassette versions and hashes;
Git commit and dirty-tree state; package-lock/`pyproject.toml`/Alembic-head hashes;
Python/package versions; OS/kernel/architecture; CPU model/count; total memory;
container image digest or `uncontainerized`; PostgreSQL version/config class;
locale/timezone; command argv; redacted allowlisted environment keys/values; start
and finish timestamps; raw/summary/schema hashes; and the `.tdd-swarm/baselines.md`
hash.  Never put DSNs, credentials, tokens, patient data, raw hostile prompts, or
unredacted target response data in it.

`summary.json` needs a schema version, explicit units, availability/reason for each
metric, exact definitions above, completeness result, the raw artifact hashes,
per-run samples/derived values, median aggregation, critical/full regression
durations, query results, error/retry values, storage deltas, and a structured
`threshold_evaluation` array.  Each threshold row must contain metric, comparator,
environment-class match, baseline approval hash, observed value, and status.  If
there is no approved baseline, status is `blocked_missing_human_approved_baseline`.
If environment classes differ, status is `not_comparable`; do not silently compare.

`SHA256SUMS` must cover every listed artifact and be verified before reviewer
recomputation.  The performance reviewer recomputes each percentile from raw
samples, recalculates throughput/error/retry/storage formulas, verifies every hash,
and confirms the 100-slot manifest/order.  A changed source/workload/cassette or
incomplete sample is a non-comparable run, not a new baseline.

## Pass/fail rules without invented grading numbers

The harness itself should enforce these fixed exits:

| Condition | Exit / outcome |
|---|---|
| invalid/missing warm-up, network attempt, fewer/more than 100 slots, mismatch, missing raw metric, missing executor duration | exit 2; exclude output |
| approved baseline absent, baseline hash mismatch, or environment class mismatch for a requested promotion comparison | promotion blocked; comparison status recorded, not a fabricated pass |
| same-class approved threshold exceeded | exit 1 in CI smoke; preserve raw evidence |
| complete local measurements, but no approved threshold | measurement artifact may exist; promotion remains blocked |
| live authorization missing/invalid/expired or any live cap/health/abort breach | T-F07b exit 4 / zero new calls for invalid authorization; stop new dispatch and preserve partial evidence for a post-start breach |

`.tdd-swarm/baselines.md` must be a human-approved, hash-pinned policy document
that defines the numeric limits for full-suite duration, critical-subset duration,
and any chosen CPU/RSS/latency/throughput/query limits.  It must state the
environment class, allowed comparison variance/comparator, effective date,
approver identity/reference, and supersession rules.  T-F07a must verify the
approval/hash mechanically.  This report supplies no values because the PRD and
repository have supplied none.

## T-F06a dependency and minimal T-F07a implementation

T-F06a is a hard dependency, not a documentation dependency.  Current
`RegressionReplayGate` accepts already-produced observations and evaluates them;
it cannot satisfy T-F07a AC-1/AC-5.  T-F06a minimally needs a fresh-replay executor
that, only after its authorization/calibration/version/integrity gates pass:

1. creates a new campaign/run identity and an exact target-call plan for every
   selected replay case; never reads/reuses a prior verdict as execution output;
2. executes the configured fixture adapter or authorized target adapter, records
   fresh evidence and independent verdicts, applies the expected-safe oracle +
   case-hash + target-version right-reason comparator, and records cross-category
   baseline-hash comparison evidence;
3. exposes a deterministic, network-disabled fixture mode with `critical_subset`
   and `full_suite` selectors; and
4. returns a typed result with selected/completed count, ordered case/source hashes,
   target/campaign/version/baseline hashes, zero-adapter-call blocked reason where
   applicable, and monotonic `critical_subset_duration_ns` /
   `full_suite_duration_ns` (or per-mode `duration_ns`).

Minimal T-F07a then consists of a benchmark module/CLI, fixture manifest/cassettes,
network-denial guard, process/resource and Postgres/file collectors, percentile and
hash verifier, approved-baseline comparator, tests for AC-1 through AC-4, and CI
smoke only after a same-class approval exists.  It must not add provider calls,
live target load, a guessed SLO, or cost projections.  It must add a `tests/performance`
test that proves mismatches/incomplete data exit 2, an absent approval blocks
promotion, and the reviewer recomputation path detects altered samples.

## Separate live-staging authorization manifest for T-F07b

Spending approval is only one cap input.  It is **not** authorization to test a
target or to create 100 live requests.  Before any live staging stress, the
owner-supplied, read-only `docs/evidence/authorizations/live-stress.json` must
validate and hash-bind all of the following exact values:

- schema/version, unique authorization ID, issued/expiry/lease timestamps and
  nonce; immutable manifest hash and referenced T-F07a baseline/metric-definition
  hashes;
- environment exactly `staging`; exact target ID, HTTPS host/base path, adapter
  kind/version, target deployment/release hash, allowed method/relative path, and
  credential reference identifier only (never its value);
- exactly 100 ordered case instance IDs plus source-case, case-content, corpus,
  workload, cassette/provisioning, and synthetic-fixture hashes; a declared
  synthetic-only attestation; no wildcard corpus, target, host, or case selector;
- maximum requests = 100, concurrency, target RPS, per-request and run timeout,
  retry/backoff policy, total USD cap/currency plus immutable rate/pricing input,
  and a no-new-dispatch rule on every cap breach;
- named monitor/telemetry sinks, health prerequisites, rate/queue/budget/error
  alert thresholds, abort owner and reachable stop procedure, polling cadence, and
  evidence output location; and
- launcher identity/session/reference, a **different** approver identity/session/
  reference, required permissions, decision timestamp, and exact scope hash.

The execution gate must verify: required file is present and schema-valid; the
manifest has not expired; computed scope/workload/release/cap hashes match the
requested run; target allowlist/adapter/credential bindings are exact; all fixtures
are synthetic; readiness and monitor are healthy; launcher and approver are
distinct; and authorization has not been consumed/reused.  Any failure is
`BLOCKED`, exits 4, and produces zero adapter/target calls.  After dispatch begins,
lease expiry, health loss, abort request, cap/rate/timeout breach, or telemetry
integrity failure must halt **new** dispatch and retain a partial immutable manifest
with actual count/cost/latency/error data.  No production target is in scope.

For a valid live run, capture the PRD's orchestration latency, actual provider/LLM
latency where an instrumented provider boundary exists (otherwise explicitly
unavailable), target HTTP latency, CPU/RSS, storage throughput/growth, errors,
retries, request count, and measured cost provenance.  The final bottleneck and
architecture change must follow observed evidence; it cannot be prewritten.

## Current blockers

1. **T-F06a not implemented:** no fresh replay executor and no critical/full
   duration interface.
2. **T-F07a not implemented:** no 100-slot workload, benchmark collector, raw
   report schema, human-approved baseline policy, comparator, performance tests,
   or CI job.
3. **No numeric SLO policy:** the PRD asks for one but supplies no values; a human
   must approve `.tdd-swarm/baselines.md` after reviewing a legitimate same-class
   baseline.
4. **No live authorization:** no verified exact-scope staging `live-stress.json`,
   distinct approval, target limit, monitoring/abort lease, or allowed target-load
   window.  No live target load was run for this assessment.
5. **Provider-cost/latency evidence incomplete:** current target telemetry cannot
   substitute for immutable provider latency/pricing/invoice inputs required by
   T-F08.

