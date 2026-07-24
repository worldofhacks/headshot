# Performance evidence index

No final 100-case performance or live-load result is available in this candidate. The artifacts
below are pre-run baselines only and must not be presented as throughput, latency percentiles,
capacity, or proof of the newer release.

| Artifact | Scope | Evidence state |
|---|---|---|
| [`PRE_RUN_RAILWAY_METRICS_2026-07-24.md`](PRE_RUN_RAILWAY_METRICS_2026-07-24.md) | Seven-day Railway summary and point-in-time idle service samples before deployment | Measured pre-run baseline |
| [`PRE_RUN_STORAGE_BASELINE_2026-07-24.md`](PRE_RUN_STORAGE_BASELINE_2026-07-24.md) | Staging PostgreSQL row/byte snapshot on deployed migration `0013` | Measured pre-run baseline |

Final evidence must integrate the security owner's deterministic 100-case result and any separately
authorized live-load result. It must report orchestration, provider/tool, queue, database, storage,
and end-to-end metrics; identify authorization and whether traffic was simulated or live; and publish
the owner's bottleneck and architecture recommendation without re-deriving or upgrading it.

The current hosted ceiling is also incompatible with the required workload: conservative preflight
reserves 400 logical provider calls for 100 cases before retries, while the closed global maximum is
56 physical calls. A reviewed exact-workload limit change and new authorization are required before a
live performance run; bypassing preflight would invalidate the evidence.
