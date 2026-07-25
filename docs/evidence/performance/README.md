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

Candidate source admits exactly 400 logical/physical provider calls for the zero-provider-retry
100-case envelope and refuses its 800-call retry-expanded shape. That limit is neither deployed nor
an authorization. The exact frozen-corpus token, USD, rate, timeout, and call ceilings still require
a staged configuration, catalog preflight, and new approval before a live performance run; bypassing
preflight would invalidate the evidence.
