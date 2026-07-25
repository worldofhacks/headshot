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

Candidate source admits exactly 400 physical provider attempts for the zero-provider-retry
100-case worst case and refuses its 800-attempt retry-expanded shape. It also refuses an encoded
request larger than its policy identity and insufficient cumulative per-role/global USD authority
before provider I/O. Those controls are neither deployed nor an authorization. The exact
frozen-corpus token, USD, rate, timeout, and call ceilings still require a human-approved exact
budget, staged configuration, catalog preflight, and new approval before a live performance run;
bypassing preflight would invalidate the evidence.

An explicit staging-campaign-only extended window is source-tested to a 14,400-second run and
14,701-second server-derived grant, with the standard profile remaining the default. The current
1,800-second target catalog exposes no extended option, and four hours is not a completion estimate
or live evidence.

The source/configuration blockers and arithmetic are retained in the
[100-case capacity preflight](../provider/HOSTED_100_CAPACITY_PREFLIGHT_2026-07-24.md).
