# Pre-run Railway metrics baseline — 2026-07-24

## Evidence boundary

This is the Railway CLI seven-day summary captured at
`2026-07-24T22:37:01Z`, before the final deployment and 100-case campaign.
The `current` CPU and memory values are point-in-time samples returned with the seven-day window;
network values are window totals. They are not load-test percentiles or service capacity claims.

| Service | CPU current (vCPU) | Memory current (MB) | Egress (MB) | Ingress (MB) |
|---|---:|---:|---:|---:|
| Runner | 0.002363 | 117.786 | 0.019460 | 0.047503 |
| Web | 0.001313 | 136.184 | 3.463775 | 0.230071 |
| Scheduler | 0.000062 | 78.970 | 0 | 0 |
| Postgres | 0.000778 | 91.223 | 0 | 0 |
| legacy `headshot` service | 0.000788 | 73.707 | 0 | 0 |

The extra legacy `headshot` service is not part of the required final topology and cannot be counted
as a Runner, Scheduler, or observability component. It remains a topology/configuration item to
resolve before final acceptance. No public ingress was observed for it.

## Required post-run comparison

Capture the same window and raw time series around the authorized campaign. Report service CPU and
memory distribution, public network traffic, queue wait, database time, model/tool time, and
end-to-end latency separately. A point-in-time idle sample must not be labeled throughput or live
load evidence.
