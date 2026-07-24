# Langfuse Cloud predeployment baseline — 2026-07-24

## Evidence boundary

This is a read-only baseline captured before deploying the final Headshot integration candidate.
It is not campaign evidence and must not be cited as proof that the four-agent runtime has executed.
No credential value, trace identifier, campaign identifier, prompt, response, or patient-derived
field is retained here.

## Configuration and authentication

- Provider: Langfuse Cloud (US).
- Local credential source: ignored `.env.local`; only variable presence was inspected.
- Langfuse SDK: `4.14.1`.
- Authenticated API check: passed.
- Railway Runner deployment environment: `staging`.
- Railway Runner Langfuse tracing environment: `staging`.
- Railway Runner and local configuration resolve to the same Langfuse Cloud host.

## Read-only query result

The Langfuse Public API was paged with payload fields excluded.

| Environment | Total observations | Spans | Generations | Headshot campaign/execution markers |
|---|---:|---:|---:|---:|
| `staging` | 0 | 0 | 0 | 0 |
| `production` | 8,298 | 8,083 | 215 | 0 |

The production observations belong to the separately deployed target application: they carry its
service/request metadata and no Headshot campaign, execution, or agent-role markers. They are not
Headshot evidence and are excluded from all Headshot reconciliation totals.

## Reconciliation with the deployed Headshot database

At capture time Railway still ran commit `23490ea` with Alembic migration `0013`. PostgreSQL held
zero canonical `agent_executions`, finding-evidence links, or vulnerability reports. Therefore the
zero Headshot-marked Langfuse observations reconcile with the deployed database, but only as proof
that the new runtime has not yet run.

## Final acceptance requirement

After the exact final commit is deployed to staging, the authorized campaign must be queried back by
campaign trace ID. The final evidence must reconcile PostgreSQL and Langfuse counts, ordered agent
parentage, every physical model request, provider/model identity, latency, token usage, retries,
errors, and provider-reported cost. Missing or provider-estimated values must remain explicitly
classified; they must not be coerced to zero.
