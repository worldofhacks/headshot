# Railway service configuration

The three manifests deploy one reviewed Docker artifact as separate services:

- `railway/web.json` — public React/FastAPI Web; the only service with a domain;
- `railway/runner.json` — private durable campaign worker; and
- `railway/scheduler.json` — private target-version/replay-plan scheduler.

PostgreSQL is a fourth private managed service.

## Current release contract

- Web alone runs `alembic upgrade head`.
- Runner and Scheduler refuse work until PostgreSQL is at the exact packaged head.
- The current sole packaged head is `0026`; the last verified staging database remains at `0025`
  until this candidate is deployed.
- Web, Runner, and Scheduler must expose the same hosted generation-policy digest and packaged policy
  file hash before new campaign authorization is minted.
- Staging currently satisfies that policy parity. Production does not; see
  `docs/CURRENT_STATE.md`.
- The hosted Red Team is composed in governed campaigns as a closed reviewed-corpus selector.
- Provider and target calls occur only in Runner.

The JSON files configure a service deployment; they do not create projects, environments, services,
domains, databases, variables, private-network rules, Clerk configuration, or authorization.

## Required deployment order

Deployment is an explicit external operation:

1. Obtain the reviewed exact commit and require GitHub and GitLab CI green.
2. Push the same commit to `origin` and `gitlab`.
3. Stop launches/scheduling and prove no active campaign leases, running hosted executions, or
   dispatchable queued authorization.
4. Deploy the new Runner artifact first. It must remain inert while the old schema is active.
5. Deploy Web and allow its pre-deploy migration to reach the new sole head.
6. Verify Web readiness and exact schema.
7. Activate/verify Runner and its heartbeat.
8. Deploy/verify Scheduler.
9. Compare policy digest and packaged policy-file hash across all three services.
10. Run target-free four-role acceptance and exact Langfuse query-back.
11. Mint fresh target authorization only after all deployment checks pass.

Do not deploy Web and Runner from different commits. A policy digest minted by Web is resolved again
by Runner; version skew fails closed as `hosted_runtime_authority_invalid`.

## Process behavior

| Manifest | Important behavior |
|---|---|
| `web.json` | `/ready` health gate, pre-deploy Alembic migration, 30-second overlap, 60-second drain |
| `runner.json` | no HTTP ingress, 30-second overlap, 60-second drain; prove quiescence before migrations that make overlap unsafe |
| `scheduler.json` | no HTTP ingress, zero overlap, 30-second drain |

All three builds need the environment's public `VITE_CLERK_PUBLISHABLE_KEY` because the shared image
contains the compiled console. No Clerk, provider, target, database, or Langfuse secret is a Docker
build argument.

The full variable and rollback contract is in `docs/deployment/RAILWAY.md`.
