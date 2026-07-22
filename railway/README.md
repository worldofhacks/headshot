# Railway service configuration

These files are config-as-code inputs for three services built from the same reviewed image:

- `/railway/web.json` — `python -m agentforge.web`; the only service permitted a public domain;
- `/railway/runner.json` — `python -m agentforge.runner`; private, no HTTP ingress; and
- `/railway/scheduler.json` — `python -m agentforge.scheduler`; private, no HTTP ingress.

All three builds require the environment-specific, public `VITE_CLERK_PUBLISHABLE_KEY` build
identifier because each independently compiles the shared Web image. No Clerk secret is a build
argument or request-authentication dependency.

Railway configuration is per deployment. During authorized provisioning, set each service's config
path to the corresponding absolute repository path. The JSON files do not create projects, services,
domains, databases, variables, or private-network policy. A human must verify in both staging and
production that Web alone has public ingress and that Runner, Scheduler, and PostgreSQL have none.

Only Web runs the pre-deploy command `alembic upgrade head`. Runner and Scheduler must refuse to
consume or enqueue work until their database is already at the integrated head. See
`docs/deployment/RAILWAY.md` for sequencing, environment isolation, variables, rollback, and required
deployment evidence.

The private Runner is composed over the durable queue and remains fail-closed until its database,
catalog, corpus, exact authorization, caps, and sealed credential reference all pass preflight.
The Scheduler remains unavailable because no authoritative schedule repository is implemented.
