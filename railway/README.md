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
consume or enqueue work until their database is already at the one exact packaged head.

For the `0017` → `0018` → `0019` release, “Runner before Web” means:

1. obtain the signed, environment-specific human deployment grant binding the exact commit/image,
   public Web origin, service IDs, revision range, and packaged target head;
2. close launches/scheduling and prove zero active leases, running hosted executions, and queued
   dispatchable authorizations;
3. scale the old Runner to zero—`runner.json` permits 30 seconds of process overlap, which is unsafe
   for this migration;
4. deploy the new Runner artifact first against `0017` and prove it remains inert at the exact-head
   gate;
5. stage Web without public promotion and let its sole migrator apply `0018`, `0019`, and every
   later serialized revision through the exact packaged head;
6. verify and activate the new private Runner; then
7. promote Web publicly and complete the human-provided signed-in audit.

Here, deploying an artifact does not activate work consumption or public traffic. Do not perform
any production step without the signed grant, and do not bypass the signed-in audit if production
stops at `/sign-in`. See `docs/deployment/RAILWAY.md` for the complete sequencing, environment
isolation, variables, rollback, and evidence requirements.

The private Runner is composed over the durable queue and remains fail-closed until its database,
catalog, corpus, exact authorization, caps, and sealed credential reference all pass preflight.
The current Red Team step is deterministic authorized-corpus selection; the traced q generator is
not production-composed and must not be reported as a fourth live hosted role.
The private Scheduler observes ready target versions and writes idempotent, append-only regression
replay plans that remain blocked on human authorization. It does not enqueue or execute attacks.
