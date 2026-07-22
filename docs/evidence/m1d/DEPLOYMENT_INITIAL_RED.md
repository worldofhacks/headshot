# M1d deployment packaging RED evidence

Recorded test-first on 2026-07-21 before changing Docker, Alembic URL selection, or Railway
configuration.

Command:

```text
pytest -q tests/deployment
```

Result: **12 failed**. The failures proved the expected missing boundaries:

- five failures because `agentforge.migration_config` did not exist;
- three failures because the Dockerfile had no console-build, wheel-build, or final-runtime split;
- one failure because the Docker context admitted Node output, source maps, and local render output;
- three failures because the Web, Runner, and Scheduler Railway configs did not exist.

After those contracts passed, one additional focused RED was retained for the local build binding:

```text
pytest -q \
  tests/deployment/test_packaging_contract.py::test_local_compose_requires_the_public_clerk_build_identifier
```

Result: **1 failed** because Compose did not explicitly require the public
`VITE_CLERK_PUBLISHABLE_KEY` build argument. No fake key was added to Compose.

The operational local Web pass-through was also added test-first:

```text
pytest -q \
  tests/deployment/test_packaging_contract.py::test_local_compose_passes_only_explicit_web_auth_configuration
```

Result: **1 failed** because Compose did not yet pass the backend Clerk or Web boundary settings.
The implementation now requires each authentication binding explicitly, pins only the packaged
console path, and never passes `CLERK_SECRET_KEY` or provider/target credentials into Web.

These are local test results, not Railway deployment evidence. No Railway resource, domain, database,
variable, or Clerk resource was created or modified.
