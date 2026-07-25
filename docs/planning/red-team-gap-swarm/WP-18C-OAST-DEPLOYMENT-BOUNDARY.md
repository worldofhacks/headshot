# WP-18C — Prepare an owner-gated OAST deployment boundary

**Branch:** `rtg/wp18c-oast-deployment-boundary`

**Model:** capable

**Depends on:** WP-07, WP-08, WP-16D, WP-18A

**Implements toward (live validation pending):** deployment-boundary portion of RT-06

Read AGENTS.md's only-Web-public and public-route laws, WP-07, WP-18A, Railway topology,
ownership authorization, and the Collaborator/OAST finding.

**Implementation writes only**

- `src/agentforge/security_tools/oast_protocols.py`
- `src/agentforge/security_tools/oast_deployment.py`
- `src/agentforge/contracts/v1/oast_deployment_policy.json`
- `docs/security/OAST_ARCHITECTURE.md`
- `docs/deployment/RAILWAY.md`
- `src/agentforge/web.py` only if an owner-approved repository policy decision explicitly
  authorizes the exact callback host/path
- `src/agentforge/app.py` only under the same condition

**Test writes only**

- `tests/security_tools/test_oast_protocols.py`
- `tests/security_tools/test_oast_deployment.py`
- `tests/test_public_shell_routes.py`

## Required result

Keep OAST deployment disabled by default. Model protocol support honestly:

- private per-attempt HTTP/HTTPS callback ingestion may be prepared;
- DNS and SMTP observation are `unsupported` unless the owner supplies separately isolated,
  authorized infrastructure and retention/abuse controls;
- no generic “Collaborator parity” label is allowed.

Create a fail-closed deployment policy binding exact callback domain, route, protocol,
certificate, environment, ownership record, token format, TTL/event/rate/size caps,
retention, abuse response, synthetic-only rule, source/network metadata policy, release
hash, and owner architecture-decision hash. Validate that only the Railway Web service is
public and that Runner/Scheduler/Postgres stay private.

The current repo law allows only minimal liveness/readiness and Clerk shell routes. Without
an explicit owner-approved repository policy decision changing that law, do not add or
enable a public callback route: finish protocol/deployment validation, keep state
`blocked_owner_architecture`, and return `DONE_WITH_CONCERNS`. If such a decision exists,
add only one exact host/path receiver that returns indistinguishable minimal responses and
cannot expose the SPA, APIs, metrics, queue, admin, artifacts, or token validity.

Tests prove disabled-default behavior, exact-host routing, public-shell non-regression,
unknown/expired-token indistinguishability, Host/cache/forwarded-header spoofing denial,
storm/rate/retention controls, protocol status honesty, and no private-service exposure.
Direct-validate the schema; WP-19B owns final registry/package parity.

**Focused verifier**

```bash
python -m pytest tests/security_tools/test_oast_protocols.py tests/security_tools/test_oast_deployment.py tests/test_public_shell_routes.py tests/test_web_m1d.py -q
```

No DNS, certificate, Railway, route, deployment, listener, or callback mutation. WP-21A
must admit and WP-21D must use the separate owner decision, deployed release/receiver,
domain ownership, and OAST authorization before any external callback.
