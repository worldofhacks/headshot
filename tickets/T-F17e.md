---
id: T-F17e
title: Publish truthful hosted-runtime capability and gate deployment
status: backlog
wave: 30
depends_on: [T-F17d, T-F18j]
branch: ticket/T-F17e-hosted-capability-deployment
file_scopes:
  - src/agentforge/telemetry/outbound.py
  - src/agentforge/runner.py
  - src/agentforge/storage/models.py
  - src/agentforge/control_plane/store.py
  - src/agentforge/api/postgres.py
  - src/agentforge/app.py
  - migrations/versions/*_hosted_runtime_capability.py
  - .env.example
  - railway/**
  - docs/deployment/RAILWAY.md
  - docs/deployment/FOUR_MODEL_RECOVERY.md
test_scopes:
  - tests/test_hosted_capability.py
  - tests/test_migrations.py
  - tests/deployment/test_hosted_runtime_deployment.py
model_hint: capable
attempts: 0
traces_to:
  - AGENTS.md Railway topology, Clerk boundary, Policy Gateway authorization
  - Week_3_AgentForge.pdf deployed live system, observability, auth/rate documentation
  - docs/planning/agent-runtime-provenance.md Web boundary and deployment gate
---

## Context
Wave 30 consumes T-F17d's executable private-Runner composition and accepted T-F18j unknown-cost
consumer migration. It is the next serialized `runner.py` owner. A dedicated content-addressed
capability observation, not the environment-only component table, is the cross-service authority.

## Acceptance Criteria
- **AC-1**: Given every Runner startup, when its new instance/generation begins, then it immediately
  supersedes prior operational evidence with `verifying`; success publishes operational only after
  checks, while failure publishes unavailable/degraded. Each secret-free observation binds
  organization, configuration-set hash, release id, image digest, deployed revision,
  prompt-registry hash, credential-reference-set hash, environment, instance/generation, database
  time, status, and bounded reason.
- **AC-2**: Given Web hosted preflight or launch, when capability is missing, stale, degraded, or
  mismatches the campaign on any organization/config/release/image/revision/prompt/credential-ref/
  environment/instance/generation field, then Web refuses launch with a typed generic reason.
- **AC-3**: Given fresh capability, when Web projects hosted readiness, then it derives the result
  from PostgreSQL time/heartbeat rather than a hard-coded constructor boolean or browser claim.
- **AC-4**: Given Web and Runner deployment configuration, when statically inspected and container
  smoked, then both use one reviewed image/release, only Runner receives provider credentials, only
  Web is public, and readiness/preflight performs no provider or target call.
- **AC-5**: Given staging promotion, when migration/deploy gates run, then migration, same-image
  parity, Runner-first heartbeat, authenticated Web preflight, and secret scans are evidenced before
  any separately authorized campaign.
- **AC-6**: Given rollback, when the prior image is restored, then hosted admissions fail closed on
  superseded/nonmatching capability, active work hard-aborts/preserves evidence, the prior release
  receives a new explicitly selected generation, and additive lineage data is retained.
- **AC-7**: Given promotion, when backend PostgreSQL/read-model/Birdseye/campaign accounting is
  checked, then accepted T-F18j proves partial/unknown costs remain unknown, mixed evidence reports
  known subtotal plus unknown count, and provider events are not double-counted; otherwise
  deployment is blocked. Agents projection remains T-F17f and the full Costs UI remains T-F18p.

## Test Plan
- Unit/integration: exact content identity, supersession, wrong org/config/release/prompt/
  credential-reference/generation, rollback overlap, launch gates, and Web projection.
- Deployment: Docker/Railway config, variable allowlist, same-image contract, offline readiness.
- Live evidence: separate owner-approved deployment/campaign gate; not a deterministic test.

## Definition of Done
- [ ] Independent Test Agent produced criterion-tagged RED and Test Reviewer froze it.
- [ ] `.tdd-swarm/run-local-gates.sh tickets/T-F17e.md <DIFF_BASE>` exits 0.
- [ ] Container, migration-copy, deployment-config, auth, and secret gates pass.
- [ ] Runbook names promotion, smoke, abort, and rollback evidence without embedding values.
- [ ] Independent Code and Security reviewers have no Critical/Important findings.

## Out of Scope
No Railway mutation, provider/target call, credential rotation, production promotion, main merge,
or human approval in this code ticket.
