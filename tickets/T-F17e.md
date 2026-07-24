---
id: T-F17e
title: Publish truthful hosted-runtime capability and gate deployment
status: backlog
wave: 29
depends_on: [T-F17d]
branch: ticket/T-F17e-hosted-capability-deployment
file_scopes:
  - src/agentforge/telemetry/outbound.py
  - src/agentforge/api/postgres.py
  - src/agentforge/app.py
  - .env.example
  - railway/**
  - docs/deployment/RAILWAY.md
  - docs/deployment/FOUR_MODEL_RECOVERY.md
test_scopes:
  - tests/test_hosted_capability.py
  - tests/deployment/test_hosted_runtime_deployment.py
model_hint: capable
attempts: 0
traces_to:
  - AGENTS.md Railway topology, Clerk boundary, Policy Gateway authorization
  - Week_3_AgentForge.pdf deployed live system, observability, auth/rate documentation
  - docs/planning/agent-runtime-provenance.md Web boundary and deployment gate
---

## Context
Wave 29 consumes T-F17d's executable private-Runner composition. PostgreSQL database time and a
Runner-owned component heartbeat are the only cross-service runtime-capability authority. The Web
service remains read-only for provider readiness and never receives a provider credential.

## Acceptance Criteria
- **AC-1**: Given a Runner whose prompt/configuration/provider-binding checks pass, when it starts
  and heartbeats, then it publishes a secret-free `hosted-four-role-runtime` capability for its
  exact environment; failed composition publishes unavailable/degraded state without values.
- **AC-2**: Given Web hosted preflight or launch, when capability is missing, stale, wrong-environment,
  or degraded, then Web reports a typed degraded/unavailable reason and refuses hosted launch.
- **AC-3**: Given fresh capability, when Web projects hosted readiness, then it derives the result
  from PostgreSQL time/heartbeat rather than a hard-coded constructor boolean or browser claim.
- **AC-4**: Given Web and Runner deployment configuration, when statically inspected and container
  smoked, then both use one reviewed image/release, only Runner receives provider credentials, only
  Web is public, and readiness/preflight performs no provider or target call.
- **AC-5**: Given staging promotion, when migration/deploy gates run, then migration, same-image
  parity, Runner-first heartbeat, authenticated Web preflight, and secret scans are evidenced before
  any separately authorized campaign.
- **AC-6**: Given rollback, when the prior image is restored, then hosted admissions fail closed on
  stale capability, active work hard-aborts/preserves evidence, and additive lineage data is retained
  without emergency production downgrade.

## Test Plan
- Unit/integration: heartbeat freshness/environment/status, launch gates, Web projection.
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
