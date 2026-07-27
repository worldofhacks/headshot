# Documentation authority and maintenance

This repository contains many Markdown files. They do not all describe current runtime state. Some are
requirements, some are binding design, some are operational runbooks, and many are dated evidence or
historical planning records. Treating them as one flat set is how stale instructions reached live
operations.

## Authority order

When sources disagree, use this order:

1. [`Week_3_AgentForge.pdf`](../Week_3_AgentForge.pdf) — product requirements and graded floor.
2. Current code, packaged migrations, tests, and read-only deployed-state evidence — implemented
   behavior.
3. [`CURRENT_STATE.md`](CURRENT_STATE.md) — dated implementation/deployment snapshot.
4. [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — current binding architecture and trust boundaries.
5. [`../PLAN.md`](../PLAN.md) — current remediation and release plan.
6. [`../CLAUDE.md`](../CLAUDE.md) and [`../AGENTS.md`](../AGENTS.md) — operating instructions.
7. Operational runbooks such as [`deployment/RAILWAY.md`](deployment/RAILWAY.md) and
   [`security/AUTHENTICATION.md`](security/AUTHENTICATION.md).
8. Dated evidence, reviews, migration notes, incident records, and historical planning — evidence of
   what was true at the recorded time, never present-tense authority.

An external service can change after a snapshot. Re-verify Railway deployment identity, health,
database head, policy digest, heartbeat, lease, and authorization immediately before an operation.

## Current documents

These files must stay aligned with implementation changes:

- `AGENTS.md`
- `CLAUDE.md`
- `README.md`
- `ARCHITECTURE.md`
- `PLAN.md`
- `USERS.md`
- `THREAT_MODEL.md`
- `.env.example`
- `console/README.md`
- `railway/README.md`
- `docs/CURRENT_STATE.md`
- `docs/deployment/RAILWAY.md`
- `docs/security/AUTHENTICATION.md`
- `docs/cost/COST_ANALYSIS.md`
- `docs/demo/MVP_DEMO_SCRIPT.md`
- `docs/defense/DEFENSE_SCRIPT.md`
- `docs/target/TARGETS.md` and `docs/target/READINESS.md`
- `docs/agents/RED_TEAM_MODEL_RESOLUTION.md` and `docs/agents/RED_TEAM_TRACED_GENERATION.md`
- current ADRs, including `docs/adrs/0004-postgresql-native-hosted-runtime.md`

`IMPLEMENTATION_PLAN.md` is the original build decomposition. Its checkboxes are historical unless a
new dated reconciliation explicitly changes them; current work is in `PLAN.md`.

## Historical and evidentiary documents

The following path classes are intentionally retained as historical records:

- `docs/evidence/**`
- `docs/integration/migration-notes/**`
- `docs/planning/**` other than links from the current plan
- `IMPLEMENTATION_PLAN.md`, `TICKETS.md`, and `tickets/T-F*.md`
- `.tdd-swarm/reports/**`
- `evals/results/**`
- dated reviews in `docs/security/**`
- vulnerability reports and reproduction records

Do not rewrite a dated observation to make it look as if it was produced by a newer release. Add a
supersession notice and link to `CURRENT_STATE.md` when readers could mistake it for current
instructions.

## Update contract

Any change to one of these runtime authorities must update the indicated documentation in the same
change:

| Runtime change | Required documentation |
|---|---|
| Hosted model/upstream/prompt/policy/caps | `CURRENT_STATE.md`, `ARCHITECTURE.md`, `README.md` |
| Alembic head or deployment sequence | `CURRENT_STATE.md`, `deployment/RAILWAY.md`, `railway/README.md` |
| Environment variable | `.env.example` and the owning runbook |
| Public/protected route or Clerk permission | `README.md`, `security/AUTHENTICATION.md`, `USERS.md` |
| Campaign failure/resume/retry semantics | `CURRENT_STATE.md`, `ARCHITECTURE.md`, `PLAN.md` |
| Langfuse hierarchy/query-back semantics | `CURRENT_STATE.md`, `ARCHITECTURE.md`, console and deployment docs |
| Target/workload/cap change | `CURRENT_STATE.md`, `THREAT_MODEL.md`, target/campaign runbooks |
| Measured cost/performance evidence | `cost/COST_ANALYSIS.md` and `CURRENT_STATE.md` |

Never copy a dynamic credential, session value, token, raw hostile transcript, or real PHI into
documentation. Opaque IDs, hashes, counts, bounded error codes, and synthetic evidence are sufficient.
