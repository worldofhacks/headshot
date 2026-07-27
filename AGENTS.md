# AGENTS.md

Durable cross-tool rules for AgentForge / Adversarial Machine.

## Read first

1. `Week_3_AgentForge.pdf` — canonical requirements.
2. `docs/CURRENT_STATE.md` — current implementation, deployment, and open defects.
3. `CLAUDE.md` — full operating rules.
4. `ARCHITECTURE.md` — binding current architecture.
5. `PLAN.md` — current remediation and release plan.

Use `docs/DOCUMENTATION.md` to distinguish current instructions from dated evidence and historical
planning. When documentation disagrees with code, migrations, tests, or verified deployed state, the
implementation wins and the documentation must be corrected.

## What this repository is

AgentForge is a target-agnostic, multi-agent adversarial evaluation platform. Its first target is the
externally deployed OpenEMR Clinical Co-Pilot. No target code lives here; authorized live traffic exits
only through the Policy Gateway.

The implemented platform is Python/FastAPI/PostgreSQL plus a React/Vite console on Railway. Web is
public; Runner, Scheduler, and PostgreSQL are private. Orchestration is a custom durable PostgreSQL
queue/Runner, not LangGraph.

## Non-negotiables

- Test a deployed live target, never only a mock, for checkpoint evidence.
- Keep Orchestrator, Red Team, Judge, and Documentation as distinct agent roles and trust contexts.
- The model Judge cannot confirm an exploit. Oracle, canary, or human evidence is required.
- A confirmed exploit can never be downgraded to safe.
- Human approval is required before publishing critical findings or remediation.
- The launcher and approver must be different verified Clerk users.
- Authentication never authorizes target execution by itself.
- Every case is boundary, invariant, or regression and maps to OWASP Web and LLM categories.
- No real PHI. Use synthetic fixtures and synthetic canaries only.
- Cost is measured from durable provider/target facts; never invent token counts or prices.
- Provider/model/upstream/prompt/policy/configuration identities are exact and fail closed on drift.
- Web, Runner, and Scheduler must run the same reviewed release before new authorization is minted.
- Never weaken caps, retries, leases, allowlists, or evidence integrity merely to make a run pass.

## Current operational facts

- `origin/main == gitlab/main == 2916668` at the latest 2026-07-26 read-only check.
- Staging Web/Runner/Scheduler share policy digest `b83acb23…`; PostgreSQL is at Alembic `0025`.
- Production is release-skewed and is not campaign-ready.
- The latest 34-case staging run reached case 12, then a schema-invalid Gemini Judge response
  terminated the batch.
- The staged hosted configuration has `max_retries = 0`.
- Failed campaigns cannot currently resume, and Langfuse query-back currently rejects failed runs.

Re-verify dynamic facts before any operation; do not assume this snapshot is still live.

## External changes

Do not deploy, change Railway variables, rotate credentials, publish findings, or launch a live
campaign unless the user explicitly authorizes that action. A code/documentation task does not grant
live-operation authority.

## Working tree and release discipline

- Preserve user-owned changes. Use an isolated worktree when the active branch is dirty or diverges
  from the intended base.
- Use `apply_patch` for edits.
- GitHub Actions and GitLab CI are both release gates.
- Every release/checkpoint commit must be pushed unchanged to both `origin` and `gitlab`.
- `origin/main` and `gitlab/main` must resolve to the same commit, with both CI systems green.
- Never force-push, mirror-push, or set GitLab as the tracking remote.
