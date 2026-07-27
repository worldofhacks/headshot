# CLAUDE.md — AgentForge / Adversarial Machine

Repository operating instructions for Claude Code. The canonical requirements are
`Week_3_AgentForge.pdf`; current implementation and deployment facts are in
`docs/CURRENT_STATE.md`.

## Source hierarchy

Read, in order:

1. `Week_3_AgentForge.pdf`
2. the relevant code, packaged migrations, tests, and read-only deployed-state evidence
3. `docs/CURRENT_STATE.md`
4. this file
5. `ARCHITECTURE.md`
6. `PLAN.md`
7. the relevant operational runbook

`docs/DOCUMENTATION.md` defines authority and historical-document rules. Dated evidence describes the
recorded release and must not be promoted to present tense. `IMPLEMENTATION_PLAN.md` is the original
build decomposition, not current task status.

Never fabricate a value. If deployed state has not been read-only verified, say so.

## Product and posture

AgentForge is a reusable multi-agent adversarial evaluation platform. It attacks an external target
over an authorized live URL; target code is out of scope. The first target is the OpenEMR Clinical
Co-Pilot, so the threat model, workload, and vulnerability material are target-specific while the
engine, contracts, policy, storage, and observability remain target-neutral.

Build posture is production-grade: defendable to a hospital CISO. Failure behavior, evidence
integrity, deployment parity, rollback, and observability are required features.

## Implemented architecture

- Python 3.12, FastAPI/Uvicorn, SQLAlchemy/psycopg, Alembic, PostgreSQL.
- React 18, TypeScript, Vite, and Clerk for the same-origin operator console.
- One Docker artifact deployed to Railway Web, Runner, and Scheduler.
- Web alone is public. Runner, Scheduler, and PostgreSQL have no public ingress.
- A custom PostgreSQL queue and concurrency-one Runner perform durable orchestration.
- There is no LangGraph dependency or runtime.
- PostgreSQL is authoritative; Langfuse is a fail-soft external projection.
- Inter-agent and evidence contracts are JSON Schema v1 packaged under
  `src/agentforge/contracts/v1/`.

### Runtime roles

| Role | Current model | Current responsibility |
|---|---|---|
| Orchestrator | `anthropic/claude-opus-4.8` | Plans each coverage/selection cycle under deterministic governance |
| Red Team | `qwen/qwen3.5-397b-a17b` | Selects an exact case from a closed reviewed workload for governed replay |
| Judge | `google/gemini-2.5-pro` | Advisory structured assessment reconciled against oracle/canary/human authority |
| Documentation | `openai/gpt-5.4` | Drafts only after a trusted confirmed finding |

The current staging upstreams are Anthropic, Chutes, Google Vertex, and OpenAI through OpenRouter.
Provider fallback and model substitution are forbidden.

The live Red Team role cannot author target-bound bytes. Novel/mutated generation is quarantined,
reviewed, content-addressed, and requires a new workload plus fresh authorization before dispatch.

## Campaign flow

1. An authenticated Operator creates an exact authorization request.
2. A different authenticated Approver authorizes the immutable scope.
3. Web enqueues a campaign only after server-side scope validation.
4. Runner performs network-free preflight: schema, heartbeat, catalog, target/surface, workload,
   authorization window, session lease, credentials, generation policy, hosted configuration, caps,
   synthetic fixtures, and canaries.
5. For each exact workload case:
   - the Orchestrator runs;
   - the durable attempt is created before hosted Red Team provider I/O;
   - Red Team selects the authorized `case_ref`;
   - the Policy Gateway alone dispatches exact reviewed bytes to the target;
   - the recorder persists hashed evidence;
   - the Judge evaluates and code reconciles the model output with trusted evidence;
   - Documentation and regression admission run only for `EXPLOIT_CONFIRMED`.
6. Scheduler may create an authorization-blocked replay plan on target-version change. It never
   launches target traffic.

## Safety and authority invariants

- No real PHI; synthetic fixtures only.
- Clerk authenticates humans but never authorizes an attack.
- Only verified custom Organization permissions authorize application actions.
- `approver.user_id != launcher_user_id`; no self-approval or emergency bypass.
- Target credentials resolve only inside the private Runner at the dispatch boundary.
- Exact target, surface, version, workload, credential generation, caps, policy/config hashes,
  authorization expiry, and session lease are immutable run authority.
- The Judge holds no target credential, mutation tool, publication authority, or remediation
  authority.
- The model Judge cannot output authoritative `EXPLOIT_CONFIRMED`.
- Ambiguous or uncalibrated non-oracle outcomes are not safe; they remain `INDETERMINATE` or `ERROR`.
- Provider token/cost facts come from provider responses and durable physical-call rows.
- One observed target request must never be repeated merely because a later agent failed.

## Current hosted policy

Generation-policy digest on repository `main` and staging:
`b83acb23122de9b4911032738bce136f214a34328357b457935ad821b44b0b18`.

Per-call bounds:

- Orchestrator: 12,288 input / 1,024 output / 1,024 reasoning / 120 seconds.
- Red Team: 32,768 input / 8,192 output / 8,192 reasoning / 180 seconds.
- Judge: 32,768 input / 512 output / 1,024 reasoning / 180 seconds.
- Documentation: 12,288 input / 512 output / 1,024 reasoning / 120 seconds.

The Red Team envelope is intentionally large. A live Chutes call took 65.9 seconds and produced
thousands of completion tokens for a closed selection. Do not shrink this envelope as a reliability
fix.

The current staged 34-case configuration has 136 global calls, `$10` global provider spend,
concurrency one, 0.5 requests/second, and **zero retries** globally and per role. The platform maximum
of one retry per logical call is not active authority.

## Current defects that must remain visible

The 2026-07-26 run `50da57b…` completed 12 target attempts and failed on one HTTP-200,
schema-invalid Gemini Judge response.

Current behavior:

- HTTP 429/502/503, transport errors, and timeouts are retryable only if configuration authorizes a
  retry.
- The repository candidate also classifies a fully attributable, usage-settled structured-output
  validation failure as retryable, but only inside existing role/global retry and usage authority.
- The deployed staging release predates that candidate and its exact configuration authorizes zero
  retries, so no live retry is currently authorized.
- One exhausted agent exception fails the entire batch.
- Queue failure is persisted `retryable = false`.
- A fresh run restarts at case 1; there is no campaign resume.
- Failed-run Langfuse query-back is rejected because the verifier requires a completed summary.
- Agent and target rows remain `queued` until exact remote query-back; `flush()` is not proof.
- Physical provider attempts are durable but are not first-class Langfuse child observations.
- Staging has no enabled exact-identity Judge calibration.
- Production is release-skewed.

Do not describe the 11 `INDETERMINATE` verdicts as successful defenses. They prove only that no
deterministic exploit was confirmed in those cases.

## Required remediation direction

Follow `PLAN.md`. The intended reliability behavior is:

- deploy and accept the candidate that retries only genuinely schema-invalid provider output and only
  within explicit per-role/global retry, call, token, cost, and rate authority;
- keep settlement/model/route/budget/evidence failures non-retryable;
- after exhausted case-local provider flakiness, persist a contract-valid `ERROR` verdict and
  continue;
- resume from durable attempts/results/verdicts without repeating observed target work;
- abort the campaign only for governance/security/integrity failures or unknown target outcomes;
- remotely verify Langfuse for complete, failed, and aborted campaigns; and
- calibrate the exact deployed Judge identity before allowing decisive non-oracle authority.

## Human identity and routes

Clerk request verification is implemented and deployed. The backend:

- accepts a bearer `session_token`;
- verifies RS256 networklessly with `CLERK_JWT_KEY`;
- requires exact `CLERK_AUTHORIZED_PARTIES` and `CLERK_REQUIRED_ORG_ID`; and
- uses only verified custom Organization permissions.

Public routes are limited to `/health`, `/ready`, and the static/sign-in/session-task shell. All
`/api/v1` data and mutations are protected. Frontend capability labels never authorize.

The real-user Organization/MFA/two-person acceptance is a human Clerk Dashboard check. Do not claim it
from unit tests or a missing-token 401 alone.

## Observability

PostgreSQL stores campaign/attempt lineage, target requests, logical agent executions, physical
provider invocations/events, tokens, measured provider cost, target accounting, hashes, status, and
Langfuse delivery state.

Langfuse receives sanitized metadata, hashes, sizes, timing, status, usage, and cost, never raw
credentials or unbounded hostile bodies. Remote query-back—not SDK return—is the delivery proof.

When changing observability, preserve:

- one campaign trace;
- exact per-attempt parentage;
- logical agent observations;
- physical provider attempt child observations;
- target HTTP child observations;
- environment, tenant, model/upstream/request IDs, tokens, cost, and terminal status; and
- PostgreSQL as the recovery and reconciliation source.

## Documentation maintenance

Any change to models, upstreams, prompts, generation policy, staged caps, migration head, retry/resume
semantics, deployment topology, authentication, target/workload, or Langfuse hierarchy must update the
files listed in `docs/DOCUMENTATION.md`.

Do not alter dated evidence to imply it came from a newer run. Add a supersession note instead.

## Development workflow

- Preserve dirty user changes; use an isolated worktree based on the intended reviewed commit.
- Read relevant migrations and tests before changing behavior.
- Use test-driven changes and run the smallest relevant tests first, then the full required gate.
- No live target/provider call from ordinary unit/integration tests.
- Never put a raw secret, session, credential digest, hostile transcript, or real PHI in logs,
  fixtures, docs, prompts, or tool output.
- Planning skills do not write application code.
- Runtime agents are application code, not Claude skills.

## External-state authority

Do not deploy, change Railway variables, rotate credentials, publish findings, or launch a live
campaign unless the user explicitly requests that external mutation. When deployment is authorized,
stop launches, verify quiescence, deploy one exact release through the documented sequence, verify
policy/file hashes and heartbeats, and require fresh post-deploy authorization.

## Dual remotes and CI

GitHub Actions and GitLab CI are both release gates. The committed `.gitlab-ci.yml` mirrors the test,
console, container, secret-scan, and security-tool classes required by GitHub.

For every release/checkpoint:

1. require GitHub and GitLab CI green on the exact commit;
2. push that unchanged commit to `origin`;
3. push the same commit to `gitlab`; and
4. verify `origin/main == gitlab/main`.

Never use `--force`, `--mirror`, or `-u` for the GitLab remote.
