# AgentForge current state

**Snapshot:** 2026-07-26

**Repository base before the operations candidate:** `29166688f2d3e3ec9744689907ac0e04ab5e044e`

**Repository parity at the latest read-only check:** `origin/main == gitlab/main == 2916668`

**Packaged schema:** sole Alembic head `0026`; the verified staging database remains at `0025`

**Canonical requirements:** [`Week_3_AgentForge.pdf`](../Week_3_AgentForge.pdf)

This is the current implementation and operations snapshot. It is the first document to read when
working on the platform. Code, migrations, tests, and read-only deployed-state checks were used to
produce it. Dated evidence and planning documents remain useful history but do not override this file
or the implementation.

## Executive status

The core platform is implemented: authenticated React/FastAPI Web, PostgreSQL control plane and
queue, private Runner and Scheduler, exact-scope campaign authorization, four hosted agent roles,
live target dispatch, independent Judge reconciliation, conditional Documentation, and fail-soft
Langfuse projection.

The platform is **not yet full-suite reliable**. The latest staging campaign executed 12 of 34 cases
and then failed because Gemini returned HTTP 200 with schema-invalid Judge output. The deployed
configuration authorized zero provider retries, and the Runner treats the resulting exhausted
exception as a terminal whole-campaign failure. The repository candidate now classifies fully
attributable, usage-settled schema-invalid output as retryable only inside the already-authorized
per-role/global retry and call/token/cost/rate envelopes. That behavior is not deployed, does not
grant a retry to the zero-retry staged configuration, and does not implement campaign resume. A fresh
run would still restart at case 1.

The latest run also proves that the prior hosted Red Team attempt-lineage defect is fixed: all 12
attempts were created before their Red Team provider calls, and no post-hoc lineage binding conflict
occurred.

## Deployment snapshot

### Staging

| Component | State | Evidence |
|---|---|---|
| Web | `SUCCESS` | deployment `ae2505f2-798b-4d96-98d9-7619e104feb0` |
| Runner | `SUCCESS` | deployment `ce2eeb34-95b-4ac0-999b-df3de4ea659a` |
| Scheduler | `SUCCESS` | deployment `4c2e38a4-6b10-4d0f-96ab-d51b2d8f63b9` |
| PostgreSQL | ready | sole Alembic head `0025` |
| Public Web | healthy | `/health` 200, `/ready` 200, unauthenticated `/api/v1/principal` 401 |

Web, Runner, and Scheduler all report generation-policy digest
`b83acb23122de9b4911032738bce136f214a34328357b457935ad821b44b0b18` and the same packaged
`hosted_policy.py` SHA-256,
`358c798924adaa50b8321e059d88975856c6e55f19e44faf88b95c5957b47305`.

Staging URL: `https://web-staging-8e30.up.railway.app`

### Production

Production is reachable and its Web boundary returns healthy/readiness responses, but it is
**release-skewed and not campaign-ready**:

- Web and Runner report policy digest `f02aa982…`;
- Scheduler reports `6a9e5480…`; and
- the production services are not on the staging/repository policy digest `b83acb23…`.

Do not use production for a governed campaign until Web, Runner, and Scheduler are intentionally
deployed from one reviewed commit, database compatibility is verified, and fresh authorization is
minted after deployment.

Production URL: `https://web-production-44528.up.railway.app`

### External target

The authorized Clinical Co-Pilot target is
`https://agent-production-9f62.up.railway.app`. Its `/health` and `/ready` endpoints returned 200 in
the 2026-07-26 read-only audit. The latest campaign bound matching target and chat-surface version
`1.0.1`. Live traffic still requires exact target/surface/version,
credential-generation, synthetic-fixture, canary, cap, lease, and two-person authorization.

## Implemented stack

| Layer | Current implementation |
|---|---|
| Backend | Python 3.12, FastAPI, Uvicorn, SQLAlchemy 2, psycopg 3, Alembic |
| Frontend | React 18, TypeScript 5.9, Vite 7, Clerk React/JS/UI |
| Durable state | PostgreSQL; append-only control-plane records, evidence, agent/provider lineage, jobs |
| Queue/orchestration | Custom Python durable Runner over PostgreSQL leases/`SKIP LOCKED`; no LangGraph dependency |
| Identity | Clerk session JWTs verified networklessly; exact Organization and custom-permission checks |
| Model routing | OpenRouter with exact model and upstream-provider binding; fallback disabled |
| Target transport | `httpx` through the Policy Gateway and versioned target adapters |
| Observability | PostgreSQL source of truth plus Langfuse 4.14.1 external projection |
| Deployment | One Docker artifact; Railway Web, Runner, Scheduler, PostgreSQL; Web-only public ingress |
| CI/release | GitHub Actions and GitLab CI must both pass; release refs must be identical |

The repository package is now at Alembic `0026`. Migration `0026` adds immutable,
organization-scoped prompt snapshots for logical agent executions. Runner can insert/select those
rows; Web can only select them. Append-only triggers prevent update/delete and enforce run,
attempt, role, and organization lineage.

## Operations-console candidate

The current source candidate consolidates primary navigation to exactly Runs, Findings, Coverage,
Approvals, Observability, and System while preserving legacy URLs as aliases. Runs opens the
authoritative campaign operations view; Traces and Costs accept an explicit selected campaign so old
runs are not hidden by bounded global projections.

`GET /api/v1/campaigns/{campaign_id}/operations` returns organization-scoped progress, current work,
logical and physical call counts, measured/partial cost, configured limits, queue state, verdict
distribution, and terminal failure facts. Unknown or incomplete facts remain null/partial rather
than becoming zero. The console consumes authenticated SSE with last-event reconnection and a
five-second polling fallback while preserving the last valid snapshot with freshness state.

`GET /api/v1/agent-executions/{execution_id}/prompt-snapshot` requires both
`org:console:read` and `org:evidence:read`. It returns one exact package-owned system prompt and the
ordered provider role/content transcript only after organization scoping, hash verification,
secret/PHI rejection, and bounded redaction validation. Prompt contents are collapsed by default and
are excluded from aggregate/list/SSE/log/Langfuse payloads.

## Hosted role set and per-call policy

| Role | Model | Required upstream | Trigger | Input | Output | Reasoning | Timeout |
|---|---|---|---|---:|---:|---:|---:|
| Orchestrator | `anthropic/claude-opus-4.8` | `anthropic` | each selection cycle | 12,288 | 1,024 | 1,024 | 120 s |
| Red Team | `qwen/qwen3.5-397b-a17b` | `chutes` in current staging config | each generation/selection cycle | 32,768 | 8,192 | 8,192 | 180 s |
| Judge | `google/gemini-2.5-pro` | `google-vertex` | each evaluated case | 32,768 | 512 | 1,024 | 180 s |
| Documentation | `openai/gpt-5.4` | `openai` | each confirmed finding | 12,288 | 512 | 1,024 | 120 s |

The live Red Team role is a hosted **closed-corpus selector**. It selects a `case_ref` from the exact
reviewed workload; it cannot author or mutate the bytes dispatched under that authorization. Separate
generation tooling can produce quarantined candidates, but candidates require review, frozen
provenance, a new workload digest, and fresh authorization before target execution.

Prompt registry identities:

| Role | Prompt version | SHA-256 |
|---|---:|---|
| Orchestrator | 1 | `0d851bb22f98921de1e8de42d90cd50fde73603d251b3a38c6591fd6f5a91bb2` |
| Red Team | 1 | `72310c2141e50bc5da0a85e8e2cad82a16ba2490aa6265efa8dc26790129a776` |
| Judge | 1 | `ae95f4b8398410b40c0b9b028aec47b6d7e027965b4f3eea4f5b524e58a29065` |
| Documentation | 1 | `4ebc294a0f24c5b7d367b986fd1b644c244d9c1df3dfe8492f5e347fb4247bd1` |

## Current staged hosted configuration

Staging configuration digest:
`a40723d196e2447ba7a6ee65390906841ad27574a872c9f47d5d86915490aef9`.

Global authority for the 34-case batch is:

- 136 physical model calls;
- 6,720,000 input, 470,000 output, and 1,700,000 reasoning tokens;
- measured provider spend ceiling `$10`;
- `max_retries = 0`;
- concurrency 1; and
- 0.5 provider requests/second.

Every role has 34 calls and zero retries in the staged set. Role spend ceilings are Orchestrator `$4`,
Red Team `$5`, Judge `$5`, and Documentation `$2`. These are ceilings, not forecasts. The closed
platform supports at most one retry per logical call, but no retry is authorized by this staged
configuration.

## Workload and target caps

The frozen full suite contains 100 cases and 121 target turns across six threat categories. It is
split into three separately authorized workloads because each hosted role is capped below the
100-call whole:

| Batch | Cases | Exact target-turn cap | Target retries |
|---|---:|---:|---:|
| `headshot-live-100-batch-01` | 34 | 41 | 0 |
| `headshot-live-100-batch-02` | 33 | 40 | 0 |
| `headshot-live-100-batch-03` | 33 | 40 | 0 |

The Runner enforces manifest order and exact logical/physical caps for the full corpus and each batch.
The full suite has not completed live.

## Latest governed live run

Run: `50da57b037d44b3c93a10e4c2edf61a8`

Window: 2026-07-26 20:58:06Z–21:12:32Z

Terminal state: `failed / campaign_execution_failed`

| Fact | Observed |
|---|---:|
| Durable attempts | 12 |
| Durable attempt results | 12 |
| Verdicts | 11, all `INDETERMINATE` |
| Hosted logical executions | 36 |
| Provider physical calls | 36 |
| Live target calls | 16: 15 HTTP 200, 1 HTTP 422 |
| Provider-measured cost | `$0.60731395` |
| Contracted target-call accounting | `$0.16` |
| Combined recorded amount | `$0.76731395` |

The fatal call was the 12th Judge execution:

- model `google/gemini-2.5-pro`;
- provider event `invalid_output`;
- 13,574 input, 230 output, 752 reasoning tokens;
- measured cost `$0.0267875`;
- HTTP transport succeeded, but the returned JSON failed the strict output schema.

The Red Team maximum observed latency was 65.9 seconds, which validates the 180-second timeout and
shows why the previous 60-second ceiling was unsafe. The observed end-to-end rate was about
72 seconds per case. At that serial rate, one 34-case batch is about 41 minutes and the 100-case suite
is about two hours before retry/resume improvements.

One target response was HTTP 422 for a message exceeding the target's 4,000-character limit. The
transport row is terminal and observed, but the current `status = succeeded` label describes receipt
of an HTTP response, not application-level success. Operator-facing documentation and UI must keep
that distinction explicit.

## Judge authority and calibration

The model Judge cannot confirm an exploit. Only a deterministic oracle, synthetic canary, or human
authority can produce `EXPLOIT_CONFIRMED`. A model may emit advisory
`EXPLOIT_LIKELY`/`NO_EXPLOIT_OBSERVED`, which is reconciled against deterministic evidence and the
deployed calibration gate.

Staging had no enabled exact-identity Judge calibration for the latest run. The 11 successful Judge
calls therefore persisted `calibration_state = unavailable`, `decision_authority = oracle`, and
final `INDETERMINATE` dispositions. They mean **no deterministic exploit was confirmed**; they do not
prove the target defended the attacks or establish a safe verdict.

## Langfuse state

PostgreSQL is authoritative. Langfuse is a fail-soft external projection.

For the latest failed run:

- all 36 agent executions are `langfuse_status = queued`;
- all 16 target requests are `langfuse_status = queued`; and
- none has `langfuse_verified_at`.

The existing verifier accepts only campaigns present in `campaign_run_summaries`, so a failed or
aborted run exits with `campaign must be a completed live run`. That means current tooling cannot
query-back verify the exact partial trace of a failed campaign. Provider physical attempts are
durable in PostgreSQL, but they are not yet first-class child observations in Langfuse.

Do not equate SDK `flush()` with remote delivery. Only authenticated exact query-back may mark a row
`exported`.

## Current reliability gaps

1. The candidate structured-output retry classification is not deployed or staging-accepted.
2. The deployed hosted configuration authorizes zero retries, so the candidate cannot retry under
   current authority.
3. One exhausted provider-format failure still aborts the entire batch.
4. A terminal batch cannot resume from its durable completed attempts.
5. Langfuse query-back rejects failed/aborted campaigns.
6. Physical provider attempts are not first-class Langfuse observations.
7. Exact current-identity Judge calibration is not enabled in staging.
8. Orchestrator and Red Team calls are expensive for an exact manifest whose next case is already
   fixed for lineage; the current model-selected singleton path adds latency without changing bytes.
9. Production services are release-skewed.
10. The full 100-case live suite has never completed.

## Required remediation order

The current implementation plan is [`../PLAN.md`](../PLAN.md). In short:

1. deploy and accept the candidate schema-invalid-output classification, then stage only the exact
   separately reviewed retry authority required for the Judge;
2. isolate exhausted per-case provider failures and continue with a contract-valid `ERROR` verdict;
3. resume terminal/interrupted batches from durable checkpoints without repeating observed target work;
4. add automatic, exact Langfuse query-back for complete, failed, and aborted runs, including physical
   provider-attempt observations;
5. capture and legitimately enable Judge calibration for the exact deployed model/upstream/prompt/
   policy identity;
6. deploy one identical release to Web, Runner, and Scheduler; and
7. run target-free acceptance, then one freshly authorized 34-case batch, then all three batches.

No documentation update itself authorizes deployment, Railway variable changes, credential rotation,
or a live campaign.
