# AgentForge current state

**Snapshot:** 2026-07-27

**Repository base before the operations candidate:** `cf18e119dc1592d72aa6a707d280ad65062dd093`

**Repository parity at the latest read-only check:** `origin/main == gitlab/main == d6136ff`
(2026-07-27, immediately before this candidate was pushed)

**Packaged schema:** sole Alembic head `0032`; the verified staging database is at canonical `0026`
before this candidate is deployed

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
| Web | `SUCCESS` | deployment `74d39043-7ef8-410e-963d-e7aee107ec13` |
| Runner | `SUCCESS` | deployment `0a6a2303-4bc2-4c20-b156-12ed34e545df` |
| Scheduler | `SUCCESS` | deployment `6689fdf2-a92e-4af1-808b-6d8068f05ef2` |
| PostgreSQL | ready | repository candidate head `0032`; deployed staging at canonical `0026` |
| Public Web | healthy | `/health` 200, `/ready` 200, unauthenticated `/api/v1/principal` 401 |

This table is the pre-candidate baseline: these deployment IDs predate the provider-call
observability candidate and are superseded the moment it is deployed. Their exact source commit is
not authoritatively represented in Railway's local-upload metadata, so service parity must be
re-established by deploying one reviewed candidate SHA to all three services. The deployment IDs,
migration revision, and live verification for a given release are recorded in that release's
handoff rather than asserted here, so this file never claims a deployment it did not verify.

The packaged default generation-policy digest remains
`b83acb23122de9b4911032738bce136f214a34328357b457935ad821b44b0b18`. This is a source-package
identity, not a claim that the three deployments above currently expose that digest.

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

The repository package is now at Alembic `0032`. Migration `0026` adds durable campaign outcome
counts; migration `0027` adds immutable,
organization-scoped prompt snapshots for logical agent executions. Runner can insert/select those
rows; Web can only select them. Append-only triggers prevent update/delete and enforce run,
attempt, role, and organization lineage.

Migration `0028` makes the *received* side of a hosted call provable. Before it,
`provider_call_events` recorded only measurements, so the platform could state that a physical call
happened and what it cost but never what the provider actually returned. `0028` is expand-only and
adds three columns to that table: `response_text` (nullable, bounded to 65,536 bytes),
`response_truncated`, and `response_sha256`. Nothing is backfilled — rows written before this
revision genuinely have no observed response and stay `NULL` rather than acquiring an invented one.
Check constraints force the digest to cover exactly the stored text and force text and digest to
appear and vanish together. The columns are populated by the same single INSERT that records the
call's terminal facts, under the append-only trigger from `0018`; the revision adds no mutation
path.

Migration `0029` keeps the evaluator's own argument with the verdict it produced. The hosted
evaluator's output schema *requires* a `rationale` (1–4,000 characters) and reports the
`criteria_hits` it believes fired, and both were discarded in transit: the verdict builder copied
the criteria and dropped the rationale, the verdict contract had no member for either, and the
`verdict` table had no column for them. A served verdict therefore decayed to
`reason_codes = ['calibrated_positive']` — a security claim at confidence 0.90 with no recorded
justification, unqueryable and unauditable. `0029` adds nullable `rationale` (bounded at the
evaluator's own 4,000-character limit) and `criteria_hits`, expand-only, nothing backfilled. Two
CHECK constraints carried the weight: the bound, and
`rationale IS NULL OR confirmation_source = 'calibrated_model'`.

Migration `0030` lifts that second constraint, because it was drawn in the wrong place. The
evaluator runs on *every* adjudicated case: `reconcile_judge_assessment` receives its assessment
alongside the deterministic verdict and, when an oracle or canary fired, returned ground truth and
discarded the reasoning. So the assessment exists for confirmed exploits too — and vulnerability
reports, which are generated **only** from `EXPLOIT_CONFIRMED`, could therefore never carry one.
`0030` separates the two things `0029` conflated: `confirmation_source` remains the sole statement
of authority, while `rationale` now means "the evaluator's advisory assessment of this attempt",
recorded whatever decided the verdict. The report payload carries
`model_assessment.authority = "advisory_never_confirmatory"` as a constant in the data, so the
advisory status survives export, copy-paste and being read as raw JSON, and the report's
`observed_behavior` continues to name the trusted source that confirmed the exploit. The
4,000-character bound is untouched and nothing is backfilled.
Verdicts written before `0029` report the rationale as unavailable rather than acquiring an
invented one.

## Campaign fault isolation

A campaign aborts only for governance, security or integrity failures, or a target the platform
can no longer reason about. Four case-local faults are isolated instead — three provider-side, one
target-side:

- `HostedStructuredOutputInvalid` (and its `HostedStructuredOutputTruncated` subclass) — a
  proposal or adjudication that will not parse.
- `HostedProviderUnavailable` — every authorized physical attempt failed to reach the provider.
  This type is raised at exactly one site, the exhaustion of the retry loop, whose cause can only
  be a timeout, a transport error, or a retryable status: the three faults recorded as
  *unobserved*. It is a narrow subclass rather than `HostedProviderError` itself because that base
  also covers budget, settlement and accounting failures, which must still abort — and because the
  error *code* cannot discriminate either, since `HostedSettlementFailed`, `_PhysicalCallError`
  and `_StructuredOutputAbsent` all report the identical `hosted-provider-unavailable`.
- `HostedProviderResponseUnusable` — one physical response was rejected for its own shape: a
  terminal HTTP status, a body that will not parse as JSON, a body that is not an object, or usage
  accounting incomplete for no attributable reason. It is the counterpart of the type above on the
  opposite exit — that one requires retry *exhaustion*, while this one leaves the transport
  immediately and untried. Its `_PhysicalCallError` siblings for `identity_invalid` and
  `route_unauthorized` are deliberately excluded: each names an authority already observed to be
  violated, and continuing to attack through a provider known to be the wrong one is not isolation.
  The split is by type at the raise site, never by inspecting `logical_error_code`.

- `IncompleteMultiTurnAttempt` — a sequential multi-turn sequence ended before every authorized
  turn was sent, because a turn returned a non-2xx status. Raised at one site in the Policy
  Gateway. It is a narrow `AbortError` subclass for the same reason: the base also carries budget,
  rate, attempt and physical-request-cap breaches, which are facts about the run's authority and
  must always abort.

They differ deliberately in what they leave behind. In the proposal phase no target turn ran,
so there is no evidence and the pre-bound attempt is abandoned un-attacked rather than handed a
verdict it did not earn. In the dispatch phase a *provider* fault leaves the target already
attacked with its evidence recorded, so the case receives a contract-valid `ERROR` verdict. An
unfinished multi-turn sequence has neither: the attempt is partially dispatched but has no
`attempt_result` row, so it is abandoned without a verdict — writing `ERROR` there would be a claim
the evidence cannot support. None of the three can open a finding or trigger the Documentation
agent.

What remains unknown after a partial sequence is bounded and specific: whether the target processed
the turn that failed. That makes the attempt unadjudicable, not the campaign. Live example — run
`2cf3773d` (2026-07-27) sent turn 1 successfully, took one HTTP 502 on turn 2 after 63.8 seconds,
and discarded 33 authorized cases; the target answered healthily moments later.

`HostedProviderResponseUnusable` has the same provenance. Run `94c141a2` (2026-07-27) reached 13 of
34 authorized cases — two of them `EXPLOIT_LIKELY` — before one invalid-JSON body from OpenRouter
ended it after 42 minutes, on the chain
`CampaignAbort[red_team_proposal_failed] <- _PhysicalCallError <- JSONDecodeError`. The fault was
already understood and already isolated in principle; it escaped because `_PhysicalCallError` is a
*sibling* of `HostedProviderUnavailable` rather than a subclass, so it matched neither handler.
That is the specific hazard the type algebra in `tests/test_red_team_proposal_isolation.py` now
pins: a shared base is never the isolatable unit, and neither isolated type may become an ancestor
of the other.

Sustained failure still aborts, on both axes. Total proposal abandonment leaves
`dispatched_case_count` at zero and raises, and three *consecutive* unfinished multi-turn attempts
abort with `target_unavailable` — the streak resets on any case that completes dispatch, so it
means consecutive rather than cumulative. A campaign that attacked nothing may never be reported as
a campaign that found nothing, and a target that is down must stop the run rather than absorb a
queue of unadjudicable work.

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

`GET /api/v1/provider-calls?campaign_id=…` projects one row per durable OpenRouter invocation from
`provider_call_invocations` joined to its terminal `provider_call_events` row and logical
`agent_executions` parent. It exposes attempt/role/sequence, requested and returned model/upstream,
provider request ID, latency, tokens, measured cost, terminal status, and a deterministic Langfuse
trace/observation locator. The same physical-call ledger is rendered in Run Operations,
Observability → Traces, and Observability → Costs. It creates no second accounting store and does not
query Langfuse from the browser.

`GET /api/v1/agent-executions/{execution_id}/prompt-snapshot` requires both
`org:console:read` and `org:evidence:read`. It returns one exact package-owned system prompt and the
ordered provider role/content transcript only after organization scoping, hash verification,
secret/PHI rejection, and bounded redaction validation. Prompt contents are collapsed by default and
are excluded from aggregate/list/SSE/log/Langfuse payloads.

`GET /api/v1/provider-calls/{invocation_id}/evidence` requires the same `org:console:read` plus
`org:evidence:read` pair and serves one physical call at a time. It returns the exact sent prompt —
reused from that call's protected `agent_prompt_snapshots` row through the same store accessor, so
the identical hash recomputation and secret/PHI rejection apply — together with the exact provider
response recorded for that invocation by migration `0028`. Both members are nullable and neither is
ever reconstructed: `prompt` is `null` when the logical execution has no snapshot, and `response` is
`null` when no response was observed for that physical call. A hash is never presented as response
content.

The response bytes are captured in the transport *before* structured-output validation, so the body
that failed validation is exactly the one an operator can read. They are credential-redacted using
the same sanitizer the outbound telemetry exporter uses, plus the literal bearer value that call
sent, so an upstream echoing the `Authorization` header cannot durably store the credential.
Capture is thread-local and cleared at the start of every physical attempt, so a retry never
inherits the previous attempt's body and each physical response stays bound to its own invocation.

These contents are served only by this per-call route. The aggregate
`GET /api/v1/provider-calls` projection selects an explicit measurement column list and never
includes prompt or response bytes; they are likewise absent from SSE, logs, Langfuse metadata, and
the browser bundle. In the console the evidence is a collapsed "Prompt & response" disclosure on
every ledger row, and the protected read is issued only when an operator expands it.

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
query-back verify the exact partial trace of a failed campaign.

Current source projects every durable physical provider attempt as a metadata-only
`provider.attempt.<sequence>` child span beneath the cost-bearing logical runtime generation. The
span carries model, upstream, provider request ID, tokens, measured cost, duration, status, and error
as metadata; usage/cost remain on the logical generation so Langfuse cannot double count them.
Headshot exposes the deterministic trace/name/attempt locator for each call. Exact remote
query-back proof is still persisted at the logical agent-row level, not as a separate timestamp for
each physical child span.

Do not equate SDK `flush()` with remote delivery. Only authenticated exact query-back may mark a row
`exported`.

## Current reliability gaps

1. The candidate structured-output retry classification is not deployed or staging-accepted.
2. The deployed hosted configuration authorizes zero retries, so the candidate cannot retry under
   current authority.
3. One exhausted provider-format failure still aborts the entire batch.
4. A terminal batch cannot resume from its durable completed attempts.
5. Langfuse query-back rejects failed/aborted campaigns.
6. Per-child Langfuse query-back proof is not persisted separately from the logical agent row.
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
