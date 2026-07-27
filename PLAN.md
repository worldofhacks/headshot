# PLAN.md — Full-suite reliability and release plan

**Updated:** 2026-07-26

**Requirements:** `Week_3_AgentForge.pdf`
**Current evidence:** `docs/CURRENT_STATE.md`

The platform exists and runs live cases. This plan is no longer a scaffold/build roadmap; it is the
ordered work required to make a 34-case batch and then the full 100-case suite complete reliably with
truthful Judge and Langfuse evidence.

Nothing in this plan authorizes a deployment, variable change, credential rotation, or campaign
launch. Those actions require explicit user authorization.

## Goal

Complete all three exact live-100 batches without:

- repeating an observed target turn;
- losing agent/provider/target lineage;
- converting uncertainty into a safe verdict;
- exceeding exact calls, tokens, cost, rate, retry, lease, or target caps;
- leaving Langfuse delivery unverifiable; or
- running Web, Runner, and Scheduler from different releases.

## P0 — Documentation and authority baseline

- [x] Establish `docs/CURRENT_STATE.md` from current code and read-only staging evidence.
- [x] Replace stale root instructions, architecture, and plan.
- [x] Classify dated evidence as historical in `docs/DOCUMENTATION.md`.
- [x] Add/keep a CI documentation contract that detects obsolete migration, role, policy, and
  runtime-framework claims in current documents.

**Gate:** a new agent can identify the current stack, role models, Alembic head, staged retry count,
latest run failure, calibration state, Langfuse limitation, staging/production status, and next work
without consulting chat history.

## P1 — Safe structured-output retry

**Repository candidate status:** the transport now separates settled usage/cost from structured
parsing, records `invalid_structured_output`, preserves each physical attempt, and retries only within
the minimum already-authorized per-role/global/ledger authority. This is not deployed or
staging-accepted; the staged configuration remains `max_retries = 0`, and no cap/configuration
widening is part of this candidate.

The candidate classification applies only to a provider response that:

1. reached an authorized endpoint;
2. returned a fully attributable HTTP response;
3. passed requested/returned model and upstream-route checks;
4. supplied valid usage/cost facts that were durably settled; and
5. failed only strict JSON decode/schema validation.

Required behavior:

- separate usage settlement from structured-output parsing;
- emit specific `invalid_structured_output`, not generic `hosted-provider-unavailable`;
- persist physical attempt 1 as observed `invalid_output`;
- retry once only when both role and global configuration authorize it;
- reserve and settle retry calls/tokens/cost independently;
- never retry model substitution, route drift, budget/cap failure, invalid usage/cost, evidence
  integrity failure, authorization expiry, or unknown provider outcome;
- keep target retries at zero; and
- aggregate both physical attempts into the logical agent totals.

Stage a new append-only hosted configuration after code review:

- Judge `max_retries = 1`;
- all other role retries remain 0;
- Judge calls 68 for a 34-case workload;
- global calls 170;
- global retries 1;
- Judge/global token and spend envelopes sized from the exact price-bound 68-Judge-call worst case;
  never assume a dollar value from the 12-case average; and
- global/other-role envelopes left no wider than the exact workload requires.

The current closed platform ceilings reject that configuration (`HOSTED_MAX_PHYSICAL_CALLS = 56`,
`HOSTED_MAX_GLOBAL_PHYSICAL_CALLS = 136`, global `$10`, Judge `$5`). Widen the code ceilings and their
tests in the same reviewed change only as far as the computed retry envelope requires—at minimum 68
Judge calls and 170 global calls. The append-only staged configuration remains the effective authority;
raising a code ceiling does not give non-Judge roles retry permission.

**Tests:** invalid output→success, invalid output→invalid output, no retry authority, exhausted call/
token/cost caps, settlement once per physical call, lineage sequences 1/2, and non-retryable security
failures.

## P2 — Case-local failure isolation

After the authorized structured-output retry is exhausted:

- close the Judge execution as failed with `invalid_structured_output`;
- persist a schema-valid `ERROR` verdict for that attempt;
- retain the existing `AttemptResult`;
- continue to the next authorized case; and
- keep low-signal/orchestration accounting honest.

Campaign-wide abort remains mandatory for:

- invalid or expired campaign authority/lease;
- explicit operator abort;
- target/surface/workload/config/policy drift;
- credential or synthetic-data failure;
- budget/rate/call/token/timeout cap breach;
- evidence/hash/lineage corruption;
- model/upstream substitution;
- unknown or unobserved target outcome;
- database/job lease failure; or
- an error that makes later dispatch safety unknowable.

**Tests:** one bad Judge response among many, Documentation skipped for `ERROR`, later cases continue,
terminal summary counts error cases, and governance failures still abort immediately.

## P3 — Durable checkpoint and resume

Make a terminal/interrupted batch resumable from PostgreSQL:

- derive completed ordinals from durable attempts, results, verdicts, work-unit reservations, and
  provider events;
- never repeat a target turn whose outcome is known and recorded;
- reuse stored target evidence when only Judge/Documentation recovery is required;
- finish or repair a started logical agent execution idempotently;
- treat an unknown target outcome as an abort requiring human review, not an automatic replay;
- maintain manifest order and exact caps across restart; and
- preserve one immutable authorization/workload identity.

Queue retries must be explicit, bounded, and state-aware. Do not change `retryable` to true without the
resume proof.

**Tests:** crash before send, after send/before result persistence, after result/before verdict,
after verdict/before summary, Runner restart, duplicate claim, stale lease, and exact cap accounting
across resume.

## P4 — Langfuse completeness and reconciliation

Keep PostgreSQL authoritative and add:

- one campaign root observation;
- logical agent observations with exact parentage;
- a child observation for every physical provider invocation/event, including retry sequence and
  status;
- target HTTP child observations;
- provider model/upstream/request ID, tokens, measured cost, duration, and terminal error code;
- no raw credential, raw PHI, or unbounded hostile content;
- bounded automatic flush/query-back reconciliation; and
- backlog/age/error metrics.

Extend the verifier to terminal `complete`, `failed`, and `aborted` campaigns:

- complete runs require the full canonical chain;
- failed/aborted runs verify the exact durable partial chain;
- only exact remote matches become `exported` with `langfuse_verified_at`;
- default remains read-only;
- an explicit write mode records verified rows only; and
- eventual consistency is bounded and observable.

**Gate:** the historical failed run shape is verifiable, and a new target-free failure fixture proves
partial-trace query-back without creating fake completion.

## P5 — Exact Judge calibration

Any retry/config/prompt/provider change alters the Judge identity. After finalizing P1–P4:

1. capture a balanced synthetic ground-truth set using the exact staged Judge model, Google Vertex
   upstream, prompt hash, policy hash, role configuration, and implementation version;
2. enforce minimum per-category sample counts and strict false-negative/false-positive/abstention/
   calibration-error thresholds;
3. preserve blinded labels and provider usage/cost provenance;
4. obtain genuine human review/approval; and
5. mount the approved absolute calibration artifact on Runner through
   `AGENTFORGE_JUDGE_CALIBRATION_PATH`.

Never copy or relabel a calibration from another upstream identity. Never set
`human_approved = true` or runtime enablement without a real human decision.

Until enabled, the console and run summaries must label non-oracle verdicts advisory/indeterminate.

## P6 — Remove ceremonial live-selection waste

The exact manifest already determines the next case before Red Team provider I/O so lineage can be
created. Evaluate and document one of these designs:

- one campaign-level Orchestrator plan plus deterministic manifest dispatch; or
- a meaningful bounded hosted Red Team task whose output cannot alter authorized target bytes.

Keep the large Red Team envelope available for legitimate hosted work. Do not shrink it to conceal
latency. Preserve reviewed generation provenance separately from live replay authority.

**Gate:** fewer unnecessary calls/tokens/seconds without weakening multi-agent separation or the PRD's
novel-generation capability.

## P7 — Release and acceptance

When explicitly authorized:

1. start from the latest agreed `main`; preserve other work in isolated worktrees;
2. require full tests, migration checks, packaging, console checks, secret scan, GitHub CI, and
   GitLab CI;
3. push the exact GitHub/GitLab-green commit to both remotes;
4. stop launches/scheduling and prove queue/execution quiescence;
5. deploy Runner inert against the old head, then Web migration, then activate Runner, then Scheduler;
6. verify all services share the same packaged policy/file hashes and healthy heartbeats;
7. run target-free four-role acceptance and exact Langfuse query-back;
8. capture/enable exact Judge calibration;
9. mint fresh target authorization after deployment;
10. run one 34-case staging batch and verify resume/error/query-back semantics;
11. run batches 2 and 3 only after batch 1 meets every gate; and
12. promote one identical release to production only after staging acceptance.

## Acceptance report

The final handoff must include:

- exact commit and both remote refs;
- GitHub and GitLab CI results;
- Alembic head;
- deployment IDs and identical policy/file hashes;
- hosted configuration and generation-policy digests;
- exact role models/upstreams/prompts/caps/retries;
- calibration identity and human approval evidence;
- per-batch cases, target turns, verdicts, errors, retries, tokens, cost, latency, and duration;
- Langfuse durable/remote counts by observation type;
- proof that observed target work was not repeated;
- remaining risks; and
- explicit confirmation that no unrequested production campaign or publication occurred.
