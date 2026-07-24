# Integration Packet

## Current integration addendum - 2026-07-24

Source implementation baseline inspected through:
`ed41c6e20b7793c656c45aa6d05f8b9a0c476d1b`, including hosted Red-Team safe composition at
`bdadc88`.

This is a **source/integration** addendum, not a final release attestation. GitHub and GitLab `main`
and the observed Railway release remain at `23490ea9846bffcf36168b58f2c36edeceabb8df` with database
revision `0013`. The candidate has not been deployed or live-accepted. The final immutable release
commit, identical remote `main` SHAs, authoritative green GitHub Actions run, Railway deployment
identities, authorized campaign, and Langfuse query-back therefore remain pending. GitLab is an
exact source mirror; GitHub Actions is the release CI authority. Historical sections below are dated
evidence and are not silently upgraded to current-release proof.

### Current interface inventory

- The package-owned v1 registry and the published repository-root
  [`contracts/v1`](../../contracts/README.md) contain the same 18 JSON Schemas. Publication and
  byte-equality tests cover `AttackAttempt`, `AttemptResult`, `CampaignDirective`, typed errors,
  `EvidenceEnvelope`, `JudgeCalibration`, `OrchestrationSnapshot`, regression
  admission/disposition/plan/result, security-tool schemas, `Verdict`, and `VulnReport`.
- The mediated trust boundary is
  `Orchestrator -> Red Team -> Policy Gateway/Recorder -> Judge -> Documentation`. Red Team never
  creates authoritative evidence; Judge does not share attack-generation authority; Documentation
  cannot publish.
- Hosted configuration, delivery state, logical execution lineage, and physical provider-call
  lineage in revisions `0015`-`0018` extend persistence and runtime acceptance without introducing
  an unversioned alternate inter-agent schema.
- The hosted role configuration hashes bind model, exact `provider.only` route, prompt identity,
  credential reference, caps, and the authorized completion-token parameter:

  | Role | Model | Exact route | Accepted returned provider | Token parameter |
  |---|---|---|---|---|
  | Orchestrator | `anthropic/claude-opus-4.8` | `amazon-bedrock/eu-west-1` | `Amazon Bedrock` | `max_tokens` |
  | Red Team | `qwen/qwen3.5-397b-a17b` | `atlas-cloud/fp8` | `AtlasCloud` | `max_tokens` |
  | Judge | `google/gemini-2.5-pro` | `google-vertex/global` | `Google` or `Google Vertex` | `max_tokens` |
  | Documentation | `openai/gpt-5.4` | `azure/eu` | `Azure` | `max_completion_tokens` |

- Every physical hosted attempt receives a committed `provider_call_invocations` reservation and at
  most one terminal `provider_call_events` row. The Langfuse projection emits one
  `provider.openrouter.attempt` generation for each physical attempt; the logical agent observation
  is metadata-only so tokens and cost are not double counted.
- The query-back verifier reconciles campaign/run/attempt identity, logical parent, physical order,
  model/provider/request identity, status, tokens, duration, retry/error state, and measured cost
  between PostgreSQL and Langfuse before atomically marking the persisted rows exported.
- The protected event stream remains cursor-based and bounded to 100 events per poll, requires
  `org:console:read`, validates same-origin browser provenance, and forces re-authentication after at
  most 30 seconds. Other collection reads still use fixed server windows; general stable cursor
  pagination and total counts remain a documented gap.

### Hosted four-agent composition and authority

For each selected frozen seed, the hosted path now records this provider parentage:

```text
campaign trace
  -> Orchestrator provider request
      -> Red Team provider request
          -> target attempt using only the byte-exact frozen seed
          -> Judge provider request over Recorder-owned evidence
              -> Documentation provider request only for a confirmed effective verdict
```

The hosted Red Team generates exactly one traced candidate variant per selected frozen seed. That
text is unreviewed and therefore **quarantined, hashed, and discarded without target authority**.
Only the byte-exact, corpus-hash-bound frozen seed can reach `seed_to_attempt` and the Policy
Gateway. A provider, trace, budget, identity, or terminal-record failure aborts before target
dispatch; no deterministic/demo fallback replaces the hosted call.

The security owner's model-Judge calibration passed its documented thresholds for the identities it
recorded, but it is not human-enabled and its recorded provider identities do not exactly match this
candidate's exact routes. The model Judge therefore remains advisory/fail-closed. Deterministic
oracle/canary precedence is decisive, and a calibration failure does not block a bounded campaign.
The vulnerability conclusions remain owned by the security workstream; this packet links the
[`vulnerability index`](../vulnerabilities/README.md) and reports
[`004`](../vulnerabilities/AF-VULN-2026-0724-004-session-token-in-url-and-sole-bearer-credential.md),
[`005`](../vulnerabilities/AF-VULN-2026-0724-005-missing-http-security-headers.md), and
[`006`](../vulnerabilities/AF-VULN-2026-0724-006-readiness-and-health-information-disclosure.md)
without changing their findings or dispositions.

### External/API behavior

- Every `/api/v1` route is authenticated and permission-gated. Missing/invalid authentication is
  401; wrong Organization, missing permission, or same-person approval is 403; an unavailable
  verifier or control-plane dependency fails closed.
- Mutating control-plane requests require a validated `Idempotency-Key` of 16-128 safe characters.
  Accepted work returns 202, completed work 200, immutable conflict 409, and unavailable work 503.
- The server exposes target maximum caps as ceilings and derives a separate exact workload envelope
  from the immutable corpus. The browser may authorize only that exact logical/physical workload,
  with zero target retries, and only when it fits every target ceiling.
- Authorization additionally requires the exact target/surface/corpus identities, exact host in its
  server-owned allowlist, synthetic-only assertion and attestation, hosted configuration, positive
  bounded budget/rate/timeout, exact attempt abort limit, and fresh nonce. Browser authorization
  expiry is strictly greater than the chosen timeout plus a 300-second execution margin and never
  exceeds 3,600 seconds; an impossible window disables authorization.
- Target and provider rates are exact run/configuration inputs, not invented constants. The physical
  path enforces budget, call, rate, retry, concurrency, timeout, logical-case, and physical-request
  limits. Typed rate/transport failures use bounded retry/backoff, then queue/abort.
- Langfuse credentials are Runner-only. Remote delivery is accepted only after authenticated,
  ID-for-ID query-back; the observability system does not authorize traffic or replace PostgreSQL
  evidence.

### Migration and compatibility state

`python -m alembic heads` reports exactly one serialized source head at `0018`:

```text
0001 -> ... -> 0013 -> 0014 -> 0015 -> 0016 -> 0017 -> 0018
```

| Revision | Integration change | Compatibility/rollback note |
|---|---|---|
| `0008` | Historical demo self-approval exception, retired by `0012` | [`migration-notes/0008-godmode-self-approval.md`](migration-notes/0008-godmode-self-approval.md) |
| `0009` | Draft reports and regression dispositions | [`migration-notes/0009-documentation-regression.md`](migration-notes/0009-documentation-regression.md) |
| `0010` | Regression replay plans/results/case versions | [`migration-notes/0010-regression-replay.md`](migration-notes/0010-regression-replay.md) |
| `0011` | Four-role execution ledger and security-tool lineage | [`migration-notes/0011-agent-runtime-observability.md`](migration-notes/0011-agent-runtime-observability.md) |
| `0012` | Two-role, unconditional different-person authorization | [`migration-notes/0012-two-role-clerk-authorization.md`](migration-notes/0012-two-role-clerk-authorization.md) |
| `0013` | Private scheduler replay planning | [`migration-notes/0013-scheduler-regression-planning.md`](migration-notes/0013-scheduler-regression-planning.md) |
| `0014` | Physical work-unit reservations | [`migration-notes/0014-campaign-work-unit-reservations.md`](migration-notes/0014-campaign-work-unit-reservations.md) |
| `0015` | Atomic append-only hosted configuration sets | [`migration-notes/0015-hosted-configuration-sets.md`](migration-notes/0015-hosted-configuration-sets.md) |
| `0016` | Multi-observation campaign traces and query-verified Langfuse delivery | [`migration-notes/0016-agent-langfuse-delivery.md`](migration-notes/0016-agent-langfuse-delivery.md) |
| `0017` | Hosted provider/accounting/Judge authority lineage | [`migration-notes/0017-hosted-agent-execution-lineage.md`](migration-notes/0017-hosted-agent-execution-lineage.md) |
| `0018` | Append-only physical provider attempt/event lineage | [`migrations/provider-call-lineage-v1.md`](migrations/provider-call-lineage-v1.md) |

The observed staging and production databases remain at `0013`. Source revisions `0014`-`0018` are
therefore **not deployed evidence**. Production also lacks a confirmed database rollback binding, so
this packet does not authorize production promotion.

### Current dependency map

```text
authenticated Web command
  -> organization-scoped PostgreSQL request/decision/job/audit
  -> exact target ceilings + server-derived immutable workload + browser expiry
  -> private Runner lease + physical work-unit reservation
  -> Orchestrator verified snapshot + physical provider attempt
  -> quarantined Red Team generation + exact frozen-seed selection + physical provider attempt
  -> Policy Gateway exact target/allowlist/synthetic/caps/abort
  -> target adapter + Recorder-owned hashed evidence
  -> independent Judge + physical provider attempt + deterministic-oracle precedence
  -> conditional draft-only Documentation + physical provider attempt
  -> PostgreSQL read models
  -> safe-metadata Langfuse projection + explicit remote query-back

private Scheduler
  -> target-version observation
  -> idempotent blocked replay plan
  -> no target/provider credential and no inline execution
```

PostgreSQL is authoritative. Langfuse observes redacted identity, order, latency, supplied usage,
cost, retries, and errors; missing and provider-estimated values remain distinguishable.

### Current source-test evidence

The candidate includes source tests for:

- byte-identical package/root contract publication and both-sided conformance;
- one serialized Alembic head at `0018` and the `0017 -> 0018` physical-lineage migration;
- exact provider routes and role-specific token parameters;
- one physical trace per provider attempt, retry/error accounting, and Langfuse query-back;
- hosted `Orchestrator -> Red Team -> Judge -> Documentation` parent/provider-request lineage;
- quarantining hosted Red-Team output while dispatching only the authorized frozen seed; and
- target ceilings versus exact workload caps, target-policy/synthetic bindings, and bounded browser
  authorization expiry.

These are source-level tests, not the complete final release suite or authoritative GitHub CI.

### End-to-end evidence status

[`../evidence/agent-trace.md`](../evidence/agent-trace.md) and existing `evals/results/` artifacts do
not establish a current `0018`, four-agent, Langfuse-reconciled release. No frozen 100-case corpus or
representative 100-case result has been integrated, and no candidate campaign has been deployed or
query-reconciled. Final cost inputs, demo URL, social-post URL, production deploy grant, and confirmed
database rollback binding are also unavailable.

The required proof remains one newly authorized campaign on the exact staging release and the
security owner's frozen corpus, with ordered durable executions, target request lineage,
finding/report behavior, exact provider identities, and Langfuse query-back. Until then, end-to-end
final-release status is **pending**.

## Final integration supplement — 2026-07-22

Current branch: `codex/final-integration-audit`; base commit: `7749fd598dee`. This supplement is
working-tree evidence and does not claim a commit, dual-CI result, deployment, or live campaign.

Additive interfaces in this integration:

- `orchestration_snapshot@1`: trusted Store → Orchestrator, built only from PostgreSQL rows whose
  `AttemptResult` hash recomputes. Raw spans/transcripts are not accepted.
- `campaign_directive@1`: Orchestrator → Red Team. The Orchestrator chooses coverage/finding/
  regression priority and copies, but cannot expand, the authorization-bound caps.
- `attack_attempt@1`: the deterministic Red Team handoff now participates in the durable Runner.
  The coordinator rejects any proposal differing from the exact corpus-hashed seed before dispatch.
- `vuln_report@1`: confirmed-verdict-only Documentation drafts with content-addressed evidence and
  no publication capability.
- `regression_disposition@1`: Documentation/Regression gate → Store. Admission is unrepresentable
  without deterministic reproduction, right-reason validation, and human approval.

Current authoritative dependency path:

```text
PostgreSQL verified signals -> Orchestrator -> CampaignDirective -> Red Team -> AttackAttempt
-> Policy Gateway -> target adapter -> Execution Recorder -> PostgreSQL reread/hash verify
-> independent Judge -> Documentation draft -> blocked regression disposition -> read models
```

On that historical branch, the additive report/disposition change was proposed as migration `0008`.
After serialization, it landed as current revision `0009`; canonical `0008` is the now-retired demo
self-approval migration. Runner has `SELECT/INSERT`, Web has `SELECT`, and Red Team/Judge have no
report/disposition table privilege. Current compatibility notes are
[`migration-notes/0008-godmode-self-approval.md`](migration-notes/0008-godmode-self-approval.md) and
[`migration-notes/0009-documentation-regression.md`](migration-notes/0009-documentation-regression.md).

Fresh local evidence: 955 Python tests, 71 frontend tests, 4 browser tests, 15 packaged inter-agent
contracts, clean `0003 -> 0008` and `0008 -> 0007 -> 0008` container migration paths, configured and
fail-closed runtime smokes, zero Semgrep/pip-audit/npm-audit/gitleaks findings, and production image
`sha256:4af41a54884a8cf918334e5a781c3e2aa510946048d82b9dfe934d4c9dbaf634`.

The external gate remains unchanged: no live target request, hosted generation, critical publication,
remediation, or regression promotion occurs until a distinct human approves the exact bounded scope.

---

Branch: `swarm/mvp-live-gate` (integration head). Reviewed spine PR: **#4** (`swarm/mvp-local-slice` @ `f518daf`, ready for review). This packet contains **no** secret values, target URLs, credentials, canaries, or provider keys.

## 1. Delivered components & integration sequence

| # | Component | Merge SHA | Trust role |
|---|---|---|---|
| P0 | dotenv env-isolation + redacted `Secret` | `6aebf50` | config core |
| M2 | exploit-DB model + migrations + per-agent DB roles | `3a64fb9` | storage boundary (S1/S2/S3) |
| M4 | Policy Gateway + Execution Recorder | `16c4267` | **trusted enforcement** (F5, D14) |
| M6a | observability core (tracing/reconcile/coverage/alerts) | `27ffdf9` | governed data substrate (S6/S9/O3/O6/O7) |
| M9 | independent Judge (deterministic, fail-closed) | `f518daf` | **independent evaluator** (D13/S4/D18) |
| — | M11 offline corpus (cherry-pick `06165c2`,`5ffe0db`) | integrated | authoring artifacts |
| — | packaging (schemas → wheel, `importlib.resources`) | `614bbbe` | deployability |
| M5 | OpenEMR adapter + fail-closed preflight | `e9a3bb5` | external adapter (behind gateway) |
| M8 | independent Red Team (seed-replay + mutation) | `f902053` | **untrusted generator** (F2) |
| — | offline deterministic end-to-end proof | `960ce2c` | integration evidence |

Dependency order honored: `M1a→M2→M4→M6a→M9` (local slice), then corpus, packaging, `M5`, `M8`, e2e.

## 2. Interface diffs & contract compatibility

- **No inter-agent contract (`contracts/v1/*.json`) changed** across the corpus/M5/M8 integration — the cherry-picks touched zero contract files; M5/M8 consume the existing `attack_attempt` / `attempt_result` / `evidence_envelope` / `verdict` schemas. `tests/contract` = **27/27 green**.
- **Authoring vs inter-agent separation (contract-steward review: compatible).** The corpus authoring schemas (`agentforge.evals.schemas`: `attack-case`, `ground-truth-slice`, `synthetic-fixture`) are **distinct `$id` namespaces** from `agentforge.contracts.v1`. The ground-truth slice validates its embedded `evidence_envelope` / `verdict` objects against the **authoritative** `contracts/v1` registry (`validator_for`) — referenced, never cloned; **no dual authoritative copy** exists.
- **New interfaces added** (not inter-agent contracts): `TargetAdapter` impl `OpenEmrAdapter`; `run_preflight`/typed `TargetPreflightError` taxonomy; `RedTeam.run` / `RedTeamProvider` / seed-replay `seed_to_attempt`; the `coverage_metric` SoR view.
- **OWASP anchor (D15):** corpus tags use `{framework,version,id,name}` with **Web=2021 / LLM=2025** exclusively — matches ARCHITECTURE.md §4 + THREAT_MODEL.md.

## 3. Dependency map (import direction)

```
config, secrets, contracts, domain        ← framework-neutral core (no web/ORM/HTTP framework)
        ↑
storage(models, roles, migrations) ─ SQLAlchemy/Alembic (storage-only)
        ↑
policy(gateway, recorder, allowlist, credentials) ─ uses config, secrets, target(base), storage
target(base, fake_adapter, openemr_adapter[httpx lazy], preflight)
observability(tracing, reconcile, coverage_view, alerts) ─ uses storage, secrets
agents/judge(judge, envelope, oracles) ─ uses contracts(registry), secrets
agents/red_team(red_team, seed_replay, selection, mutation, providers) ─ uses policy(gateway), contracts, evals
evals(validation, cli, schemas) ─ uses contracts(registry), secrets
```
Import-purity test enforced: `import agentforge.config` / `secrets` pulls **no** SQLAlchemy, FastAPI, httpx, or provider SDK. The Red Team and adapter pull no HTTP client / provider SDK at import (lazy).

## 4. Offline campaign dataflow — `M8 → M4 → M5/P9 → Recorder → M6a → M9`

```
seed corpus (evals/seeds, NOT_EXECUTED authoring records)
  │  M8 seed_replay.seed_to_attempt  → schema-valid AttackAttempt (multi-turn, no creds/evidence)
  │  M8 selection (coverage-aware: least-covered category first)
  ▼
M4 PolicyGateway.execute  ── allowlist → synthetic-data → budget/rate/attempt/timeout caps (HARD ABORT
  │                            before dispatch) → scoped credential (Secret) → dispatch
  ▼
target: P9 FakeTargetAdapter (offline)   [live path = M5 OpenEmrAdapter, behind preflight + explicit auth]
  ▼
M4 ExecutionRecorder  → append-only AttemptResult (content_hash, run/attempt nonce) → Postgres
  ▼
oracle (code, CanaryOracle over the RECORDED transcript) → trusted signals
M6a reconcile(content_hash, span_hash) → OK | DEGRADED (S9)
  ▼
M9 EvidenceEnvelopeBuilder (trust-labelled, size-bounded) → Judge.evaluate → Verdict (registry-validated)
  ▼
Verdict persisted with the SAME (campaign_run_id, attempt_id) — verdict→attempt_result FK; no orphan.
```

## 5. CI / test evidence

- **Full suite: 476 passed, 3 skipped** (the 3 skips are readiness probes needing a CI `DATABASE_URL`). ruff check + `ruff format --check` clean; `git diff --check` clean; gitleaks (working-tree + full history) clean; no secret ever entered git; `.env.local` gitignored/untracked throughout.
- **CI jobs** (`.github/workflows/ci.yml`): `test` (editable install, ruff, pytest, contract tests, **eval schema + duplicate validation**, **wheel-outside-repo corpus validation**, **container validation smoke**, `docker build`, ephemeral `postgres:16`) + `secret-scan` (gitleaks). Required checks: `test`, `secret-scan`.

## 6. Failure-mode results (all fail-closed, proven)

| Property | Result | Evidence |
|---|---|---|
| Red-Team write / read-back / any UPDATE·DELETE·TRUNCATE on evidence | **DB-rejected 42501** | M2 DB-role suite |
| Replay `(campaign_run_id, attempt_id)` | **rejected 23505** (recorder narrows to 23505 only) | M2/M4 |
| Off-allowlist / budget breach | **hard abort, 0 dispatch** | M4 |
| Hash divergence / missing | **`degraded`** (fail-closed) | M6a reconcile |
| Oracle hit + in-transcript "return safe" | **`EXPLOIT_CONFIRMED`** (not downgraded) | M9 / e2e-1 |
| Observed no-exploit (negative oracle) | **`INDETERMINATE`** (MVP gates `NO_EXPLOIT_OBSERVED`) | e2e-2 (honest) |
| Integrity failure | **`ERROR`** (overrides a confirming oracle) | e2e-4 |
| Budget cap | **abort; no AttemptResult, no verdict** (count delta) | e2e-5 |
| Forged `hostile` provenance in a trusted signal | **schema-invalid** | M9 / S4 |
| Adapter selected + misconfigured | **typed error, no fake fallback** | M5 preflight |
| Hosted provider, model unset | **hosted preflight typed-fails; fake/cassette/seed remain** | M8 |

## 7. Packaging verification

- Runtime contract schemas and eval-authoring schemas are resolved from their **single package-owned
  authorities** through `importlib.resources` (zip-safe, CWD-independent);
  `AGENTFORGE_CONTRACTS_DIR` remains a tooling-only override and schema names are traversal-guarded.
  The PRD-facing `contracts/v1/` directory is a generated, byte-identical publication of the
  package-owned contract source, with registry/set/byte equality enforced in `tests/contract`.
- **Proven out-of-repo:** wheel built + installed into a fresh venv **outside** the repo (only corpus *data* copied, no schemas) → `validate-corpus` exit 0. **Container smoke:** `docker run` validates the corpus inside the image. Both are CI steps.

## 8. Remaining live-authorization gate (not crossed)

**No hosted-model or live-target request has occurred.** A loaded key is not authorization. Before any live campaign, ALL must hold and a **bounded, explicit human authorization** must be granted:
- M5 adapter/OpenEMR preflight passes (HTTPS + exact-host allowlist + auth-mode + exact creds + no-conflict + synthetic + canary + typed errors), **no fake fallback**, URL-set ≠ authorized.
- M8 hosted provider/model preflight passes (supported provider + non-empty `HEADSHOT_RED_TEAM_MODEL` + credential reference); model unset ⇒ hosted path fails preflight while fake/cassette/seed remain usable.
- Gateway budget/rate/timeout/abort caps configured (M4 enforces before any dispatch).
- D1 deployed target URL + campaign authorization.

The presence-only preflight status (set/empty + validity, no values) is reported separately at the live-authorization checkpoint.
