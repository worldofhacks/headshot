# Integration Packet — MVP Secure Local Spine + M11 Corpus + M5/M8 + Offline E2E

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

- `contracts/v1` (7) + `evals/schemas` (3) relocated **into the package** as **one authoritative copy each** (byte-for-byte renames; repo-root copies removed). Resolved via `importlib.resources` (zip-safe, CWD-independent); `AGENTFORGE_CONTRACTS_DIR` override preserved (tooling-only); schema-name traversal guard.
- **Proven out-of-repo:** wheel built + installed into a fresh venv **outside** the repo (only corpus *data* copied, no schemas) → `validate-corpus` exit 0. **Container smoke:** `docker run` validates the corpus inside the image. Both are CI steps.

## 8. Remaining live-authorization gate (not crossed)

**No hosted-model or live-target request has occurred.** A loaded key is not authorization. Before any live campaign, ALL must hold and a **bounded, explicit human authorization** must be granted:
- M5 adapter/OpenEMR preflight passes (HTTPS + exact-host allowlist + auth-mode + exact creds + no-conflict + synthetic + canary + typed errors), **no fake fallback**, URL-set ≠ authorized.
- M8 hosted provider/model preflight passes (supported provider + non-empty `HEADSHOT_RED_TEAM_MODEL` + credential reference); model unset ⇒ hosted path fails preflight while fake/cassette/seed remain usable.
- Gateway budget/rate/timeout/abort caps configured (M4 enforces before any dispatch).
- D1 deployed target URL + campaign authorization.

The presence-only preflight status (set/empty + validity, no values) is reported separately at the live-authorization checkpoint.
