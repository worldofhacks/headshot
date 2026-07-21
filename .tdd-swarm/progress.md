# tdd-swarm progress ledger (swarm/mvp-local-slice)

Baseline (2026-07-21): 35 tests green (P8-P10); ruff clean; tree clean; main protected; CI green.
Gates: `ruff check .` · `ruff format --check .` · `pytest` · `pytest tests/contract -q` · `gitleaks git . --redact`.
Epic: M1a -> M2 -> M3 ∥ M6a -> M4 (vs P9 fake). Source of truth: IMPLEMENTATION_PLAN.md + references/headshot-mvp.md.

Ticket M1a: tests-frozen (RED verified; AC-2/AC-3/AC-5) — wave 1
Ticket M1a: impl-green (65 tests pass; ruff+contract+gitleaks green; frozen intact) — pending Reviewer+Security (Phase 4), then Wave-1 integration.
LESSON: Test Agent should write ruff-clean frozen tests (a stray I001 blank line forced a scoped per-file lint-ignore in ruff.toml rather than mutating a frozen test).
Ticket M1a: repair committed — ruff bypass removed, readiness fixed (real DB check + pluggable schema seam), test_readiness added; 69 pass/3 skip; physical container verified (/health 200, /ready 503 fail-closed, db_ok True/False, sanitized logs). Frozen hashes: config 08392c61 env_isolation 84feb7a6 health 7ad1ddc7. Pending Reviewer+Security.
Ticket M1a: Critical(C1 target_id validation) + Important(I1 compose ports, CI docker-build gate, Settings.from_env) resolved + orchestrator-reverified. test_config_security.py frozen sha256 abf872d6636aea09875a8dca91b354ede930d7aca66060fb832c02e924b11fd7. Minor findings -> ledger (image digest-pin, dep lockfile, .dockerignore .env.example, redundant CI contract step, frozen test_env_isolation dead-code) for pre-Final.
M1a: REVIEW-PASSED.

## Wave 1 COMPLETE (M1a integrated, draft PR open). Phase-2 execution-order refinement (approved):
M2 -> (M4 ∥ M6a after M2) -> M9 (after M4+M6a) -> M5 (on D1) -> M8 (on hosted-OSS cred+cap) -> M11 [HARD GATE].
- M4 must NOT wait for M3 (build M4 vs the P9 fake; live adapter M5 is plugin registration, not a gateway refactor).
- M6a is NOT deferrable (M9 depends on it; S9 hash-reconciliation is locked MVP security spine).
- M3 runs parallel ONLY if genuinely disjoint agent/worktree and does not delay M4/M6a; else PARK immediately after the M11 path. M3 stays FINAL-COMMITTED/graded — not deleted, not relabelled optional.
Critical path to M11: M2 -> {M4, M6a} -> M9 -> (M5 needs D1, M8 needs hosted-OSS cred) -> M11.

Config: Settings.from_env now loads .env.local/.env (python-dotenv, real-env-wins). Secrets via .env.local (gitignored, untracked, never in history; gitleaks clean). SECRETS NEVER inlined/logged/committed. NAMING: model var is HEADSHOT_RED_TEAM_MODEL; user calls it OPENROUTER_MODEL — reconcile before M8. BUDGET: M4 Policy Gateway MUST enforce HEADSHOT_RUN_BUDGET_USD + MAX_ATTEMPTS_PER_RUN + TARGET_REQUESTS_PER_SECOND + RUN_TIMEOUT_SECONDS (hard abort) before ANY live inference; NO live model/target calls occur until M4 passes + explicit go-ahead. Current wave M2 uses no models.

## 2026-07-21 — Corrected wave order (governs; supersedes manifest's M3∥M6a)
Owner directive: **M2 → (M4 ∥ M6a) → M9**, then **M8 offline/cassette** after M9 (live provider
activation = config change, not refactor). **M3 stays OFF the critical path** unless genuinely separate
capacity. M9 depends on M6a's authoritative evidence + correlation + hash-reconciliation path — do NOT skip M6a.
Full test→impl→reviewer→security on M2, M4, M6a, M9 (trust boundaries — no reduced review). Run continuously.

### Phase 0 (pre-M2, REQUIRED FIRST) — dotenv env-isolation + secret redaction
- .env.example: removed OPENROUTER_MODEL alias; HEADSHOT_RED_TEAM_MODEL is the single canonical model id.
- from_env: env-from-process-FIRST, validate-before-load, load .env files ONLY when environment==local;
  staging/production skip dotenv entirely; a dotenv file cannot elevate the environment (AGENTFORGE_ENVIRONMENT
  popped from file view); precedence process>.env.local>.env>defaults. NEW src/agentforge/secrets.py: redacted
  Secret type (repr/str/format/reveal), redact_mapping, looks_like_provider_key (prefix backstop; redaction
  tests are the primary control). Ran as Workflow phase0-dotenv-redaction (Test→Impl→Reviewer∥Security).
- MUST be committed + CI-green BEFORE M2 starts (owner gate).

### M2 stack (confirmed): SQLAlchemy 2.x + Alembic (D7 locks Alembic) on Postgres (psycopg present).
Local PG: compose `postgres` service (start `docker compose up -d postgres` before M2 tests; DB-role +
migration invariants must RUN, not skip). CI already provides ephemeral postgres:16.

### Live-call posture (unchanged, confirmed): NO hosted-model call, NO target call now. A loaded key is
NOT authorization. No paid inference until M4 green + M8 built + preflight passes + explicit owner authz.
No target traffic until M5 + D1 authorization. Offline fake/cassette mode stays usable without external values.
