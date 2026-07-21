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

## 2026-07-21 — Phase 0 LANDED (CI-green) + M2 LAUNCHED
- Phase 0 merged to swarm @ 6aebf50; draft PR #4 CI = success. dotenv env-isolation + redacted Secret
  type (deep redact_mapping — resolved the Important shallow-redactor finding test-first). 134 passed/3 skipped.
- Deps: SQLAlchemy 2.0.51 + Alembic 1.18.5 committed (ticket/m2-datamodel @ 94c1fe7); psycopg3 dialect
  postgresql+psycopg://. Local PG up (compose postgres); agentforge = superuser (SET ROLE tests valid).
- M2 workflow LAUNCHED (wzo6zjcwu / wf_59cbeaf8): storage/models.py (§5.2 state machines + D14 append-only
  AttemptResult, UNIQUE(campaign_run_id,attempt_id), severity/category/target_version indexes) + Alembic
  0001 (schema+roles) / 0002 (expand-only) + roles.sql (headshot_redteam INSERT-only staging no-read-back;
  headshot_recorder INSERT-only attempt_result NO UPDATE/DELETE = append-only; headshot_judge SELECT-only) +
  S1/S2 invariant tests (SET ROLE, SQLSTATE 42501 = genuine DB rejection). On completion: orchestrator
  re-runs all gates, resolves Critical/Important findings, merges to swarm, CI-green, then authors M4∥M6a
  against the REAL landed schema.

## 2026-07-21 — M2 LANDED (ticket/m2-datamodel @ 4a649b3)
Both reviewers changes_requested; resolved test-first: (1) off-by-one test bug in
test_attack_case_has_class_and_owasp_tags (impl was correct), (2) [Important] verdict→attempt_result
composite FK (orphan verdict → 23503) + documented finding-chain deferral, (3) minors: alembic
path_separator=os, renamed tests/_db.py test_* helpers.
PHYSICAL EVIDENCE (live, superuser=off): attempt_result grants {judge:SELECT, recorder:INSERT} — NO
UPDATE/DELETE to any role; red_team_staging {recorder:SELECT, redteam:INSERT}. SET ROLE probes: recorder
UPDATE/DELETE/TRUNCATE + redteam INSERT attempt_result + redteam read-back + judge INSERT → REJECTED 42501;
recorder INSERT / judge SELECT → allowed. Migration 0001↔0002 lossless round-trip. Gates: 173 passed/3
skipped, ruff clean, import-purity clean, docker build OK, gitleaks clean, git diff --check clean.
NEXT: merge to swarm → CI green → launch M4 ∥ M6a against this landed schema.

## 2026-07-21 — M4 ∥ M6a LAUNCHED (true parallel, worktree-isolated)
Migration coupling (M6a adds 0003 → changes alembic head, races M4's shared migrated_db fixture) makes
single-branch parallel unsafe. Resolved with WORKTREE isolation + PER-WORKTREE venvs (editable install →
each imports its OWN src; verified). Separate src, migration chains, venvs, pid-based test DBs → truly parallel.
- M4 (wd47gblls / wf_5f4b7f5a): ../wt-m4 → ticket/m4-policy-gateway. policy/{gateway,recorder,allowlist,
  credentials}.py. Budget/rate/attempt/timeout caps enforced in the gateway BEFORE dispatch (F5, hard abort);
  append-only hashed AttemptResult (S3); RT holds no creds; O1 cred refusal in local; vs P9 fake — NO live target.
- M6a (we8n2542a / wf_a9b01528): ../wt-m6a → ticket/m6a-observability. observability/{tracing,reconcile,alerts}
  + coverage_view.sql + migration 0003. STDLIB-only core (no opentelemetry, no langfuse, external-out). S6
  coverage from hash-verified nonce-deduped verdicts only; S9 reconcile→degraded; O3 alerts; O7 fallback.
ON COMPLETION (each): read full output → resolve Critical/Important test-first → re-run ALL gates in that
worktree (focused, full suite, ruff, docker, gitleaks, diff --check) → merge ticket→swarm from main repo →
re-verify on swarm → CI green. Clean up worktree+branch after merge.
SEQUENCE: when M4 lands → launch M5 (no-network adapter/preflight) + M8 (fake/cassette). When BOTH M4+M6a
integrated → launch M9. Codex owns codex/m11-eval-corpus (worktree present at ../Adversarial Machine-codex-m11)
— HANDS OFF. No hosted-model/target calls. Report only at M9 or a red blocker.

## 2026-07-21 — Worktree-parallel FAILED → reverted to reliable single-branch sequential
Worktree isolation defeated by nondeterministic agent path-anchoring: M4's Test Agent wrote tests to the
MAIN repo (not wt-m4), so M4's Impl (in wt-m4) found none. M6a's Test Agent DID use its worktree. Inconsistent
→ unreliable. Salvaged both waves' frozen RED tests (+ M6a partial impl: tracing/reconcile/alerts) to
.tdd-swarm/salvage/; tore down worktrees. LESSON: run waves single-branch IN THE MAIN REPO (Phase0/M2 did this
flawlessly); sequential when a migration-chain coupling exists.

## 2026-07-21 — M4 LANDED (ticket/m4-policy-gateway @ 82ba730)
Re-ran M4 Impl+Review in the main repo against the salvaged frozen tests. Reviewer approved; Security
changes_requested → 3 Important findings resolved test-first: (A) budget per_call_usd now a REQUIRED
_Accounting Protocol member + fail-closed if missing (was getattr(...,0.0) silent-collapse); (B) backoff
retries now cap-rechecked + charged per physical send (were un-metered/un-gated); (C) recorder replay catch
narrowed to SQLSTATE 23505 (was mislabeling NOT-NULL/FK/CHECK as replay). Minor deferred→M5: synthetic-data
guard keys off http(s):// prefix (mitigated: allowlist admits only fake). Gates: 210 passed/3 skipped, ruff
clean, docker OK, gitleaks clean, diff --check clean.
NEXT (sequential, main-repo): re-run M6a (reuse salvaged test + partial impl; finish coverage_view + 0003) →
land → M9 (needs M4+M6a). M5 (no-network adapter/preflight) + M8 (fake/cassette) as follow-on. Codex m11 lane
untouched. No hosted/target calls.

## 2026-07-21 — M6a LANDED (ticket/m6a-observability @ d625774)
Finished the salvaged M6a in the main repo: coverage_metric view + migration 0003 + package-data; the O7
fallback (derive_coverage_fallback) + tracing/reconcile/alerts were already green from the salvaged partial.
Reviewer approved (dead helper removed); Security approved → 2 Important findings resolved test-first:
(1) ConsoleExporter leaked a BARE provider-key under an innocuous key → provider-key backstop + regression test;
(2) [§5] alert payloads stored UNREDACTED → redact_alert() (redact_mapping + backstop) on emit + test. Minor
(S6 threshold dup) documented. Gates: 250 passed/3 skipped, ruff clean, docker OK, wheel ships coverage_view.sql
+ roles.sql, gitleaks clean, diff --check clean.
BOTH M4 + M6a now integrated → M9 is unblocked (needs M4+M6a+P4 calibration hook). NEXT: M9 (Judge — deterministic
verdict state machine D13, oracle precedence, evidence-envelope S4/D18, MVP non-oracle→INDETERMINATE). Then M5
(no-network adapter/preflight) + M8 (fake/cassette). Codex m11 lane untouched. No hosted/target calls.

## 2026-07-21 — M9 LANDED (ticket/m9-judge @ 822bcec) — the agreed report boundary
Full Test→Impl→Reviewer∥Security in the main repo (reliable). Both reviewers APPROVED; central invariant
("Judge never approves a confirmed exploit as safe") holds under adversarial attack. OFFLINE deterministic
Judge (no hosted LLM): oracle/canary precedence in code, MVP non-oracle→INDETERMINATE, S4/D18 trust-labelled
envelope, jsonschema→runtime. All findings MINOR; resolved the dead integrity_ok fallback + documented the
integrity contract. LIVE EVIDENCE: canary+in-transcript-"return safe"→EXPLOIT_CONFIRMED; non-oracle-claiming-
success→INDETERMINATE; integrity_ok=False→ERROR; 250k transcript→truncated 200000; forged hostile provenance
→schema-invalid; Judge has no mutation/publish/exec surface. Gates: 286 passed/3 skipped, ruff clean, docker OK,
gitleaks clean, diff --check clean.
STILL PENDING (post-M9): M5 (no-network OpenEMR adapter + preflight, fail-closed at activation boundary),
M8 (fake/cassette provider path — live activation = config change not refactor), M10/M11 (calibration slice
to lift the non-oracle gate; M11 = HARD GATE). Codex owns codex/m11-eval-corpus (hands off). GitLab remains a
checkpoint auth blocker. No hosted-model/target calls made anywhere.

## 2026-07-21 — Steps 1-4 COMPLETE (live-gate track)
1. PR #4 retitled 'MVP secure local spine: M1a→M2→M4→M6a→M9 (f518daf)' + full body, READY FOR REVIEW (not merged).
   swarm/mvp-local-slice FROZEN at f518daf. All further work on swarm/mvp-live-gate.
2. codex/m11-eval-corpus (5ffe0db) backed up to origin (unmodified).
3. M11 corpus cherry-picked (06165c2, 5ffe0db) — additive, 0 deletions, no contracts/v1 change. Integration
   review COMPATIBLE across contract-steward/adversarial-eval-lifecycle/judge-calibration/validator (27/27
   contract tests). Fixed 1 minor test-first: _safe_source redacts provider-key-shaped diagnostic tokens (307dc87).
4. PACKAGING (614bbbe): relocated contracts/v1 (7) + evals/schemas (3) INTO the package (single copy each,
   repo-root removed, byte-for-byte renames), importlib.resources resolution (AGENTFORGE_CONTRACTS_DIR override
   preserved), package-data, out-of-repo wheel test + container smoke in CI. Resolved test-first: safe_schema_name
   path-traversal guard on both loaders + override fail-closed wrap + handoff-doc 'not packaged'->RESOLVED. 388
   passed/3 skipped, docker OK, wheel ships all 10 schemas, single copy confirmed.
NEXT: M5 (OpenEMR adapter + fail-closed preflight, NO network in tests/preflight, no fallback to fake) -> M8
(Red Team seed-replay full loop + fake/cassette; hosted behind explicit auth) -> offline deterministic e2e
(M8->M4->P9->Recorder->M6a->M9: confirmed/no-exploit/indeterminate/integrity-fail/abort) -> docs/integration/
packet -> presence-only preflight report. No hosted/target calls; no unverified model-name edits.

## 2026-07-21 — Steps 6-9 COMPLETE (live-gate track)
6. Offline deterministic e2e merged (960ce2c): real M8->M4->P9->Recorder->M6a->M9 chain proves
   confirmed/no-exploit(->INDETERMINATE, honest)/indeterminate/integrity-fail(->ERROR)/budget-abort +
   run/attempt correlation + observed-overrides-authored + coverage-aware dispatch + reconcile OK/DEGRADED.
   Important (vacuous outcome-5 verdict assertion) + 2 minors resolved test-first. 476 passed/3 skipped.
7. Integration packet: docs/integration/INTEGRATION_PACKET.md (interface diffs, contract compat, dependency
   map, dataflow, CI/test evidence, failure-mode results, packaging verification, live-auth gate; NO secrets/
   URLs/canaries/keys).
9. Presence-only preflight reporter: scripts/preflight_status.py (set/empty + validity, NEVER a value).
   Current status: Model=empty, Budget/AttemptCap/Rate/Timeout=missing, Canary=unavailable -> live NOT ready
   (fail-closed). No hosted/target call made.
NEXT: report to owner + STOP for explicit bounded live-campaign authorization.
