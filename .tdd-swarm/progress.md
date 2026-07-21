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
