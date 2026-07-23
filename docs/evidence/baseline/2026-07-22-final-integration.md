# Final integration baseline - 2026-07-22

- Initial audit captured: `2026-07-22T23:06:25Z`
- Final working-tree verification: `2026-07-22T23:37:31Z`
- Base commit audited: `7749fd598dee1a16ad4fd4d04a6ec37855c0ac2c`
- Local branch: `codex/final-integration-audit`
- Data policy: synthetic/offline fixtures only; no target, Clerk, model-provider, or SMART credential value was read or recorded.

## Deterministic gates

| Gate | Fresh result |
|---|---|
| Ruff lint and format | pass; 185 files formatted |
| Eval validation | pass; 9 cases, 15 labels, 3 categories, 1 fixture; no duplicate sequences |
| Python suite with PostgreSQL 16 | pass; 955 tests; readiness tests exercised against the migrated `0008` database |
| Contract suite | pass independently |
| Wheel-outside-repo | pass; all 15 packaged schemas and corpus validation work without a checkout |
| Frontend dependency audit | pass; 0 vulnerabilities |
| Frontend typecheck/tests/build/bundle | pass; 71 tests; 207-file bundle policy pass |
| Browser smoke | pass; 4 tests |
| Production image | pass; `sha256:4af41a54884a8cf918334e5a781c3e2aa510946048d82b9dfe934d4c9dbaf634`; non-root, no Node/dev sources/maps, one Alembic head |
| Container migrations/readiness/routes | pass; clean and 0003-to-0008 upgrades plus 0008 downgrade/upgrade; configured ready; unconfigured ready fails closed |
| GitHub CI | success for commit `7749fd5`, run 29948042589 |
| GitLab CI | success for commit `7749fd5`, pipeline 16321 |
| Dual-remotes | `origin/main` and `gitlab/main` both resolve to `7749fd5` |

The Python run emitted one non-failing Starlette deprecation warning about the compatibility `httpx` TestClient import. The frontend build emitted a large Clerk vendor-chunk warning; the bundle security/honesty gate still passed. Two earlier full-suite invocations used an invalid direct-psycopg URL and then a nonexistent temporary database; both failed only the two connectivity tests. The retained green result uses canonical `postgresql://` against the migrated `agentforge_upgrade_0008` database. Local Promptfoo first failed closed under unsupported Node 22.13; the required Node 24 rerun validated and passed 1/1 offline case.

## Authoritative offline slice added on this branch

The durable Runner now obtains a contract-valid Orchestrator decision from hash-recomputed PostgreSQL evidence, passes the directive through a deterministic Red Team proposal boundary, rejects any proposal that differs from the exact authorization-bound corpus, dispatches only through the Policy Gateway, persists append-only evidence, and invokes the independent Judge. Confirmed findings produce contract-valid draft reports and fail-closed regression dispositions that remain pending deterministic reproduction and human approval. Migration `0008` persists both artifacts with uniqueness, foreign-key, draft-state, and admitted-state checks; database grants keep Red Team and Judge away from these tables.

No live target campaign was run. Passive deployment checks are not campaign authorization, and critical publication/remediation/regression promotion remain blocked.

## Public deployment probes

| Surface | Result |
|---|---|
| Staging `/health`, `/ready` | `200 alive`, `200 ready` |
| Production `/health`, `/ready` | `200 alive`, `200 ready` |
| Staging and production `/` and `/live` with `Accept: text/html` | 200 with the compiled SPA root |
| Staging protected `/api/v1/principal` and `/api/v1/coverage` without a bearer session | 401 fail-closed |
| Deployed target `/health` | `200 alive`; returned deployment SHA was recorded only in the temporary probe output |

These are passive readiness/auth-boundary checks, not authorization for `/chat`, active ZAP, adversarial campaigns, or load tests.

## Security-tool baseline

Raw local artifacts are outside the repository under `/tmp/agentforge-baseline-20260722-final-integration/`; CI retains equivalent artifacts. Hashes let a reviewer verify that local summaries were not substituted after the run.

| Tool | Version/scope | Result | SHA-256 |
|---|---|---|---|
| Semgrep | 1.170.0; final platform source including new files | 0 findings across 129 applicable targets | `8804a68dd6d8c2378c93b680d637bf82882c02b2b9cdf5f5c16312877cdedfd8` JSON |
| pip-audit | 2.10.1; project dependency graph | 0 known vulnerabilities | `e98e1fcf8a32d920caf3eb78852a0212df6d2f5ef98b1672c31a90bf8410b0f3` |
| npm audit | console lockfile | 0 vulnerabilities | `a979997e33539f5e0aa0ad2e31d04f4ab22a2daae57d998cff40f55f799cb65c` |
| gitleaks | 8.30.1; 98 commits | 0 leaks | `37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570` |
| Garak | 0.15.1 isolated bounded probe | adapter-valid artifact | `f803e2bacdb8794e7f27eea614d54d61ea5ac5e8064cb0580eacc61e7ecf4a7a` raw |
| PyRIT | 0.14.0 isolated converters | adapter-valid artifact | `b25986978d9f374e0406d90ad0292b371dbfade0ce8fad1f6cc27596a3153fc7` |
| Giskard Scan | 1.0.0b3 checksum-pinned wheel | adapter-valid artifact | `248388f798422294d43faea0ebd5142f259efb600a7971c63afc44aa1c8ad0eb` |
| Promptfoo | 0.121.19 under Node 24 | valid config; 1/1 deterministic pass; no remote generation | `a2d6ab5b2e7d82194c47cf4c14192ab3964adecc1b4337baa9724a35636f2c6d` |
| OWASP ZAP | pinned image digest; passive isolated fake target | 4 expected header warnings, 0 failures | `054742e10501df7ab963b0dd3f8dd16e3780ae7a817b0a14886dd0fb591c1032` |

The ZAP warnings describe the isolated Python fixture server, not Headshot or the Clinical Co-Pilot. No live origin was scanned.
