# Final-submission gate mapping

[locked-decision] Until T-F00 lands, mechanical swarm local-gate/spec/coverage/import checks are BLOCKED. No code ticket may become `review-passed`.

| gate | exact command | current status |
|---|---|---|
| Swarm local wrapper | `.tdd-swarm/run-local-gates.sh <ticket-file> <diff-base>` | BLOCKED pending T-F00 |
| Spec mapping | `.tdd-swarm/spec-lint.sh <ticket-file> <diff-base>` | BLOCKED pending T-F00 |
| Coverage policy | enforced by wrapper from `.tdd-swarm/coverage-policy.md` | BLOCKED pending T-F00 owner decision |
| Import cycles | `.venv/bin/python .tdd-swarm/check-import-cycles.py` | BLOCKED pending T-F00 |
| Python lint/format | `.venv/bin/ruff check .` / `.venv/bin/ruff format --check .` | AVAILABLE |
| Backend tests | `.venv/bin/pytest` | AVAILABLE; baseline 1001 pass/3 skip |
| Contract tests | `.venv/bin/pytest tests/contract -q` | AVAILABLE |
| Corpus | `PYTHONPATH=src .venv/bin/python -m agentforge.evals validate-corpus evals && PYTHONPATH=src .venv/bin/python -m agentforge.evals detect-duplicate-sequence evals/seeds` | AVAILABLE |
| Secret scan | `bash scripts/secret_scan.sh` | AVAILABLE |
| Console | `cd console && npm ci --ignore-scripts && npm audit --audit-level=high && npm run typecheck && npm test && npm run check:forbidden && npm run build && npm run check:bundle` | AVAILABLE with declared public Clerk fixture; baseline 75 |
| Browser | `cd console && npm run test:browser` | AVAILABLE if installed; baseline 4 |
| Wheel/package | `bash scripts/wheel_outside_repo_check.sh` | AVAILABLE |
| Migrations | `.venv/bin/pytest tests/test_migrations.py tests/test_queue.py -q` | AVAILABLE |
| Container | exact `.github/workflows/ci.yml` commands plus `scripts/verify_runtime_image.sh`, `verify_container_migrations.sh`, `smoke_ready_container.sh`, `smoke_runtime_container.sh` | AVAILABLE with Docker/fixture env |
| Security tests | `.venv/bin/pytest tests/auth tests/security_tools tests/test_secrets_redaction.py tests/test_gateway.py tests/test_db_roles.py -q` | AVAILABLE |
| Semgrep/pip-audit/ZAP | exact pinned GitHub/GitLab CI jobs | SKIPPED locally: pinned local executables/environment unavailable; CI authoritative |
| Architecture drift | T-F12 reviewer compares `ARCHITECTURE.md`, ADRs, import report, contracts, diff | BLOCKED pending dependencies; no existing script |
| Benchmark/SLO | T-F07a harness and approved `.tdd-swarm/baselines.md` | BLOCKED pending T-F06a/T-F07a |
| Judge calibration | T-F03b verifier using T-F03a policy hash | BLOCKED: current baseline FAIL; authorization required |
| Provider eval | T-F04b verifier using authorization threshold hash | BLOCKED: authorization/provider required |
| Live campaign | T-F05b preflight + campaign command | BLOCKED: named authorization/lease/providers/calibration |
| Replay/stress | T-F06b / T-F07b named authorization manifests | BLOCKED |
| Artifact integrity | `sha256sum -c <artifact-dir>/manifest.sha256` | AVAILABLE once each manifest exists |
| Dual remote | `git ls-remote origin refs/heads/main` and `git ls-remote gitlab refs/heads/main` | READ-ONLY; final release pending |

[locked-decision] SKIPPED/BLOCKED is not green; deferral/threshold changes require owner approval.
