# Local gate report — T-F00

ticket: tickets/T-F00.md
base: 6fcfa0c80c80a81bafc788b1878a8477b7d52fd6
head: 3e1c3700740345a477f4033fd757f82590faf7f9
coverage-policy-sha256: 07f7b5edd7758a482d6e16c5cb7caa73682eb31a6b3cede804e00a909140ec22
import-graph-sha256: 23c6f6c76ccda09ad2824df2dbc6b57dd4bf53d3f0c9673fcadab3fb346a148f
coverage-decision: non-applicable
coverage-reason: T-F00 bootstraps shell orchestration and a standalone import-graph utility before repository coverage tooling exists; its frozen behavior tests remain mandatory.
coverage-approver: T-F00 task owner
coverage-date: 2026-07-24
coverage-expiry: 2026-07-31

| gate | exact command | exit | output |
|---|---|---:|---|
| format | `.venv/bin/ruff format --check .` | 0 | 208 files already formatted |
| lint | `.venv/bin/ruff check .` | 0 | All checks passed! |
| unit | `.venv/bin/pytest` | 0 | ........................................................................ [  7%]<br>........................................................................ [ 14%]<br>........................................................................ [ 21%]<br>........................................................................ [ 28%]<br>........................................................................ [ 35%]<br>........................................................................ [ 42%]<br>........................................................................ [ 49%]<br>........................................................................ [ 56%]<br>........................................................................ [ 63%]<br>........................................................................ [ 70%]<br>........................................................................ [ 77%]<br>........................................................................ [ 84%]<br>...........................s.ss......................................... [ 91%]<br>........................................................................ [ 98%]<br>.............                                                            [100%]<br>=============================== warnings summary ===============================<br>../Adversarial Machine/.venv/lib/python3.12/site-packages/fastapi/testclient.py:1<br>  /Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine/.venv/lib/python3.12/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using &#96;httpx&#96; with &#96;starlette.testclient&#96; is deprecated; install &#96;httpx2&#96; instead.<br>    from starlette.testclient import TestClient as TestClient  # noqa<br><br>-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html<br>1018 passed, 3 skipped, 1 warning in 30.29s |
| secret-scan | `bash scripts/secret_scan.sh` | 0 | secret scan clean (555 files) |
| spec-lint | `bash .tdd-swarm/spec-lint.sh tickets/T-F00.md 6fcfa0c80c80a81bafc788b1878a8477b7d52fd6` | 0 | spec-lint: T-F00 maps 5 acceptance criteria across 3 test scopes |
| import-cycles | `python3 .tdd-swarm/check-import-cycles.py` | 0 | import graph acyclic; sha256=23c6f6c76ccda09ad2824df2dbc6b57dd4bf53d3f0c9673fcadab3fb346a148f |
