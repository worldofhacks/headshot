# Mechanical local gate mapping

`run-local-gates.sh` executes every `AVAILABLE` row below without a shell
interpolation layer, then always runs spec mapping and import-cycle checks. Coverage
is governed separately by `coverage-policy.md`. A command must use an explicit
`sh -c` argument itself if shell syntax is intentional.

| gate | exact command | current status |
|---|---|---|
| format | .venv/bin/ruff format --check . | AVAILABLE |
| lint | .venv/bin/ruff check . | AVAILABLE |
| unit | .venv/bin/pytest | AVAILABLE |
| secret-scan | bash scripts/secret_scan.sh | AVAILABLE |

Repository-only checks that need Docker, pinned CI scanners, browser dependencies,
provider authorization, or live-target authorization remain CI/release gates. They
are not represented as local successes and cannot be waived by this wrapper.
