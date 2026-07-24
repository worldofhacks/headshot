# Mechanical local gate mapping

`run-local-gates.sh` executes every `AVAILABLE` row below without a shell
interpolation layer, then always runs spec mapping and import-cycle checks. Coverage
is governed separately by `coverage-policy.md`. A command must use an explicit
`sh -c` argument itself if shell syntax is intentional.

| gate | exact command | current status |
|---|---|---|
| format | .venv/bin/ruff format --check . | AVAILABLE |
| lint | .venv/bin/ruff check . | AVAILABLE |
| typecheck | reason=.venv/bin/mypy is not installed in the approved local toolchain | BLOCKED |
| unit | .venv/bin/pytest | AVAILABLE |
| new-tests | reason=the wrapper runs the base-aware spec-lint intrinsically with trusted ticket and base arguments | BLOCKED |
| coverage | reason=coverage is governed by coverage-policy.md and currently lacks an external signed owner approval or executable baseline | BLOCKED |
| no-todos | reason=no protected repository command has been approved for this diff-scoped check | BLOCKED |
| no-debug-logging | reason=no protected repository command has been approved for this diff-scoped check | BLOCKED |
| docs | reason=the documentation applicability check still requires reviewer judgment | BLOCKED |
| reachability | reason=the reachability check still requires reviewer judgment | BLOCKED |
| spec-lint | reason=the wrapper runs the base-aware spec-lint intrinsically with trusted ticket and base arguments | BLOCKED |
| secret-scan | bash scripts/secret_scan.sh | AVAILABLE |

Repository-only checks that need Docker, pinned CI scanners, browser dependencies,
provider authorization, or live-target authorization remain CI/release gates. They
are not represented as local successes and cannot be waived by this wrapper.
