# T-F17a Implementation Report

Status: `DONE_WITH_CONCERNS`

## Provenance

- Branch: `ticket/T-F17a-hosted-role-prompt-contract`
- Frozen base: `f22609140b7f9e1fe7d53761668bd778b8dfbda6`
- Frozen `tests/test_agent_prompts.py`:
  - SHA-256: `8e5b003c2160fdee2333e56da6c0e4e505708296f0325de76eb27262a15014bc`
  - Git blob: `ea8940325146877f22038a8e275b025bcf798cbb`
- Frozen `tests/test_packaging.py`:
  - SHA-256: `53ad0d07fe7f19d2f7c2cc37edd1f1a56dfeaac2709b7d1c04f2204a6473d5fe`
  - Git blob: `33a22029da045d05888993545e3b94a87cc04ae1`
- The frozen tests were not edited.

## Implementation

- Added an immutable four-record prompt registry with exact role/version/SHA-256 lookup and no
  role-only fallback.
- Added a closed, duplicate-key-safe manifest validator with bounded raw-byte reads, exact
  role/resource ordering, UTF-8/trailing-newline checks, and generic non-leaking failures.
- Added broad secret-shape rejection for provider, AWS, Slack, Clerk, bearer, sensitive-assignment,
  and PEM credential families.
- Added the four package-owned v1 role prompts and their content-addressed manifest.
- Declared all prompt authority resources as setuptools package data.
- Added the hosted prompt registry migration/rollback contract.
- Runtime loading uses only `importlib.resources.files()` traversables. This ticket performs no
  provider composition, provider/target call, deployment, or live action.

## TDD evidence

Initial focused RED at the frozen base:

```text
8 failed
```

First GREEN implementation attempt:

```text
8 passed in 1.21s
```

Final focused offline gate after the review fix:

```text
8 passed in 0.73s
```

The final focused command covers all of `tests/test_agent_prompts.py` plus AC-4's deterministic
offline installed-wheel/direct-archive probe with `PIP_NO_INDEX=1` and `PYTHONPATH` unset.

Additional regression evidence:

```text
Preserved hosted/packaging baseline: 14 passed, 2 deselected
Initial complete repository suite: 1133 passed, 3 skipped, 1 warning
Final network-disabled repository suite excluding only the pre-existing network-dependent
setuptools wheel test: 1132 passed, 3 skipped, 1 deselected, 1 warning
```

The one warning is the existing Starlette `httpx` deprecation warning. Six additional local
adversarial probes confirmed generic rejection of AWS, Slack, Clerk, bearer, generic API-key
assignment, and PEM secret shapes.

## Quality and integrity gates

- Ruff check: pass.
- Ruff format check: pass.
- `git diff --check`: pass.
- Ticket source has no TODO/FIXME/debug-print/debug-log additions.
- Frozen test SHA-256 and Git blob identities: exact.
- Frozen test diff: empty.
- `scripts/secret_scan.sh`: `secret scan clean (853 files)`.
- `gitleaks git . --redact`: no leaks found.
- Generated `__pycache__` directories removed before commit.
- Independent read-only review found one Important secret-family coverage gap; the detector was
  expanded as described above, and the frozen/offline/static/secret gates were rerun green.

## Concern

The ticket's required wrapper and spec-lint scripts are absent from the frozen base:

```text
bash .tdd-swarm/run-local-gates.sh tickets/T-F17a.md f22609140b7f9e1fe7d53761668bd778b8dfbda6
bash: .tdd-swarm/run-local-gates.sh: No such file or directory

bash .tdd-swarm/spec-lint.sh
bash: .tdd-swarm/spec-lint.sh: No such file or directory
```

Both commands therefore exit 127. Their constituent available gates were run directly and pass.
No out-of-scope bootstrap file was added.
