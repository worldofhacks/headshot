# T-F17a Test Agent Report

Status: `DONE`

## Scope

- Base: `0803849aab0e99387ee80566b359384cb216f2b1`
- Branch: `ticket/T-F17a-hosted-role-prompt-contract`
- Test ownership: `tests/test_agent_prompts.py`, `tests/test_packaging.py`
- No production, provider, target, deployment, or main-branch change was made.
- Provider system-message transport remains T-F17c scope; authenticated prompt API/UI exposure
  remains T-F17f scope.

## RED contracts

- AC-1: exact immutable four-role records, UTF-8 content, explicit version, SHA-256 over exact
  bytes including the trailing newline, safe record repr, exact identity lookup with no role,
  version, or hash fallback, and the four locked role/model assignments.
- AC-2: deterministic bundle validation rejects missing, duplicate, altered, role-mismatched,
  non-UTF-8, oversized, secret-shaped, unmanifested, and traversal-shaped resources; validation
  is network-denied and error text may not disclose prompt fragments.
- AC-3: every full prompt must encode its role-specific trust boundary, including fresh authorized
  Orchestrator select/halt, exact-parent bounded Red Team mutation, independent fail-closed Judge
  precedence, and draft-only Documentation behavior.
- AC-4: an actual wheel must contain the manifest and four prompt resources, preserve build-input
  bytes exactly, and load those bytes from an isolated installed wheel despite decoy filesystem
  override variables.

## Evidence

Baseline before authoring:

- `python -m pytest tests/test_packaging.py tests/test_hosted_configuration.py -q` → exit 0
  (focused baseline green).

Intentional RED:

- `python -m pytest tests/test_agent_prompts.py -q` → exit 1, `6 failed, 1 passed`; every failure
  is the explicit assertion `T-F17a prompt registry package is missing`, with no collection/setup
  error.
- Offline wheel execution of
  `tests/test_packaging.py::test_wheel_installed_outside_repo_validates_corpus` → exit 1 at
  `the prompt registry manifest is not packaged in the wheel`; build dependencies came only from
  a local wheelhouse (`PIP_NO_INDEX=1`).

Preservation and gates:

- Existing suite excluding only the seven new prompt tests and the intentionally RED augmented
  wheel case → exit 0 through 100%, with three expected skips.
- Test-scope collection → `tests/test_agent_prompts.py: 7`,
  `tests/test_packaging.py: 5`.
- T-F00 spec-lint from `ticket/T-F00-swarm-gates` → `T-F17a maps 4 acceptance criteria across
  2 pytest-collected scopes`.
- `ruff format` / `ruff check` on both owned test files → pass.
- `git diff --check` → pass.
- `bash scripts/secret_scan.sh` → `secret scan clean (843 files)`.
- The pinned base does not contain `.tdd-swarm/run-local-gates.sh`; therefore that wrapper cannot
  run until dependency T-F00 is integrated. No gate was silently treated as passing.

## Pre-commit isolation record

```text
pwd: /Users/quietguy/Documents/Dev/Gauntlet/wt-T-F17a
top-level: /Users/quietguy/Documents/Dev/Gauntlet/wt-T-F17a
branch: ticket/T-F17a-hosted-role-prompt-contract
status:
 M tests/test_packaging.py
?? tests/test_agent_prompts.py
```

Verdict: clean, criterion-tagged RED for the missing T-F17a prompt registry and packaged resources.
