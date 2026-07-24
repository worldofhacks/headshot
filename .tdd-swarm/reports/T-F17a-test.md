# T-F17a Test Agent Report

Status: `DONE`

## Scope

- Base: `0803849aab0e99387ee80566b359384cb216f2b1`
- Repaired after review commit: `3fa7b1adfb5e36157268fc029ef4da1f9194deaa`
- Branch: `ticket/T-F17a-hosted-role-prompt-contract`
- Test ownership: `tests/test_agent_prompts.py`, `tests/test_packaging.py`
- No production, provider, target, deployment, or main-branch change was made.
- Provider system-message transport remains T-F17c scope; authenticated prompt API/UI exposure
  remains T-F17f scope.

## RED contracts

- AC-1: exact immutable four-role records, UTF-8 content, explicit version, SHA-256 over exact
  bytes including the trailing newline, safe record repr, all four identity fields resistant to
  hostile mutation, exhaustive exact-identity lookup with no role/version/hash fallback, and each
  locked model assignment bound to the corresponding loaded registry role.
- AC-2: deterministic bundle validation rejects missing, duplicate, altered, role-mismatched,
  non-UTF-8, oversized, secret-shaped, unmanifested, and traversal-shaped resources; validation
  is network-denied and error text may not disclose short prefix/middle/suffix or unique-canary
  fragments. All 23 non-identity permutations are exercised independently for manifest roles,
  resource references, hashes, and resource content.
- AC-3: every full prompt must encode its role-specific trust boundary, including fresh authorized
  Orchestrator select/halt, exact-parent bounded Red Team mutation, independent fail-closed Judge
  precedence, and draft-only Documentation behavior.
- AC-4: a deterministic stdlib-built wheel contains the manifest and four prompt resources,
  preserves build-input bytes exactly, declares them in setuptools package data, and installs with
  `--no-index --no-deps`. One isolated network-denied probe loads/looks up those bytes from the
  unpacked installation outside the repository despite a valid content-addressed decoy filesystem
  bundle. A second isolated probe imports directly from the `.whl` archive, verifies a zip-backed
  `importlib.resources` traversable, and instruments the actual `load_prompt_registry()` call. The
  registry load itself must call `importlib.resources.files` for
  `agentforge.agents.prompts`, and the returned tracking traversable must read the manifest plus all
  four exact prompt resources. The independent backend inspection uses the original unwrapped
  `files` function outside that counter, so it cannot manufacture this proof.
- AC-4 bypass resistance: archive-member attempts through `Path.open`, `builtins.open`, `io.open`,
  `os.open`, or Python's `open` audit event are recorded; the direct wrappers reject immediately
  and the post-load invariant rejects even a caught attempt. `ZipFile.open` separately records
  direct prompt-member reads outside a tracking-traversable read, so a dummy `files()` call followed
  by manual `ZipFile` loading cannot pass. Archive-path comparison tolerates macOS's equivalent
  `/private/var` and `/var` spellings without weakening the exact wheel identity check.
- Size boundary: the test no longer requires public `MAX_PROMPT_BYTES` or an unsupported 256-byte
  minimum. Its private one-MiB-plus-one adversarial resource proves a finite rejection boundary
  without prescribing a production constant or smaller valid-prompt minimum.

## Evidence

Intentional RED:

- `PIP_NO_INDEX=1 ... pytest tests/test_agent_prompts.py
  tests/test_packaging.py::test_spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority
  -q` → exit 1, `8 failed`; every new test is RED.
- All seven registry tests fail only at the explicit
  `T-F17a prompt registry package is missing` assertion.
- The wheel test builds without pip/build isolation, then fails only at
  `the prompt registry manifest is not packaged in the wheel`.
- A separate network-disabled smoke of the same stdlib wheel builder plus
  `pip install --no-index --no-deps` exits 0, proving wheel installation itself is not the RED
  cause.
- A direct-from-wheel smoke imports the existing `agentforge.contracts` package from the archive,
  denies sockets and package-member filesystem opening, verifies the `importlib.resources` backend
  is `zipfile`, and reads a packaged schema successfully. It prints `ZIP_RESOURCE_SMOKE_OK`,
  proving the zip-backed probe mechanism itself is viable before T-F17a resources exist.
- An isolated synthetic-wheel adversarial check extracted the exact subprocess probe from
  `tests/test_packaging.py`. A legitimate loader that called `files()` and read all five authority
  resources through its returned traversable was accepted. Hybrid loaders that attempted then
  caught `Path.open`, `builtins.open`, `io.open`, or `os.open` archive-member access before using
  package resources were each rejected. A loader that made a dummy `files()` call and manually read
  the manifest/prompts with `ZipFile` was also rejected.

Zero-network proof:

- An autouse socket/urllib/http.client denial guard is active before every in-process registry,
  validation, lookup, and trust-boundary test.
- The installed-wheel subprocess patches the same connection paths before importing the installed
  package.
- The direct archive subprocess applies the same network denials before import and runs under
  isolated mode with only the local wheel prepended to `sys.path`.
- Wheel creation uses only `zipfile`; installation sets `PIP_NO_INDEX=1`, disables pip config and
  version checks, and passes `--no-index --no-deps`.

Preservation and gates:

- Existing hosted-configuration plus non-wheel packaging baseline → `14 passed`.
- Existing repository suite excluding only the eight new RED tests and the pre-existing
  network-dependent wheel test → `1124 passed, 3 skipped, 2 deselected`.
- Test-scope collection → `tests/test_agent_prompts.py: 7`,
  `tests/test_packaging.py: 6`.
- T-F00 spec-lint from `ticket/T-F00-swarm-gates` → `T-F17a maps 4 acceptance criteria across
  2 pytest-collected scopes`.
- `ruff format` / `ruff check` on both owned test files → pass.
- `git diff --check` → pass.
- `bash scripts/secret_scan.sh` → `secret scan clean (845 files)`.
- The pinned base does not contain `.tdd-swarm/run-local-gates.sh`; therefore that wrapper cannot
  run until dependency T-F00 is integrated. No gate was silently treated as passing.

## Pre-commit isolation record

```text
pwd: /Users/quietguy/Documents/Dev/Gauntlet/wt-T-F17a
top-level: /Users/quietguy/Documents/Dev/Gauntlet/wt-T-F17a
branch: ticket/T-F17a-hosted-role-prompt-contract
status:
 M .tdd-swarm/reports/T-F17a-test.md
 M tests/test_packaging.py
```

Verdict: review finding I-6 is repaired; all eight new tests remain clean, criterion-tagged RED for
the missing T-F17a prompt registry and packaged resources. Review finding I-7 is now also repaired:
the registry must use `importlib.resources.files` and its returned traversable, while caught
filesystem-first and manual-ZipFile bypasses remain observable and fatal. The suite is ready for
the final independent freeze review and remains explicitly **not frozen** until that reviewer
passes and hashes it.
