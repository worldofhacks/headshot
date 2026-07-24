# T-F17a GREEN Code and Security Review

Status: `DONE`

Verdict: `CHANGES_REQUIRED`

Reviewed implementation: `7ecff119e1381b3d656a03c34e286657a1a19161`

Frozen base: `f22609140b7f9e1fe7d53761668bd778b8dfbda6`

## Frozen-test integrity

The frozen tests are unchanged:

- `tests/test_agent_prompts.py`
  - Frozen/current SHA-256: `8e5b003c2160fdee2333e56da6c0e4e505708296f0325de76eb27262a15014bc`
  - Frozen/current Git blob: `ea8940325146877f22038a8e275b025bcf798cbb`
- `tests/test_packaging.py`
  - Frozen/current SHA-256: `53ad0d07fe7f19d2f7c2cc37edd1f1a56dfeaac2709b7d1c04f2204a6473d5fe`
  - Frozen/current Git blob: `33a22029da045d05888993545e3b94a87cc04ae1`

The implementation diff contains no test edit.

## Finding

### Important — common provider/session/credential shapes bypass AC-2 validation

The secret detector in `src/agentforge/agents/prompts/__init__.py:20-35` rejects the frozen
OpenRouter case plus AWS access ids, Slack tokens, Clerk secret keys, Bearer values, bare sensitive
assignments, and PEM private-key headers. It does not provide the promised general fail-closed
boundary for secret-shaped prompt resources.

Independent hash-consistent bundle probes were accepted for these synthetic shapes:

- GitHub classic and fine-grained token prefixes;
- Google API-key prefix;
- an environment-prefixed `OPENROUTER_API_KEY=<opaque-value>`;
- `TARGET_SESSION=<opaque-value>`;
- a quoted JSON `"password":"<opaque-value>"`;
- a raw JWT; and
- a credential-bearing PostgreSQL URL.

The environment-prefixed provider key bypasses because the generic assignment pattern begins at a
word boundary before `api_key`; the underscore before that suffix is also a word character. The
same pattern omits session names and cannot cross a quoted key's closing quote. The other common
families have no dedicated pattern.

An altered prompt with one of these values and a correspondingly updated manifest hash passes
`validate_prompt_bundle()` and can become provider system-message content in T-F17c. This violates
AC-2 and the ticket's no-provider-key/no-target-session Definition of Done. Add frozen hostile
cases for the accepted shapes and replace or extend the detector so all fail with the same generic,
non-disclosing `PromptRegistryError`. Keep the patterns bounded to avoid scanning pathological
input.

## Verified behavior

- The manifest hashes equal the exact packaged prompt bytes, including trailing newlines:
  - orchestrator:
    `0d851bb22f98921de1e8de42d90cd50fde73603d251b3a38c6591fd6f5a91bb2`
  - red_team:
    `72310c2141e50bc5da0a85e8e2cad82a16ba2490aa6265efa8dc26790129a776`
  - judge:
    `ae95f4b8398410b40c0b9b028aec47b6d7e027965b4f3eea4f5b524e58a29065`
  - documentation:
    `4ebc294a0f24c5b7d367b986fd1b644c244d9c1df3dfe8492f5e347fb4247bd1`
- The role order, version, resource identity, duplicate-key rejection, exact raw-byte hash, UTF-8,
  size, NUL, trailing-newline, and exact-identity lookup checks are closed and fail generically.
- `PromptRecord` is frozen/slotted and omits content from `repr`; public validation, load, and
  lookup errors expose only `prompt registry validation failed`.
- All four prompts contain their exact required role-specific trust clauses. They contain no
  credential, target-session value, PHI, URL, runtime template, or environment-specific setting.
- `load_prompt_registry()` reads the manifest and every prompt only through
  `importlib.resources.files(__package__)` traversables. There is no environment, database,
  checkout-relative, `Path`, direct `open`, or manual-ZipFile fallback.
- The offline installed/direct-wheel test proves byte-identical package-resource access outside
  the checkout and rejects decoy filesystem and manual archive-member bypasses.
- `pyproject.toml` includes the manifest and `v1/*.txt` as package data. No dependency changed.
- The migration note correctly records raw-byte authority, exact identity lookup, T-F17c handoff,
  wheel verification, and rollback/configuration pairing.

## Independent gates

Focused frozen tests:

```text
PIP_NO_INDEX=1 PYTHONPATH=src <venv-python> -m pytest -o addopts='' \
  tests/test_agent_prompts.py \
  tests/test_packaging.py::test_spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority \
  -q
```

Result: `8 passed` in `2.54s`.

Focused hosted/packaging preservation:

```text
PYTHONPATH=src <venv-python> -m pytest -o addopts='' \
  tests/test_hosted_configuration.py tests/test_packaging.py \
  -k 'not wheel_installed_outside_repo_validates_corpus and
      not spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority' -q
```

Result: `14 passed, 2 deselected`.

Full offline-compatible repository suite:

```text
<venv-python> -c 'import sys, pytest; sys.path.insert(0, "src");
raise SystemExit(pytest.main(["-o", "addopts=", "-q", "-k",
"not wheel_installed_outside_repo_validates_corpus"]))'
```

Result: `1132 passed, 3 skipped, 1 deselected` in `19.28s`.

Additional gates:

- Ruff check and format check: pass.
- Diff check from the frozen base: pass.
- Secret scan: `secret scan clean (853 files)`.
- Gitleaks: no leaks across 204 commits.
- No ticket-source TODO/FIXME/debug additions.
- `.tdd-swarm/run-local-gates.sh` and the in-tree spec-lint remain absent from the frozen T-F00
  dependency base; the wrapper cannot be represented as passing.

Final severity: Critical `0`; Important `1`; Minor `0`.
