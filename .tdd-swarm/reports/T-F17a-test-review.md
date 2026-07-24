# T-F17a Final Test Design Review

Status: `REVIEW_CHANGES_REQUIRED`

Freeze verdict: `NOT_FROZEN`

Review attempt: `3/3`

Reviewed commit: `1f2bc4f3b99f820ea596d9b258a7621f9f66c327`

Reviewed candidate snapshot:

- `tests/test_agent_prompts.py`
  - SHA-256: `8e5b003c2160fdee2333e56da6c0e4e505708296f0325de76eb27262a15014bc`
  - Git blob: `ea8940325146877f22038a8e275b025bcf798cbb`
- `tests/test_packaging.py`
  - SHA-256: `d1f5af0d844abb3432bd07c8be7d74f41186e9511295977aac16a59c780550cb`
  - Git blob: `3dc7306736a344804a3a0b87db72b7d74fce7a2c`
- `.tdd-swarm/reports/T-F17a-test.md`
  - SHA-256: `359203ff68253a25dcb28062e02f47978c27521a6c46bbd3a6a6bc3b96cf6b6f`

These hashes identify the rejected final-review candidate. They are not frozen implementation
contracts.

## Prior finding closure

The five Important findings and one Minor finding from `d630bbb`, plus the direct-wheel portion of
I-6 from `78b28ca`, are materially closed:

1. Every new test reaches the missing registry or packaged-resource assertion before any
   pre-existing model assertion can pass.
2. The deterministic stdlib wheel builder and local install require no build frontend or dependency
   acquisition; pip is configured with `--no-index --no-deps`.
3. In-process and isolated registry paths deny socket, urllib, and HTTP-client connection attempts
   before registry import/use.
4. Record mutation, identity lookup, and all 23 non-identity role/resource/hash/content
   permutations cover every role.
5. Error checks cover prefix, middle, suffix, and unique-canary fragments through both `str` and
   `repr`.
6. The unsupported public size constant/minimum is gone; a private one-MiB-plus-one input proves a
   finite upper bound.
7. The AC-4 subprocess now imports the package directly from the `.whl`, proves the traversable is
   zip-backed, loads all four records, and compares their exact manifest/content/hash identities.

One Important gap remains in the claimed proof that the registry itself resolves through
`importlib.resources` with zero filesystem fallback attempts.

## Important finding

### I-7 — The zip probe can pass without registry use of `importlib.resources` and misses filesystem attempts

The subprocess patches only `Path.open` and `builtins.open` for archive-member pseudo-paths
(`tests/test_packaging.py:413-439`). It does not observe `io.open`, `os.open`, or Python's `open`
audit event. A filesystem-first loader can therefore attempt one of those APIs, catch the failure,
and continue while `filesystem_attempts` remains empty.

The probe also creates `resource_root = importlib.resources.files(prompts)` itself
(`tests/test_packaging.py:443-449`). That proves an independently constructed traversable is
zip-backed, but no instrumentation proves `prompts.load_prompt_registry()` at line 451 called
`importlib.resources.files`. A loader that reads members directly with `zipfile.ZipFile` can return
the correct four records while the probe's unrelated `resource_root` supplies the passing backend
assertion.

An isolated reproduction reused the candidate's two open wrappers against the deterministic wheel,
then:

1. attempted `io.open` on a package-member pseudo-path and caught its `OSError`;
2. confirmed the candidate tracker still contained zero attempts;
3. manually read a packaged member through `zipfile.ZipFile`, without using the resource
   traversable for that load; and
4. retained the passing independent `zipfile` backend assertion.

It exited `0` and printed:

```text
UNRECORDED_IO_FALLBACK_AND_MANUAL_ZIP_LOAD_PASSED
```

This is the lazy hybrid implementation that AC-4 and the review prompt require the frozen tests to
reject. Direct-from-wheel success closes package-relative `Path(__file__)` as the sole loader, but
the current instrumentation does not prove the registry used `importlib.resources` or made zero
filesystem attempts.

Required repair:

- wrap `importlib.resources.files` before importing/loading the prompt registry, keep the probe's
  independent backend inspection outside that counter, and require the registry load itself to
  request resources for `agentforge.agents.prompts`; and
- install an audit hook (or equivalently complete wrappers) before import/load that records every
  archive-member filesystem `open` attempt, including `io.open` and `os.open`, then require the
  attempt list to remain empty.

The direct wheel, exact-byte, no-network, and installed-wheel checks should remain unchanged.

## Independent evidence

Focused intentional RED:

```text
PIP_NO_INDEX=1 PYTHONPATH=src python -m pytest -o addopts='' \
  tests/test_agent_prompts.py \
  tests/test_packaging.py::test_spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority \
  -q
```

Result: exit `1`; `8 failed`. All seven registry tests fail only at
`T-F17a prompt registry package is missing`; the wheel case builds locally and fails only because
`agentforge/agents/prompts/registry.v1.json` is absent. There are no collection, fixture, build,
install, provider, target, or network errors.

Existing hosted-configuration and non-wheel packaging baseline:

```text
PYTHONPATH=src python -m pytest -o addopts='' \
  tests/test_hosted_configuration.py tests/test_packaging.py \
  -k 'not wheel_installed_outside_repo_validates_corpus and
      not spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority' -q
```

Result: exit `0`; `14 passed, 2 deselected`.

Independent offline smoke of the stdlib wheel builder plus
`pip install --no-index --no-deps --target ...` exited `0` and printed
`OFFLINE_INSTALL_OK`. A network-denied isolated direct-wheel probe loaded an existing packaged
schema through a zip-backed `importlib.resources` traversable with zero `Path.open`/`builtins.open`
member attempts and printed `ZIP_RESOURCE_SMOKE_OK`. This proves the intended mechanism is viable;
I-7 concerns whether the candidate test requires the prompt registry to use it.

- Ruff check: pass.
- Ruff format check: pass; both owned tests already formatted.
- `git diff --check 0803849..1f2bc4f`: pass.
- Secret scan: `secret scan clean (845 files)`.
- Diff from `0803849` changes only the two declared test scopes and the Test Agent/Test Reviewer
  reports. No product, provider, target, credential, fixture, deployment, or configuration file
  changed.
- No network, provider call, target call, credential read, deployment, or main-branch operation was
  performed during this review.

Verdict: Critical findings: `0`; Important findings: `1`; Minor findings: `0`. The candidate remains
unfrozen and must not be given to an Implementation Agent until I-7 is repaired and independently
re-reviewed.
