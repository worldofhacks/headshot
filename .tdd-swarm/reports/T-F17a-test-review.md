# T-F17a Test Design Re-review

Status: `REVIEW_CHANGES_REQUIRED`

Freeze verdict: `NOT_FROZEN`

Review attempt: `2/3`

Reviewed commit: `ff36e0db89466eaf498b60057b607d89df18ec44`

Reviewed test snapshot:

- `tests/test_agent_prompts.py`:
  `8e5b003c2160fdee2333e56da6c0e4e505708296f0325de76eb27262a15014bc`
- `tests/test_packaging.py`:
  `e6ecca56d11be0b0ec0e7140f4dbdd040ba90f49c2fe8420a77ab59489c786cd`
- `.tdd-swarm/reports/T-F17a-test.md`:
  `9f7f002156032365514c77c567574fe987f898d3b3a287be22b1ddfb9bd8f6b6`

These hashes identify the reviewed repair snapshot. They are not frozen implementation contracts.

## Prior finding closure

All five Important findings from `d630bbb` are materially closed:

1. The exact hosted model table is now reached only after the missing prompt registry loads, so all
   new tests are feature-missing RED.
2. The new prompt-wheel test uses a deterministic stdlib wheel, `--no-index --no-deps`, disabled
   pip configuration/version checks, and no build isolation or dependency acquisition. A separate
   local-wheel install smoke exits `0`.
3. An autouse socket/urllib/http.client denial guard covers every in-process registry, lookup,
   validation, and trust-boundary test. The installed subprocess installs offline and applies the
   same connection guards before importing the registry.
4. All four record identity fields receive hostile mutation attempts; identity lookup spans every
   role/version/hash combination; and all 23 non-identity role/resource/hash/content permutations
   are rejected.
5. Every role now carries a unique short canary. Hostile validation and lookup errors are checked
   through both `str` and `repr` for prefix, middle, suffix, and canary fragments.

The unsupported public `MAX_PROMPT_BYTES` and 256-byte minimum from the prior Minor finding are
also removed. The repaired private one-MiB-plus-one case proves a finite upper-bound rejection
without prescribing a production constant.

## Important finding

### I-6 — The AC-4 probe still allows a package-filesystem loader instead of `importlib.resources`

The test-review prompt explicitly requires proof that a lazy filesystem fallback cannot pass, and
AC-4 requires resolution through `importlib.resources`. The repaired test verifies archive
membership at `tests/test_packaging.py:322-338`, but then installs and unpacks the wheel at lines
340-369. Its isolated probe imports that unpacked package directory at lines 405-447.

Consequently, an implementation that reads
`Path(__file__).parent / "registry.v1.json"` and
`Path(__file__).parent / "v1" / f"{role}.txt"` passes this probe. Those files exist in the unpacked
installation and are byte-identical to the archive. The decoy at lines 371-385 and environment
variables at lines 425-431 rule out caller/environment override directories only; they do not
distinguish package-relative filesystem reads from `importlib.resources`.

That is the exact lazy fallback the review prompt says must not pass. It also loses zip-safe
resource behavior despite the otherwise correct installed-wheel assertions.

Required repair: retain the offline installed-wheel proof, and add a second isolated probe that
imports directly from the `.whl` archive on `sys.path` (or another behaviorally equivalent
zip-backed package-resource test). Assert all four manifest/content/hash records load there with
network denied. A `Path(__file__)` reader will then fail while `importlib.resources` remains valid.
The repair must stay deterministic and must not inspect production source text as a substitute for
behavior.

## Bounded review evidence

Focused zero-network RED:

```text
PIP_NO_INDEX=1 python -m pytest -o addopts='' \
  tests/test_agent_prompts.py \
  tests/test_packaging.py::test_spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority \
  -q
-> exit 1; 8 failed
```

All seven registry tests fail only at the explicit
`T-F17a prompt registry package is missing` assertion. The wheel test builds without a frontend and
fails only because `agentforge/agents/prompts/registry.v1.json` is absent. There are no collection,
fixture, dependency-acquisition, provider, target, or network errors.

Independent offline installation smoke of `_build_stdlib_test_wheel` with `--no-index --no-deps`
exits `0`. Existing hosted-configuration and non-wheel packaging baseline:
`14 passed, 2 deselected`.

- Test collection: `tests/test_agent_prompts.py: 7`; `tests/test_packaging.py: 6`.
- Ruff check on both test-owned files: pass.
- Ruff format check on both test-owned files: pass.
- `git diff --check d630bbb..ff36e0d`: pass.
- Repair commit changes only the two test files and Test Agent report; no product file changed.
- No test or product file was edited during this review.

Verdict: Critical findings: `0`; Important findings: `1`; Minor findings: `0`.
The repaired tests must return once more to the Test Agent, then receive a third independent review
and new hash freeze before implementation begins.
