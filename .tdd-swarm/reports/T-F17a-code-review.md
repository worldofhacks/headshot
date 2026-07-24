# T-F17a GREEN Code and Security Re-review

Status: `DONE`

Verdict: `PASS`

Reviewed repair: `ebe4432407f1ab780ac75003fd2dbb6a304d0141`

Prior review: `1e5e21de1fc6b6346be75327fb4f5d3f8d7fb8d8`

Frozen base: `f22609140b7f9e1fe7d53761668bd778b8dfbda6`

## Findings

No Critical, Important, or Minor findings.

The narrow repair closes the prior Important secret-family gap. The added expressions in
`src/agentforge/agents/prompts/__init__.py:28-43` cover GitHub classic/fine-grained tokens, Google
API keys, environment- and JSON-shaped sensitive assignments including provider keys and sessions,
raw JWTs, and credential-bearing PostgreSQL URLs. They remain bounded and feed the existing closed
content check. Public validation still translates failures to the one generic
`prompt registry validation failed` error without retaining prompt fragments
(`src/agentforge/agents/prompts/__init__.py:121-148`).

## Independent adversarial verification

A reviewer-owned probe started with the exact package-owned bundle, injected each synthetic secret
shape into each role, and updated that resource's manifest SHA-256 so digest mismatch could not
mask secret detection.

All `60/60` role/shape bundles were rejected:

- the eight bypasses from the prior review: GitHub classic, GitHub fine-grained, Google API key,
  prefixed OpenRouter API-key assignment, target-session assignment, quoted JSON password, raw JWT,
  and credential-bearing PostgreSQL URL;
- the previously covered families recorded by that review: OpenRouter provider token, AWS access
  id, Slack token, Clerk secret, Bearer value, bare API-key assignment, and PEM private-key header;
- each of the fifteen families was varied across `orchestrator`, `red_team`, `judge`, and
  `documentation`.

Every failure was exactly `PromptRegistryError("prompt registry validation failed")`. The supplied
value was absent from `str(error)`, `repr(error)`, cause, and context. No case was accepted and no
provider, target, credential, environment, or network operation occurred.

## Frozen and package-resource integrity

Frozen tests remain byte-identical:

- `tests/test_agent_prompts.py`
  - SHA-256: `8e5b003c2160fdee2333e56da6c0e4e505708296f0325de76eb27262a15014bc`
  - Git blob: `ea8940325146877f22038a8e275b025bcf798cbb`
- `tests/test_packaging.py`
  - SHA-256: `53ad0d07fe7f19d2f7c2cc37edd1f1a56dfeaac2709b7d1c04f2204a6473d5fe`
  - Git blob: `33a22029da045d05888993545e3b94a87cc04ae1`

The manifest, four prompt resources, and `pyproject.toml` are unchanged from the reviewed
implementation `7ecff119e1381b3d656a03c34e286657a1a19161`:

- manifest SHA-256:
  `211751e3419f68306820c5d57197a919cbb6ca0036786e46e916588a01529dc7`;
- orchestrator prompt SHA-256:
  `0d851bb22f98921de1e8de42d90cd50fde73603d251b3a38c6591fd6f5a91bb2`;
- red-team prompt SHA-256:
  `72310c2141e50bc5da0a85e8e2cad82a16ba2490aa6265efa8dc26790129a776`;
- Judge prompt SHA-256:
  `ae95f4b8398410b40c0b9b028aec47b6d7e027965b4f3eea4f5b524e58a29065`;
- Documentation prompt SHA-256:
  `4ebc294a0f24c5b7d367b986fd1b644c244d9c1df3dfe8492f5e347fb4247bd1`.

The repair diff from the prior review contains only
`src/agentforge/agents/prompts/__init__.py` and the Implementation Agent report. It changes no test,
manifest, prompt, package-data declaration, dependency, migration, runtime composition, provider,
target, deployment, or configuration artifact.

## Independent gates

Focused frozen and offline installed/direct-wheel package-resource gate:

```text
PIP_NO_INDEX=1 PYTHONPATH=src <venv-python> -m pytest -o addopts='' \
  tests/test_agent_prompts.py \
  tests/test_packaging.py::test_spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority \
  -q
```

Result: `8 passed` in `1.06s`.

Focused hosted/packaging preservation:

```text
PYTHONPATH=src <venv-python> -m pytest -o addopts='' \
  tests/test_hosted_configuration.py tests/test_packaging.py \
  -k 'not wheel_installed_outside_repo_validates_corpus and
      not spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority' -q
```

Result: `14 passed, 2 deselected` in `0.09s`.

Full offline-compatible repository suite:

```text
<venv-python> -c 'import sys, pytest; sys.path.insert(0, "src");
raise SystemExit(pytest.main(["-o", "addopts=", "-q", "-k",
"not wheel_installed_outside_repo_validates_corpus"]))'
```

Result: `1132 passed, 3 skipped, 1 deselected` in `18.55s`.

Additional gates:

- Candidate T-F00 spec-lint:
  `T-F17a maps 4 acceptance criteria across 2 pytest-collected scopes`.
- Ruff check: pass.
- Ruff format check: pass.
- Python compilation: pass.
- Diff check from both the frozen and repair bases: pass.
- Secret scan: `secret scan clean (854 files)`.
- Gitleaks over `1e5e21d..ebe4432`: one commit scanned, no leaks.
- Package resources load byte-identically through `importlib.resources`; the offline wheel gate
  rejects checkout/decoy/manual-archive fallback.

The T-F00-owned local-gate wrapper remains absent from this frozen dependency base, so its available
constituent gates were run directly and are green.

Final severity: Critical `0`; Important `0`; Minor `0`.
