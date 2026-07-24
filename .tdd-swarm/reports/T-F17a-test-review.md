# T-F17a Final Test Design Review

Status: `PASS`

Freeze verdict: `FROZEN`

Reviewed commit: `79edaeaef4ec3fab375f666f0e2154dd4cbdf2c5`

## Frozen test identities

- `tests/test_agent_prompts.py`
  - SHA-256: `8e5b003c2160fdee2333e56da6c0e4e505708296f0325de76eb27262a15014bc`
  - Git blob: `ea8940325146877f22038a8e275b025bcf798cbb`
- `tests/test_packaging.py`
  - SHA-256: `53ad0d07fe7f19d2f7c2cc37edd1f1a56dfeaac2709b7d1c04f2204a6473d5fe`
  - Git blob: `33a22029da045d05888993545e3b94a87cc04ae1`

No Implementation Agent may edit either frozen test.

## Finding closure

All prior Important and Minor test-design findings are closed. The direct-wheel probe:

- imports the package directly from the wheel archive under isolated Python;
- requires `load_prompt_registry()` itself to call `importlib.resources.files` for
  `agentforge.agents.prompts`;
- requires the returned traversable to read the manifest and all four prompt resources;
- detects local-file attempts through `Path.open`, `builtins.open`, `io.open`, `os.open`, and the
  Python open audit event; and
- detects direct prompt-member reads through `ZipFile.open` outside a tracked traversable read.

The Test Agent's synthetic-loader checks demonstrate that the legitimate traversable loader is
accepted while each covered alternate loader is refused. The tests remain offline and do not read
an environment, credential, target session, or patient fixture.

## Independent evidence

Focused RED:

```text
PIP_NO_INDEX=1 PYTHONPATH=src <venv-python> -m pytest -o addopts='' \
  tests/test_agent_prompts.py \
  tests/test_packaging.py::test_spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority \
  -q
```

Result: `8 failed`, each at the missing T-F17a registry/package-resource boundary.

Preserved baseline:

```text
PYTHONPATH=src <venv-python> -m pytest -o addopts='' \
  tests/test_hosted_configuration.py tests/test_packaging.py \
  -k 'not wheel_installed_outside_repo_validates_corpus and
      not spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority' -q
```

Result: `14 passed, 2 deselected`.

Preserved repository suite excluding the eight intended RED cases and the pre-existing
network-dependent wheel test: `1124 passed, 3 skipped, 9 deselected`.

Additional gates:

- Ruff check: pass.
- Ruff format check: pass.
- Diff check from `0803849` through `79edaea`: pass.
- Secret scan: `secret scan clean (845 files)`.
- Candidate diff contains only the declared tests and TDD review reports.

Verdict: Critical findings `0`; Important findings `0`; Minor findings `0`.
