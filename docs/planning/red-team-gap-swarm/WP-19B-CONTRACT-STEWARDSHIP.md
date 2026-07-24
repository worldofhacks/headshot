# WP-19B — Reconcile schemas, compatibility, registry, and package data

**Branch:** `rtg/wp19b-contract-stewardship`

**Model:** capable

**Depends on:** WP-11 through WP-19A, including WP-13, WP-13A–F, WP-16A–D, and WP-18A–C

**Implements toward (live validation pending):** cross-package contract registration and distribution

Read every schema added or changed by the gap-closure packages, the existing registry/
compatibility rules, package-data configuration, wheel tests, and all producer handoffs.
This is a serialized stewardship package after every schema producer.

**Implementation writes only**

- `src/agentforge/contracts/__init__.py`
- `src/agentforge/contracts/registry.py`
- `src/agentforge/contracts/compat.py`
- `src/agentforge/contracts/v1/manifest.json`
- `pyproject.toml` only for contract/eval schema package data
- `scripts/check_contract_registry.py`

**Test writes only**

- `tests/contract/test_gap_contract_registry.py`
- `tests/contract/test_gap_contract_compatibility.py`
- `tests/contract/test_installed_contract_package.py`

## Required result

Inventory every packaged `contracts/v1` and eval schema by exact path, ID, version, and
SHA-256. Register each once, reject duplicate IDs/paths and ambiguous precedence, and
preserve the repository's compatibility rules. Validate references and producer/consumer
expectations across Judge observations, surfaces, tool brokers/bundles, workbench/fuzz/
scanner/OAST/browser plans, regressions, and reports.

Do not edit a producer's schema to make stewardship green. If a schema is invalid or
incompatible, return `NEEDS_CONTEXT` naming its owning package and exact mismatch. Do not
restore the removed duplicate root contract tree. Source-tree and built-wheel lookup must
resolve the same bytes; all schema/manifest files must be explicit package data.

Tests install the built wheel into an isolated environment, enumerate every manifest
entry, load all schemas without repository-root fallback, verify hashes/references, test
supported backward compatibility, and fail for an unregistered, duplicate, missing,
shadowed, path-escaped, or source/wheel-divergent contract.

**Focused verifier**

```bash
python -m pytest tests/contract tests/contract/test_gap_contract_registry.py tests/contract/test_gap_contract_compatibility.py tests/contract/test_installed_contract_package.py -q
python scripts/check_contract_registry.py --check
RTG_BUILD_TMP="$(mktemp -d)"
mkdir -p "$RTG_BUILD_TMP/src" "$RTG_BUILD_TMP/dist"
git archive --format=tar HEAD | tar -x -C "$RTG_BUILD_TMP/src"
(cd "$RTG_BUILD_TMP/src" && python -m build --no-isolation --outdir "$RTG_BUILD_TMP/dist")
```

Then inspect the temporary wheel and run its contract lookup in a clean temporary virtual
environment using `pip install --no-deps <wheel>`. Build/venv artifacts must stay under
the validated `RTG_BUILD_TMP`; no repository `dist/`, `build/`, or egg-info writes. No
network or package download.

**Handoff:** WP-20A/B/C depend on this manifest and must not add an unregistered contract.
