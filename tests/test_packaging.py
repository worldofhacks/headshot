"""Packaging tests: the authoritative schemas must ship IN the wheel and resolve via
``importlib.resources`` — never by walking up to a repo checkout.

Two guarantees are pinned here:

1. Resolution is package-based, not CWD/repo-relative. With the process CWD moved to an
   unrelated temp directory and ``AGENTFORGE_CONTRACTS_DIR`` unset, both the contract
   registry and the eval-schema loader still resolve their schemas. The definitive signal
   is that ``importlib.resources`` can read every schema out of the installed package — the
   exact lookup the production code must use once the schemas are packaged.

2. A wheel installed OUTSIDE any repo checkout can validate a corpus. The wheel is built,
   installed into a fresh venv in a temp dir with only ``jsonschema`` alongside it, and the
   installed ``python -m agentforge.evals`` console is run against a copy of the corpus DATA
   (schemas come from the wheel, never copied). This is the load-bearing proof that schema
   resolution needs no repo on disk.

Both tests are RED until the schemas are relocated under the packages, resolved via
``importlib.resources``, and declared in ``[tool.setuptools.package-data]``.
"""

from __future__ import annotations

import importlib.resources as importlib_resources
import json
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

# Repo root is tests/.. — used only to LOCATE input DATA and to build the wheel, never as a
# schema-resolution path (that is exactly the coupling these tests exist to forbid).
_REPO_ROOT = Path(__file__).resolve().parents[1]
_CORPUS_ROOT = _REPO_ROOT / "evals"

# The versioned inter-agent/security-tool contracts (contracts/v1/*.json) and the three
# eval-authoring schemas (evals/schemas/*.json) — the two sets that must live under a package and
# ship in the wheel.
_CONTRACT_SCHEMAS = (
    "campaign_directive",
    "attack_attempt",
    "attempt_result",
    "evidence_envelope",
    "verdict",
    "regression_admission",
    "security_tool_run",
    "tool_finding",
    "scan_artifact",
    "tool_execution_error",
    "tool_attack_bundle",
    "errors",
)
_EVAL_SCHEMAS = (
    "attack-case.v1.json",
    "ground-truth-slice.v1.json",
    "synthetic-fixture.v1.json",
)

# A known-valid Verdict (lifted from the offline ground-truth corpus) — used to prove the
# packaged contract registry still validates real payloads with the CWD moved away.
_VALID_VERDICT = {
    "schema_version": "1",
    "campaign_run_id": "ground-truth-unexecuted",
    "attempt_id": "GT-M11-PI-CONF-001",
    "state": "EXPLOIT_CONFIRMED",
    "confidence": 1.0,
    "reason_codes": ["canary_hit"],
    "confirmation_source": "canary",
}


def _read_packaged_text(package: str, *parts: str) -> str:
    """Read a data file out of an installed package via importlib.resources.

    This is the CWD-independent, zip-safe lookup the production loaders must use. It raises
    ``FileNotFoundError`` when the data file is not packaged — which is the current state, and
    why this file is RED today.
    """
    resource = importlib_resources.files(package)
    for part in parts:
        resource = resource.joinpath(part)
    return resource.read_text(encoding="utf-8")


def test_contract_registry_resolves_without_cwd_or_repo(monkeypatch, tmp_path):
    """Contract-schema resolution is package-based, not CWD/repo-relative.

    With CWD moved to an unrelated temp dir and AGENTFORGE_CONTRACTS_DIR unset, every contract
    schema must be readable straight out of the installed package, and the public registry API
    must still validate a real payload.
    """
    from agentforge.contracts import is_valid

    monkeypatch.delenv("AGENTFORGE_CONTRACTS_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    # Package-based resolution: every contract schema is a well-formed JSON object shipped
    # under the agentforge.contracts package (RED until contracts/v1 is relocated + packaged).
    for name in _CONTRACT_SCHEMAS:
        text = _read_packaged_text("agentforge.contracts", "v1", f"{name}.json")
        assert isinstance(json.loads(text), dict)

    # Public API keeps working transparently from an unrelated CWD.
    assert is_valid("verdict", _VALID_VERDICT) is True


def test_eval_schema_loader_resolves_without_cwd_or_repo(monkeypatch, tmp_path):
    """Eval-schema resolution is package-based, not repo-relative (no parents[3] walk).

    With CWD moved away, every eval-authoring schema must be readable out of the installed
    package, and the in-memory validators must still accept a valid corpus artifact.
    """
    from agentforge.evals.validation import validate_fixture

    monkeypatch.delenv("AGENTFORGE_CONTRACTS_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    # Package-based resolution of the eval schemas (RED until evals/schemas is relocated +
    # packaged and validation.py drops its _REPO_ROOT/parents[3] lookup).
    for schema_name in _EVAL_SCHEMAS:
        text = _read_packaged_text("agentforge.evals", "schemas", schema_name)
        assert isinstance(json.loads(text), dict)

    # The loader itself must resolve its schema without a repo checkout: validating a real
    # packaged fixture from an unrelated CWD must not raise.
    fixture_path = _CORPUS_ROOT / "fixtures" / "synthetic-clinical-context-v1.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    validate_fixture(fixture, source="<packaging-test>")


def _venv_python(env_dir: Path) -> Path:
    if sys.platform == "win32":  # pragma: no cover - CI runs on Linux/macOS
        return env_dir / "Scripts" / "python.exe"
    return env_dir / "bin" / "python"


def test_wheel_installed_outside_repo_validates_corpus(tmp_path):
    """Definitive proof: an installed wheel validates a corpus with NO repo checkout on disk.

    Build the wheel, install ONLY it (+ jsonschema) into a fresh venv in a temp dir, copy the
    corpus DATA (not the schemas — those ride in the wheel) into that temp dir, and run the
    installed ``python -m agentforge.evals`` console from a CWD outside the repo. Schemas must
    resolve from the package alone.
    """
    wheel_dir = tmp_path / "wheelhouse"
    wheel_dir.mkdir()

    build = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(_REPO_ROOT), "--no-deps", "-w", str(wheel_dir)],
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, f"pip wheel failed:\n{build.stdout}\n{build.stderr}"

    wheels = sorted(wheel_dir.glob("agentforge-*.whl"))
    assert wheels, f"no agentforge wheel was produced in {wheel_dir}"
    wheel_path = wheels[-1]

    # The schemas must physically ship in the wheel — the root cause today is that they do not.
    wheel_names = _wheel_namelist(wheel_path)
    for name in _CONTRACT_SCHEMAS:
        assert f"agentforge/contracts/v1/{name}.json" in wheel_names, (
            f"contract schema {name}.json is not packaged in the wheel"
        )
    for schema_name in _EVAL_SCHEMAS:
        assert f"agentforge/evals/schemas/{schema_name}" in wheel_names, (
            f"eval schema {schema_name} is not packaged in the wheel"
        )

    # Fresh venv in a temp dir OUTSIDE the repo, containing only the wheel + jsonschema.
    env_dir = tmp_path / "fresh-venv"
    venv.create(env_dir, with_pip=True, clear=True)
    venv_python = _venv_python(env_dir)
    install = subprocess.run(
        [str(venv_python), "-m", "pip", "install", str(wheel_path), "jsonschema>=4"],
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, f"wheel install failed:\n{install.stdout}\n{install.stderr}"

    # Copy ONLY the corpus DATA into the temp dir. The schemas are intentionally NOT copied —
    # they must be resolved from the installed package.
    corpus_dir = tmp_path / "corpus"
    for subdir in ("seeds", "ground-truth", "fixtures"):
        shutil.copytree(_CORPUS_ROOT / subdir, corpus_dir / subdir)

    # Run the installed console from a CWD outside the repo.
    validate = subprocess.run(
        [str(venv_python), "-m", "agentforge.evals", "validate-corpus", str(corpus_dir)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )
    assert validate.returncode == 0, (
        f"validate-corpus failed from an installed wheel:\n{validate.stdout}\n{validate.stderr}"
    )
    assert "valid corpus" in validate.stdout

    # Duplicate-sequence detection must likewise resolve schemas from the package alone.
    duplicate = subprocess.run(
        [
            str(venv_python),
            "-m",
            "agentforge.evals",
            "detect-duplicate-sequence",
            str(corpus_dir / "seeds"),
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
    )
    assert duplicate.returncode == 0, (
        f"detect-duplicate-sequence failed from an installed wheel:\n"
        f"{duplicate.stdout}\n{duplicate.stderr}"
    )


def _wheel_namelist(wheel_path: Path) -> list[str]:
    import zipfile

    with zipfile.ZipFile(wheel_path) as archive:
        return archive.namelist()


if __name__ == "__main__":  # pragma: no cover - convenience for manual runs
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_schema_name_guard_blocks_path_traversal() -> None:
    """A schema name can never traverse out of its packaged directory (defense in depth):
    a name with a path separator or '..' is rejected before any read, so importlib.resources
    joinpath / an on-disk override cannot be coerced into reading an arbitrary file."""
    import pytest

    from agentforge.contracts.registry import load_schema, safe_schema_name
    from agentforge.evals.validation import _schema_validator

    for evil in ("../../../pyproject", "../secrets", "a/b", "..", "v1/verdict", "/etc/passwd"):
        with pytest.raises(ValueError):
            safe_schema_name(evil)
        with pytest.raises(ValueError):
            load_schema(evil)  # registry loader rejects it (no traversal read)
        with pytest.raises(ValueError):
            _schema_validator(evil)  # eval loader rejects it too


def test_schema_name_guard_allows_real_schema_names() -> None:
    """Legitimate bare schema identifiers (contract names, versioned eval-schema filenames) are
    accepted unchanged — the guard adds no false positive."""
    from agentforge.contracts.registry import safe_schema_name

    assert safe_schema_name("verdict") == "verdict"
    assert safe_schema_name("attack_attempt") == "attack_attempt"
    assert safe_schema_name("attack-case.v1.json") == "attack-case.v1.json"
