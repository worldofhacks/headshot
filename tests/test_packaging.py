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
    "orchestration_snapshot",
    "judge_calibration",
    "attack_attempt",
    "attempt_result",
    "evidence_envelope",
    "verdict",
    "regression_admission",
    "vuln_report",
    "regression_disposition",
    "regression_replay_plan",
    "regression_replay_result",
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
    for subdir in ("seeds", "drafts", "ground-truth", "fixtures"):
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


def _build_stdlib_test_wheel(wheel_dir: Path) -> Path:
    """Build a deterministic pure-Python wheel without a build frontend or network."""
    import zipfile

    wheel_path = wheel_dir / "agentforge-0.1.0-py3-none-any.whl"
    source_package = _REPO_ROOT / "src" / "agentforge"
    dist_info = "agentforge-0.1.0.dist-info"
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(source_package.rglob("*")):
            if source.is_file() and "__pycache__" not in source.parts:
                archive.write(source, source.relative_to(source_package.parent).as_posix())
        archive.writestr(
            f"{dist_info}/METADATA",
            "Metadata-Version: 2.1\nName: agentforge\nVersion: 0.1.0\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: T-F17a-stdlib\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(f"{dist_info}/RECORD", "")
    return wheel_path


def _package_data_covers_prompt_resources(resource_names: set[str]) -> bool:
    import fnmatch
    import tomllib

    configuration = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = (
        configuration.get("tool", {})
        .get("setuptools", {})
        .get("package-data", {})
        .get("agentforge.agents.prompts", ())
    )
    return bool(patterns) and all(
        any(fnmatch.fnmatchcase(resource_name, pattern) for pattern in patterns)
        for resource_name in resource_names
    )


# spec(T-F17a:AC-4)
def test_spec_T_F17a_AC_4_offline_installed_wheel_preserves_prompt_authority(
    tmp_path: Path,
) -> None:
    """Build/install/probe the prompt wheel with indexes disabled and sockets denied."""
    import base64
    import hashlib
    import os
    import zipfile

    roles = ("orchestrator", "red_team", "judge", "documentation")
    manifest_name = "agentforge/agents/prompts/registry.v1.json"
    wheel_resources = {role: f"agentforge/agents/prompts/v1/{role}.txt" for role in roles}
    wheel_path = _build_stdlib_test_wheel(tmp_path)

    with zipfile.ZipFile(wheel_path) as archive:
        names = set(archive.namelist())
        assert manifest_name in names, "the prompt registry manifest is not packaged in the wheel"
        for role, resource_name in wheel_resources.items():
            assert resource_name in names, f"{role} system prompt is not packaged in the wheel"
        manifest_bytes = archive.read(manifest_name)
        packaged_bytes = {
            role: archive.read(resource_name) for role, resource_name in wheel_resources.items()
        }

    relative_resources = {"registry.v1.json", *(f"v1/{role}.txt" for role in roles)}
    assert _package_data_covers_prompt_resources(relative_resources), (
        "pyproject.toml does not declare every prompt resource as package data"
    )
    for role, raw in packaged_bytes.items():
        source = _REPO_ROOT / "src" / "agentforge" / "agents" / "prompts" / "v1" / f"{role}.txt"
        assert raw == source.read_bytes(), f"{role} wheel bytes differ from build input"

    install_root = tmp_path / "installed"
    pip_environment = os.environ.copy()
    pip_environment.update(
        {
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PIP_REQUIRE_VIRTUALENV": "0",
        }
    )
    install = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            "--target",
            str(install_root),
            str(wheel_path),
        ],
        capture_output=True,
        text=True,
        env=pip_environment,
    )
    assert install.returncode == 0, (
        f"offline local-wheel install failed:\n{install.stdout}\n{install.stderr}"
    )

    manifest = json.loads(manifest_bytes)
    decoy_root = tmp_path / "decoy-prompts"
    decoy_manifest = json.loads(manifest_bytes)
    by_resource = {entry["resource"]: entry for entry in decoy_manifest["prompts"]}
    for role, resource_name in wheel_resources.items():
        relative_name = resource_name.removeprefix("agentforge/agents/prompts/")
        decoy_raw = b"DECOY-FILESYSTEM-FALLBACK-" + packaged_bytes[role]
        decoy_path = decoy_root / relative_name
        decoy_path.parent.mkdir(parents=True, exist_ok=True)
        decoy_path.write_bytes(decoy_raw)
        by_resource[relative_name]["sha256"] = hashlib.sha256(decoy_raw).hexdigest()
    (decoy_root / "registry.v1.json").write_text(
        json.dumps(decoy_manifest, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    probe = r"""
import base64
import builtins
import http.client
import importlib.resources
import io
import json
import os
import socket
import sys
import urllib.request
import zipfile
from pathlib import Path

def denied(*_args, **_kwargs):
    raise AssertionError("installed prompt registry attempted network I/O")

socket.create_connection = denied
socket.socket.connect = denied
socket.socket.connect_ex = denied
urllib.request.urlopen = denied
http.client.HTTPConnection.connect = denied
http.client.HTTPSConnection.connect = denied
sys.path.insert(0, sys.argv[1])

probe_mode = sys.argv[2]
archive_path_spellings = {
    str(Path(sys.argv[1]).absolute()),
    str(Path(sys.argv[1]).resolve()),
}
archive_path_spellings.update(
    path.removeprefix("/private")
    for path in tuple(archive_path_spellings)
    if path.startswith("/private/")
)
archive_member_prefixes = tuple(
    f"{path}/agentforge/" for path in sorted(archive_path_spellings)
)
if probe_mode == "zip":
    original_resource_files = importlib.resources.files
    original_path_open = Path.open
    original_builtin_open = builtins.open
    original_io_open = io.open
    original_os_open = os.open
    original_zipfile_open = zipfile.ZipFile.open
    filesystem_attempts = []
    manual_zip_attempts = []
    resource_files_calls = []
    resource_reads = []
    load_in_progress = False
    traversable_read_depth = 0

    def normalized_path(value):
        try:
            candidate = os.fspath(value)
        except TypeError:
            return ""
        if isinstance(candidate, bytes):
            candidate = os.fsdecode(candidate)
        return candidate if isinstance(candidate, str) else ""

    def record_filesystem_attempt(api, value):
        candidate = normalized_path(value)
        if candidate.startswith(archive_member_prefixes):
            filesystem_attempts.append((api, candidate))
            return True
        return False

    def deny_archive_member_path_open(path, *args, **kwargs):
        if record_filesystem_attempt("Path.open", path):
            raise AssertionError(
                "prompt registry used a Path(__file__) package-filesystem fallback"
            )
        return original_path_open(path, *args, **kwargs)

    def deny_archive_member_builtin_open(file, *args, **kwargs):
        if record_filesystem_attempt("builtins.open", file):
            raise AssertionError(
                "prompt registry used an open(__file__) package-filesystem fallback"
            )
        return original_builtin_open(file, *args, **kwargs)

    def deny_archive_member_io_open(file, *args, **kwargs):
        if record_filesystem_attempt("io.open", file):
            raise AssertionError(
                "prompt registry used an io.open(__file__) package-filesystem fallback"
            )
        return original_io_open(file, *args, **kwargs)

    def deny_archive_member_os_open(file, *args, **kwargs):
        if record_filesystem_attempt("os.open", file):
            raise AssertionError(
                "prompt registry used an os.open(__file__) package-filesystem fallback"
            )
        return original_os_open(file, *args, **kwargs)

    def audit_archive_member_open(event, args):
        if event == "open" and args:
            record_filesystem_attempt("audit.open", args[0])

    def tracked_zipfile_open(archive, member, *args, **kwargs):
        member_name = getattr(member, "filename", member)
        if (
            load_in_progress
            and traversable_read_depth == 0
            and isinstance(member_name, str)
            and (
                member_name == "agentforge/agents/prompts/registry.v1.json"
                or (
                    member_name.startswith("agentforge/agents/prompts/v1/")
                    and member_name.endswith(".txt")
                )
            )
        ):
            manual_zip_attempts.append(member_name)
        return original_zipfile_open(archive, member, *args, **kwargs)

    class TrackedTraversable:
        def __init__(self, wrapped, relative=""):
            self._wrapped = wrapped
            self._relative = relative

        @property
        def name(self):
            return self._wrapped.name

        def is_dir(self):
            return self._wrapped.is_dir()

        def is_file(self):
            return self._wrapped.is_file()

        def iterdir(self):
            for child in self._wrapped.iterdir():
                relative = "/".join(part for part in (self._relative, child.name) if part)
                yield TrackedTraversable(child, relative)

        def joinpath(self, *descendants):
            wrapped = self._wrapped.joinpath(*descendants)
            suffix = "/".join(str(part).strip("/") for part in descendants)
            relative = "/".join(part for part in (self._relative, suffix) if part)
            return TrackedTraversable(wrapped, relative)

        def __truediv__(self, child):
            return self.joinpath(child)

        def open(self, *args, **kwargs):
            global traversable_read_depth
            resource_reads.append(self._relative)
            traversable_read_depth += 1
            try:
                return self._wrapped.open(*args, **kwargs)
            finally:
                traversable_read_depth -= 1

        def read_bytes(self):
            global traversable_read_depth
            resource_reads.append(self._relative)
            traversable_read_depth += 1
            try:
                return self._wrapped.read_bytes()
            finally:
                traversable_read_depth -= 1

        def read_text(self, *args, **kwargs):
            global traversable_read_depth
            resource_reads.append(self._relative)
            traversable_read_depth += 1
            try:
                return self._wrapped.read_text(*args, **kwargs)
            finally:
                traversable_read_depth -= 1

    def tracked_resource_files(*args, **kwargs):
        root = original_resource_files(*args, **kwargs)
        if not load_in_progress:
            return root
        anchor = args[0] if args else kwargs.get("anchor", kwargs.get("package"))
        anchor_name = getattr(anchor, "__name__", anchor)
        resource_files_calls.append(anchor_name)
        if anchor_name == "agentforge.agents.prompts":
            return TrackedTraversable(root)
        return root

    Path.open = deny_archive_member_path_open
    builtins.open = deny_archive_member_builtin_open
    io.open = deny_archive_member_io_open
    os.open = deny_archive_member_os_open
    zipfile.ZipFile.open = tracked_zipfile_open
    importlib.resources.files = tracked_resource_files
    sys.addaudithook(audit_archive_member_open)

import agentforge.agents.prompts as prompts

module_path = str(prompts.__file__)
resource_root = (
    original_resource_files(prompts)
    if probe_mode == "zip"
    else importlib.resources.files(prompts)
)
if probe_mode == "zip":
    assert module_path.startswith(archive_member_prefixes)
    assert not Path(module_path).exists()
    assert type(resource_root).__module__.startswith("zipfile")
    assert resource_root.joinpath("registry.v1.json").is_file()

if probe_mode == "zip":
    resource_files_calls.clear()
    resource_reads.clear()
    load_in_progress = True
try:
    records = prompts.load_prompt_registry()
finally:
    if probe_mode == "zip":
        load_in_progress = False
for record in records:
    assert prompts.prompt_for_identity(record.role, record.version, record.sha256) == record
if probe_mode == "zip":
    assert "agentforge.agents.prompts" in resource_files_calls, (
        "load_prompt_registry() did not call importlib.resources.files for its package"
    )
    expected_resource_reads = {
        "registry.v1.json",
        "v1/orchestrator.txt",
        "v1/red_team.txt",
        "v1/judge.txt",
        "v1/documentation.txt",
    }
    assert expected_resource_reads.issubset(set(resource_reads)), (
        "load_prompt_registry() did not read every authority byte through the traversable: "
        f"{resource_reads!r}"
    )
    assert manual_zip_attempts == [], (
        "prompt registry bypassed the traversable with manual ZipFile member reads: "
        f"{manual_zip_attempts!r}"
    )
    assert filesystem_attempts == [], (
        f"prompt registry attempted package-filesystem access: {filesystem_attempts!r}"
    )
print(json.dumps({
    "module": module_path,
    "resource_backend": type(resource_root).__module__,
    "zip_backed": probe_mode == "zip",
    "records": [
        {
            "role": record.role,
            "version": record.version,
            "sha256": record.sha256,
            "content": base64.b64encode(record.content.encode("utf-8")).decode("ascii"),
        }
        for record in records
    ],
}, sort_keys=True))
"""
    probe_environment = os.environ.copy()
    probe_environment.update(
        {
            "AGENTFORGE_PROMPTS_DIR": str(decoy_root),
            "AGENTFORGE_PROMPT_DIR": str(decoy_root),
            "PYTHONNOUSERSITE": "1",
        }
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    loaded = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(install_root), "installed"],
        cwd=outside,
        env=probe_environment,
        capture_output=True,
        text=True,
    )
    assert loaded.returncode == 0, (
        f"installed prompt registry failed outside the repo:\n{loaded.stdout}\n{loaded.stderr}"
    )

    payload = json.loads(loaded.stdout)
    assert Path(payload["module"]).is_relative_to(install_root)
    assert payload["zip_backed"] is False

    zip_loaded = subprocess.run(
        [sys.executable, "-I", "-c", probe, str(wheel_path), "zip"],
        cwd=outside,
        env=probe_environment,
        capture_output=True,
        text=True,
    )
    assert zip_loaded.returncode == 0, (
        "zip-backed prompt registry failed direct-from-wheel package-resource resolution:\n"
        f"{zip_loaded.stdout}\n{zip_loaded.stderr}"
    )
    zip_payload = json.loads(zip_loaded.stdout)
    assert zip_payload["zip_backed"] is True
    assert zip_payload["resource_backend"].startswith("zipfile")
    zip_archive_path = zip_payload["module"].split("/agentforge/", 1)[0]
    assert Path(zip_archive_path).resolve() == wheel_path.resolve()

    manifest_by_role = {entry["role"]: entry for entry in manifest["prompts"]}
    for probe_payload in (payload, zip_payload):
        assert tuple(record["role"] for record in probe_payload["records"]) == roles
        for record in probe_payload["records"]:
            raw = base64.b64decode(record["content"], validate=True)
            role = record["role"]
            assert raw == packaged_bytes[role]
            assert b"DECOY-FILESYSTEM-FALLBACK" not in raw
            assert record["version"] == manifest_by_role[role]["version"]
            assert record["sha256"] == manifest_by_role[role]["sha256"]
            assert record["sha256"] == hashlib.sha256(raw).hexdigest()
