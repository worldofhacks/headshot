"""Contract tests for the fail-closed local gate wrapper and its evidence report."""

from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SWARM_FILES = (
    "run-local-gates.sh",
    "spec-lint.sh",
    "check-import-cycles.py",
)
REPORT_PUBLISHER: Final = "publish-report.py"
FORMAT_COMMAND: Final = ".venv/bin/ruff format --check ."
LINT_COMMAND: Final = ".venv/bin/ruff check ."
TYPECHECK_COMMAND: Final = ".venv/bin/mypy --config-file pyproject.toml src tests"
SECRET_SCAN_COMMAND: Final = "bash scripts/secret_scan.sh"
COVERAGE_ADAPTER: Final = "pytest-cov"
OUTPUT_LIMIT: Final = 16_384
APPROVAL_TRUST_PATH: Final = ".tdd-swarm/coverage-approval-trust.json"


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def _write_ticket(repository: Path) -> None:
    ticket = repository / "tickets" / "T-F00.md"
    ticket.parent.mkdir(parents=True)
    ticket.write_text(
        "---\nid: T-F00\nfile_scopes:\n"
        "  - src/agentforge/alpha.py\n"
        "test_scopes:\n"
        "  - tests/swarm/test_secondary.py\n"
        "  - tests/swarm/test_fixture.py\n"
        "---\n\n"
        "## Acceptance Criteria\n- **AC-1**: Fixture.\n"
        "- **AC-2**: Fixture.\n- **AC-3**: Fixture.\n"
        "- **AC-4**: Fixture.\n- **AC-5**: Fixture.\n",
        encoding="utf-8",
    )
    test_file = repository / "tests" / "swarm" / "test_fixture.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        'def test_ac_1():\n    """spec(T-F00:AC-1)"""\n\n'
        'def test_ac_2():\n    """spec(T-F00:AC-2)"""\n\n'
        'def test_ac_3():\n    """spec(T-F00:AC-3)"""\n\n'
        'def test_ac_4():\n    """spec(T-F00:AC-4)"""\n\n'
        'def test_ac_5():\n    """spec(T-F00:AC-5)"""\n',
        encoding="utf-8",
    )
    (repository / "tests" / "swarm" / "test_secondary.py").write_text(
        'def test_secondary_evidence():\n    """spec(T-F00:AC-5)"""\n',
        encoding="utf-8",
    )


def _write_gate_map(repository: Path, *, lint_fails: bool = False) -> None:
    (repository / ".tdd-swarm").mkdir(parents=True, exist_ok=True)
    lint_failure = repository / ".tdd-swarm" / "fixture-lint-fails"
    if lint_fails:
        lint_failure.write_text("yes\n", encoding="utf-8")
    elif lint_failure.exists():
        lint_failure.unlink()
    (repository / ".tdd-swarm" / "gates.md").write_text(
        "# Fixture gate mapping\n\n"
        "| gate | exact command | current status |\n"
        "|---|---|---|\n"
        f"| format | {FORMAT_COMMAND} | AVAILABLE |\n"
        f"| lint | {LINT_COMMAND} | AVAILABLE |\n"
        f"| typecheck | {TYPECHECK_COMMAND} | AVAILABLE |\n",
        encoding="utf-8",
    )


def _approval_paths(repository: Path) -> dict[str, Path]:
    prefix = repository.parent / f".{repository.name}-coverage-approval"
    return {
        "record": prefix.with_suffix(".json"),
        "signature": prefix.with_suffix(".sig"),
        "private_key": prefix.with_suffix(".private.pem"),
        "public_key": prefix.with_suffix(".public.pem"),
    }


def _ensure_approval_keypair(repository: Path) -> dict[str, Path]:
    paths = _approval_paths(repository)
    if paths["private_key"].exists():
        return paths
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(paths["private_key"]),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(paths["private_key"]),
            "-pubout",
            "-out",
            str(paths["public_key"]),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return paths


def _write_signed_approval(
    repository: Path,
    *,
    policy_sha256: str | None = None,
    commit_sha: str | None = None,
    approver_id: str = "owner:headshot",
) -> None:
    paths = _ensure_approval_keypair(repository)
    policy = repository / ".tdd-swarm" / "coverage-policy.md"
    payload = {
        "schema_version": 1,
        "policy_sha256": policy_sha256 or hashlib.sha256(policy.read_bytes()).hexdigest(),
        "commit_sha": commit_sha
        or _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip(),
        "approver_id": approver_id,
    }
    paths["record"].write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(paths["private_key"]),
            "-in",
            str(paths["record"]),
            "-out",
            str(paths["signature"]),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _write_policy(repository: Path, content: str) -> Path:
    policy = repository / ".tdd-swarm" / "coverage-policy.md"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text(content, encoding="utf-8")
    if "decision: non-applicable" in content and (repository / ".git").exists():
        _write_signed_approval(repository)
    return policy


def _approved_non_applicable_policy(*, expiry: str = "2999-01-01") -> str:
    return (
        "# Coverage policy\n\n"
        "decision: non-applicable\n"
        "reason: This fixture contains shell gate orchestration only.\n"
        "approver: Headshot Owner\n"
        "date: 2026-07-24\n"
        f"expiry: {expiry}\n"
    )


def _executable_policy(*, base: str, baseline: float) -> str:
    return (
        "# Coverage policy\n\n"
        "decision: executable\n"
        f"coverage-adapter: {COVERAGE_ADAPTER}\n"
        f"baseline-base-sha: {base}\n"
        f"baseline-percent: {baseline:.2f}\n"
    )


def _write_coverage_output(repository: Path, output: str) -> None:
    (repository / ".tdd-swarm" / "fixture-coverage-output").write_text(
        output,
        encoding="utf-8",
    )


def _write_import_checker(repository: Path, output: str) -> None:
    checker = repository / ".tdd-swarm" / "check-import-cycles.py"
    checker.write_text(
        f"#!/usr/bin/env python3\nprint({output!r}, end='')\n",
        encoding="utf-8",
    )
    checker.chmod(0o755)
    _run(["git", "add", ".tdd-swarm/check-import-cycles.py"], cwd=repository)
    _run(["git", "commit", "-qm", "fixture import checker output"], cwd=repository)


def _install_gate_shims(repository: Path) -> None:
    executable_directory = repository / ".venv" / "bin"
    executable_directory.mkdir(parents=True)
    interpreter = executable_directory / "python"
    interpreter.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    interpreter.chmod(0o755)
    ruff = executable_directory / "ruff"
    ruff.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import sys\n"
        "args = sys.argv[1:]\n"
        "if args == ['format', '--check', '.']:\n"
        "    print('format-before', end='')\n"
        "    Path('gate-order.log').open('a').write('1')\n"
        "elif args == ['check', '.']:\n"
        "    Path('gate-order.log').open('a').write('2')\n"
        "    if Path('.tdd-swarm/fixture-lint-fails').exists():\n"
        "        print('lint-failed', file=sys.stderr, end='')\n"
        "        raise SystemExit(7)\n"
        "    print('lint-ok', end='')\n"
        "else:\n"
        "    raise SystemExit(64)\n",
        encoding="utf-8",
    )
    ruff.chmod(0o755)
    mypy = executable_directory / "mypy"
    mypy.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "import sys\n"
        "if sys.argv[1:] != ['--config-file', 'pyproject.toml', 'src', 'tests']:\n"
        "    raise SystemExit(64)\n"
        "print('typecheck-after', end='')\n"
        "Path('gate-order.log').open('a').write('3')\n",
        encoding="utf-8",
    )
    mypy.chmod(0o755)
    pytest = executable_directory / "pytest"
    pytest.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "print(Path('.tdd-swarm/fixture-coverage-output').read_text(), end='')\n",
        encoding="utf-8",
    )
    pytest.chmod(0o755)


def _install_swarm_tools(repository: Path) -> None:
    for filename in SWARM_FILES:
        source = REPOSITORY_ROOT / ".tdd-swarm" / filename
        assert source.is_file(), f"spec(T-F00:AC-3) requires {filename}"
        destination = repository / ".tdd-swarm" / filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    publisher = REPOSITORY_ROOT / ".tdd-swarm" / REPORT_PUBLISHER
    if publisher.is_file():
        shutil.copy2(publisher, repository / ".tdd-swarm" / REPORT_PUBLISHER)


def _commit_fixture(repository: Path) -> str:
    _run(["git", "init", "-q"], cwd=repository)
    _run(["git", "config", "user.email", "swarm@example.test"], cwd=repository)
    _run(["git", "config", "user.name", "TDD Swarm"], cwd=repository)
    _run(["git", "add", "."], cwd=repository)
    _run(["git", "commit", "-qm", "fixture"], cwd=repository)
    return _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip()


def _commit_head_change(repository: Path) -> str:
    marker = repository / "head-marker.txt"
    marker.write_text("distinct head\n", encoding="utf-8")
    _run(["git", "add", "head-marker.txt"], cwd=repository)
    _run(["git", "commit", "-qm", "distinct head"], cwd=repository)
    return _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip()


def _wrapper_environment(
    repository: Path,
    *,
    extra_environment: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = os.environ.copy()
    approval_paths = _approval_paths(repository)
    if approval_paths["record"].exists():
        environment["TDD_SWARM_COVERAGE_APPROVAL_FILE"] = str(approval_paths["record"])
    if approval_paths["signature"].exists():
        environment["TDD_SWARM_COVERAGE_APPROVAL_SIGNATURE_FILE"] = str(approval_paths["signature"])
    if approval_paths["public_key"].exists():
        environment["TDD_SWARM_COVERAGE_APPROVAL_PUBLIC_KEY_FILE"] = str(
            approval_paths["public_key"]
        )
        environment["TDD_SWARM_COVERAGE_APPROVER_IDS"] = "owner:headshot"
    if extra_environment:
        environment.update(extra_environment)
    return environment


def _run_wrapper(
    repository: Path,
    base: str,
    *,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", ".tdd-swarm/run-local-gates.sh", "tickets/T-F00.md", base],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        env=_wrapper_environment(repository, extra_environment=extra_environment),
        timeout=8,
    )


def _run_wrapper_with_test_deadline(
    repository: Path,
    base: str,
    *,
    deadline_seconds: float,
    extra_environment: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], float, bool]:
    started = time.monotonic()
    process = subprocess.Popen(
        ["bash", ".tdd-swarm/run-local-gates.sh", "tickets/T-F00.md", base],
        cwd=repository,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_wrapper_environment(repository, extra_environment=extra_environment),
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=deadline_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    elapsed = time.monotonic() - started
    return (
        subprocess.CompletedProcess(
            process.args,
            process.returncode,
            stdout=stdout,
            stderr=stderr,
        ),
        elapsed,
        timed_out,
    )


def _start_wrapper_at_failpoint(
    repository: Path,
    base: str,
    *,
    failpoint: str,
    ready_file: Path,
    continue_file: Path,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.Popen[str]:
    environment = _wrapper_environment(
        repository,
        extra_environment=extra_environment,
    )
    environment.update(
        {
            "TDD_SWARM_TEST_FAILPOINT": failpoint,
            "TDD_SWARM_TEST_FAILPOINT_READY_FILE": str(ready_file),
            "TDD_SWARM_TEST_FAILPOINT_CONTINUE_FILE": str(continue_file),
        }
    )
    return subprocess.Popen(
        ["bash", ".tdd-swarm/run-local-gates.sh", "tickets/T-F00.md", base],
        cwd=repository,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        start_new_session=True,
    )


def _terminate_process_group(process: subprocess.Popen[str]) -> tuple[str, str]:
    if process.poll() is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    try:
        return process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        return process.communicate()


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _poll_until(predicate: Callable[[], bool], *, deadline_seconds: float) -> bool:
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _file_state(path: Path) -> tuple[int, int, int, int, int, int]:
    status = path.lstat()
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _write_single_gate_map(
    repository: Path, gate: str, command: str, status: str = "AVAILABLE"
) -> None:
    (repository / ".tdd-swarm" / "gates.md").write_text(
        "# Fixture gate mapping\n\n"
        "| gate | exact command | current status |\n"
        "|---|---|---|\n"
        f"| {gate} | {command} | {status} |\n",
        encoding="utf-8",
    )


def _write_secret_scan(repository: Path, body: str) -> None:
    script = repository / "scripts" / "secret_scan.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
    if (repository / ".git").exists():
        _run(["git", "add", "scripts/secret_scan.sh"], cwd=repository)
        staged = subprocess.run(
            ["git", "diff", "--cached", "--quiet", "--", "scripts/secret_scan.sh"],
            cwd=repository,
            check=False,
        )
        if staged.returncode == 1:
            _run(["git", "commit", "-qm", "fixture secret-scan behavior"], cwd=repository)
        else:
            assert staged.returncode == 0
        policy = repository / ".tdd-swarm" / "coverage-policy.md"
        if policy.exists() and "decision: non-applicable" in policy.read_text(encoding="utf-8"):
            _write_signed_approval(repository)


def _report(repository: Path) -> str:
    return (repository / ".tdd-swarm" / "reports" / "T-F00-gates.md").read_text(encoding="utf-8")


def _prepare_fixture(repository: Path) -> str:
    _install_swarm_tools(repository)
    _install_gate_shims(repository)
    _write_ticket(repository)
    _write_gate_map(repository)
    _write_secret_scan(repository, "printf 'secret-scan-ok\\n'\n")
    package = repository / "src" / "agentforge"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "alpha.py").write_text("import agentforge.beta\n", encoding="utf-8")
    (package / "beta.py").write_text("", encoding="utf-8")
    approval_paths = _ensure_approval_keypair(repository)
    (repository / APPROVAL_TRUST_PATH).write_text(
        json.dumps(
            {
                "owner:headshot": hashlib.sha256(
                    approval_paths["public_key"].read_bytes()
                ).hexdigest()
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return _commit_fixture(repository)


def _canonical_test_scope_hash(repository: Path, paths: tuple[str, ...]) -> str:
    """Hash sorted length-prefixed UTF-8 paths and length-prefixed raw file bytes."""
    return _test_scope_hash_in_order(repository, tuple(sorted(paths)))


def _test_scope_hash_in_order(repository: Path, paths: tuple[str, ...]) -> str:
    payload = bytearray()
    for relative_path in paths:
        path_bytes = relative_path.encode("utf-8")
        file_bytes = (repository / relative_path).read_bytes()
        payload.extend(len(path_bytes).to_bytes(4, "big"))
        payload.extend(path_bytes)
        payload.extend(len(file_bytes).to_bytes(8, "big"))
        payload.extend(file_bytes)
    return hashlib.sha256(payload).hexdigest()


def _canonical_import_graph_hash(repository: Path) -> str:
    edges: set[tuple[str, str]] = set()
    source_root = repository / "src"
    for source_file in sorted(source_root.rglob("*.py")):
        source_module = ".".join(source_file.relative_to(source_root).with_suffix("").parts)
        for node in ast.walk(ast.parse(source_file.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("agentforge."):
                        edges.add((source_module, alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module == "agentforge":
                for alias in node.names:
                    edges.add((source_module, f"agentforge.{alias.name}"))
    canonical = "".join(f"{source} -> {target}\n" for source, target in sorted(edges))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _assert_report_row(report: str, gate: str, command: str, exit_code: int, output: str) -> None:
    expected = f"| {gate} | `{command}` | {exit_code} | {output} |"
    assert expected in report


def _assert_base_sha_diagnostic(output: str) -> None:
    normalized = output.lower().replace("_", "-").replace(" ", "-")
    assert "base-sha" in normalized


def test_wrapper_rejects_a_truly_absent_coverage_policy(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — an absent coverage policy fails closed with exit 1."""
    base = _prepare_fixture(tmp_path)

    missing = _run_wrapper(tmp_path, base)

    assert missing.returncode == 1
    assert "coverage-policy" in (missing.stdout + missing.stderr).lower()


def test_wrapper_rejects_each_incomplete_non_applicable_waiver(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — reason, approver, date, and expiry are independently mandatory."""
    required_fields = ("reason", "approver", "date", "expiry")
    for missing_field in required_fields:
        case = tmp_path / missing_field
        base = _prepare_fixture(case)
        lines = _approved_non_applicable_policy().splitlines()
        incomplete = "\n".join(line for line in lines if not line.startswith(f"{missing_field}:"))
        _write_policy(case, incomplete + "\n")

        result = _run_wrapper(case, base)

        assert result.returncode == 1
        assert missing_field in (result.stdout + result.stderr).lower()


def test_wrapper_rejects_an_expired_non_applicable_waiver(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — an otherwise complete owner waiver fails after its expiry."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy(expiry="2000-01-01"))

    expired = _run_wrapper(tmp_path, base)

    assert expired.returncode == 1
    assert "expired" in (expired.stdout + expired.stderr).lower()


def test_wrapper_accepts_a_complete_unexpired_non_applicable_waiver(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — a complete current owner approval is the only waiver path."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr


def test_wrapper_accepts_executable_coverage_at_its_base_sha_baseline(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — executable coverage bound to the supplied base may meet baseline."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=97.25\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=97.25))

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "coverage=97.25" in result.stdout + result.stderr


def test_wrapper_rejects_executable_coverage_without_a_baseline_base_sha(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — executable coverage fails closed without its base-SHA binding."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=97.25\n")
    complete = _executable_policy(base=base, baseline=97.25)
    missing_binding = "\n".join(
        line for line in complete.splitlines() if not line.startswith("baseline-base-sha:")
    )
    _write_policy(tmp_path, missing_binding + "\n")

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 1
    _assert_base_sha_diagnostic(result.stdout + result.stderr)


def test_wrapper_rejects_a_coverage_baseline_bound_to_a_different_commit(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-3) — policy base SHA must equal the wrapper's diff-base commit."""
    base = _prepare_fixture(tmp_path)
    different_commit = _commit_head_change(tmp_path)
    assert different_commit != base
    _write_policy(
        tmp_path,
        _executable_policy(base=different_commit, baseline=97.25),
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 1
    output = result.stdout + result.stderr
    _assert_base_sha_diagnostic(output)
    assert "match" in output.lower()


def test_wrapper_rejects_executable_coverage_regression(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — observed coverage below the base-SHA baseline fails closed."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=96.50\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=97.25))

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert "regression" in output.lower()
    assert "96.50" in output
    assert "97.25" in output


def test_wrapper_preserves_failure_output_and_runs_all_mapped_gate_rows(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — one failed gate cannot hide later commands or their report rows."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_gate_map(tmp_path, lint_fails=True)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "format-before" in output
    assert "lint-failed" in output
    assert "typecheck-after" in output
    assert (tmp_path / "gate-order.log").read_text(encoding="utf-8") == "123"
    report = (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").read_text(encoding="utf-8")
    _assert_report_row(report, "format", FORMAT_COMMAND, 0, "format-before")
    _assert_report_row(report, "lint", LINT_COMMAND, 7, "lint-failed")
    _assert_report_row(report, "typecheck", TYPECHECK_COMMAND, 0, "typecheck-after")
    assert (
        report.index("format-before")
        < report.index("lint-failed")
        < report.index("typecheck-after")
    )


def test_wrapper_writes_a_hash_bound_report_when_all_gates_are_green(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — a green run records immutable identifiers, commands, exits, and hashes."""
    base = _prepare_fixture(tmp_path)
    policy = _write_policy(tmp_path, _approved_non_applicable_policy())
    head = _commit_head_change(tmp_path)
    _write_signed_approval(tmp_path)
    expected_import_hash = _canonical_import_graph_hash(tmp_path)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    report = (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").read_text(encoding="utf-8")
    assert base != head
    assert "ticket: tickets/T-F00.md" in report
    assert f"base: {base}" in report
    assert f"head: {head}" in report
    _assert_report_row(report, "format", FORMAT_COMMAND, 0, "format-before")
    _assert_report_row(report, "lint", LINT_COMMAND, 0, "lint-ok")
    _assert_report_row(report, "typecheck", TYPECHECK_COMMAND, 0, "typecheck-after")
    assert f"coverage-policy-sha256: {hashlib.sha256(policy.read_bytes()).hexdigest()}" in report
    assert f"import-graph-sha256: {expected_import_hash}" in report


def test_wrapper_rejects_an_arbitrary_gate_executable_without_running_it(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — gate rows select fixed IDs/argv, never arbitrary executables."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    marker = tmp_path / "arbitrary-executable-ran"
    executable = tmp_path / "scripts" / "arbitrary-gate"
    executable.parent.mkdir(exist_ok=True)
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "Path('arbitrary-executable-ran').write_text('unsafe')\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    _write_single_gate_map(tmp_path, "secret-scan", "scripts/arbitrary-gate")

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    output = (result.stdout + result.stderr).lower()
    assert "fixed" in output or "sanctioned" in output or "authority" in output


def test_wrapper_rejects_mutated_arguments_of_a_sanctioned_gate_without_running_it(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-4) — even a sanctioned executable cannot receive map-supplied argv."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    marker = tmp_path / "mutated-argument-ran"
    _write_secret_scan(tmp_path, "printf unsafe > mutated-argument-ran\n")
    _write_single_gate_map(
        tmp_path,
        "secret-scan",
        f"{SECRET_SCAN_COMMAND} --policy-supplied-argument",
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    output = (result.stdout + result.stderr).lower()
    assert "argument" in output or "fixed" in output or "sanctioned" in output


def test_wrapper_binds_each_sanctioned_vector_to_its_exact_gate_id(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — a valid vector under the wrong valid gate ID is never executed."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    marker = tmp_path / "wrong-gate-id-ran"
    _write_secret_scan(tmp_path, "printf unsafe > wrong-gate-id-ran\n")
    _write_single_gate_map(tmp_path, "lint", SECRET_SCAN_COMMAND)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    output = (result.stdout + result.stderr).lower()
    assert "gate" in output and ("fixed" in output or "sanctioned" in output or "mapping" in output)


def test_wrapper_rejects_an_unsanctioned_shell_vector_without_running_it(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-4) — an unsanctioned sh -c vector is rejected before execution."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    marker = tmp_path / "shell-ran"
    _write_single_gate_map(tmp_path, "lint", "sh -c 'printf unsafe > shell-ran'")

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    assert "shell" in (result.stdout + result.stderr).lower()


def test_wrapper_rejects_an_unknown_marker_writing_coverage_adapter(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-3) — coverage adapter IDs are allowlisted and never executable paths."""
    base = _prepare_fixture(tmp_path)
    marker = tmp_path / "unknown-coverage-adapter-ran"
    adapter = tmp_path / "scripts" / "marker-coverage-adapter"
    adapter.parent.mkdir(exist_ok=True)
    adapter.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        "Path('unknown-coverage-adapter-ran').write_text('unsafe')\n"
        "print('coverage=100')\n",
        encoding="utf-8",
    )
    adapter.chmod(0o755)
    _run(["git", "add", "scripts/marker-coverage-adapter"], cwd=tmp_path)
    _run(["git", "commit", "-qm", "fixture unknown coverage adapter"], cwd=tmp_path)
    _write_policy(
        tmp_path,
        "# Coverage policy\n\n"
        "decision: executable\n"
        "coverage-adapter: scripts/marker-coverage-adapter\n"
        f"baseline-base-sha: {base}\n"
        "baseline-percent: 99\n",
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    assert "coverage" in (result.stdout + result.stderr).lower()


def test_wrapper_rejects_an_arbitrary_coverage_command_without_running_it(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — coverage uses a fixed adapter rather than policy-supplied code."""
    base = _prepare_fixture(tmp_path)
    marker = tmp_path / "coverage-shell-ran"
    _write_policy(
        tmp_path,
        "# Coverage policy\n\n"
        "decision: executable\n"
        f"coverage-adapter: {COVERAGE_ADAPTER}\n"
        "coverage-command: sh -c 'printf coverage=100; touch coverage-shell-ran'\n"
        f"baseline-base-sha: {base}\n"
        "baseline-percent: 99\n",
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    assert "coverage" in (result.stdout + result.stderr).lower()


def test_repository_gate_map_enumerates_every_tier_one_gate_and_skip_reason() -> None:
    """spec(T-F00:AC-4) — every Tier-1 gate is executable or explicitly non-green with a reason."""
    gate_map = (REPOSITORY_ROOT / ".tdd-swarm" / "gates.md").read_text(encoding="utf-8")
    rows = {
        cells[0].lower(): cells
        for line in gate_map.splitlines()
        if line.strip().startswith("|")
        and len(cells := [cell.strip() for cell in line.strip().split("|")[1:-1]]) == 3
        and cells[0].lower() not in {"gate", "---"}
    }
    required = {
        "format",
        "lint",
        "typecheck",
        "unit",
        "new-tests",
        "coverage",
        "no-todos",
        "no-debug-logging",
        "docs",
        "reachability",
        "spec-lint",
    }

    assert required <= rows.keys(), f"missing Tier-1 gates: {sorted(required - rows.keys())}"
    for gate in required:
        command, status = rows[gate][1:]
        if status != "AVAILABLE":
            assert status in {"SKIPPED", "BLOCKED"}
            assert command.startswith("reason=") and len(command) > len("reason=")


def test_wrapper_retains_a_skipped_gate_reason_and_cannot_report_green(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — a declared non-runnable local gate is visible and non-green."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_secret_scan(tmp_path, "printf 'secret-scan-ok\\n'\n")
    (tmp_path / ".tdd-swarm" / "gates.md").write_text(
        "# Fixture gate mapping\n\n"
        "| gate | exact command | current status |\n"
        "|---|---|---|\n"
        "| secret-scan | bash scripts/secret_scan.sh | AVAILABLE |\n"
        "| typecheck | reason=no configured type checker | SKIPPED |\n",
        encoding="utf-8",
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    report = _report(tmp_path)
    assert "typecheck" in report
    assert "SKIPPED" in report
    assert "no configured type checker" in report
    assert "overall-verdict: FAIL" in report


def test_wrapper_deadline_kills_the_entire_gate_process_group(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — deadline expiry terminates descendants and records a failed gate."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_secret_scan(
        tmp_path,
        "python3 - <<'PY' &\n"
        "import os\nimport time\nfrom pathlib import Path\n"
        "time.sleep(0.7)\nPath('orphan-marker').write_text('alive')\n"
        "PY\n"
        "printf '%s' \"$!\" > child.pid\n"
        "sleep 2\n",
    )
    _write_single_gate_map(tmp_path, "secret-scan", SECRET_SCAN_COMMAND)

    result, _, hit_test_deadline = _run_wrapper_with_test_deadline(
        tmp_path,
        base,
        deadline_seconds=4,
        extra_environment={"TDD_SWARM_GATE_TIMEOUT_SECONDS": "0.20"},
    )

    assert not hit_test_deadline, "wrapper ignored its much shorter configured gate deadline"
    assert result.returncode != 0
    child_pid = int((tmp_path / "child.pid").read_text(encoding="utf-8"))
    assert _poll_until(
        lambda: (tmp_path / "orphan-marker").exists() or not _pid_exists(child_pid),
        deadline_seconds=3,
    )
    assert not (tmp_path / "orphan-marker").exists()
    assert not _pid_exists(child_pid)
    assert "timeout" in _report(tmp_path).lower()


def test_wrapper_output_budget_terminates_a_continuously_noisy_process_group(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-4) — exceeding the byte cap terminates, rather than drains, the producer."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_secret_scan(
        tmp_path,
        "printf '%s' \"$$\" > noisy-group.pid\n"
        "python3 - <<'PY' &\n"
        "import time\nfrom pathlib import Path\n"
        "time.sleep(0.8)\nPath('output-limit-orphan').write_text('alive')\n"
        "PY\n"
        "exec python3 -u - <<'PY'\n"
        "import os\n"
        "block = b'x' * 4096\n"
        "while True:\n"
        "    os.write(1, block)\n"
        "PY\n",
    )
    _write_single_gate_map(tmp_path, "secret-scan", SECRET_SCAN_COMMAND)

    result, _, hit_test_deadline = _run_wrapper_with_test_deadline(
        tmp_path,
        base,
        deadline_seconds=3,
    )
    group_file = tmp_path / "noisy-group.pid"
    noisy_group = int(group_file.read_text(encoding="utf-8")) if group_file.exists() else None
    if hit_test_deadline and noisy_group is not None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(noisy_group, signal.SIGKILL)

    assert not hit_test_deadline, (
        "wrapper drained an unbounded producer instead of enforcing the byte cap"
    )

    assert result.returncode != 0
    report = _report(tmp_path)
    assert len(report.encode()) < 32_768
    assert "truncated" in report.lower() or "output limit" in report.lower()
    assert "overall-verdict: FAIL" in report
    assert _poll_until(
        lambda: (
            (tmp_path / "output-limit-orphan").exists()
            or noisy_group is None
            or not _pid_exists(noisy_group)
        ),
        deadline_seconds=3,
    )
    assert not (tmp_path / "output-limit-orphan").exists()
    assert noisy_group is not None and not _pid_exists(noisy_group)


def test_wrapper_redacts_console_and_report_output_and_records_a_digest(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — configured and recognized credentials are independently redacted."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    configured_secret = "configured-value-that-is-not-a-known-credential-format"
    known_format_secret = "AKIAIOSFODNN7EXAMPLE"
    raw = f"configured={configured_secret}\nrecognized={known_format_secret}\n"
    _write_secret_scan(
        tmp_path,
        "printf 'configured=%s\\n' \"$FIXTURE_SECRET\"\n"
        f"printf 'recognized=%s\\n' '{known_format_secret}'\n",
    )
    _write_single_gate_map(tmp_path, "secret-scan", SECRET_SCAN_COMMAND)

    result = _run_wrapper(
        tmp_path,
        base,
        extra_environment={"FIXTURE_SECRET": configured_secret},
    )

    console = result.stdout + result.stderr
    report = _report(tmp_path)
    assert configured_secret not in console
    assert configured_secret not in report
    assert known_format_secret not in console
    assert known_format_secret not in report
    assert "[REDACTED]" in console
    assert "[REDACTED]" in report
    assert f"output-sha256: {hashlib.sha256(raw.encode()).hexdigest()}" in report


def test_wrapper_rejects_a_post_commit_mapped_executable_mutation(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — a fixed mapped script must still match its committed bytes."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    marker = tmp_path / "dirty-secret-scan-ran"
    script = tmp_path / "scripts" / "secret_scan.sh"
    script.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\nprintf unsafe > dirty-secret-scan-ran\n",
        encoding="utf-8",
    )
    _write_single_gate_map(tmp_path, "secret-scan", SECRET_SCAN_COMMAND)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    output = (result.stdout + result.stderr).lower()
    assert "secret_scan.sh" in output or "executable" in output or "integrity" in output


def test_wrapper_distinguishes_exact_output_limit_from_one_byte_over(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-4) — exactly 16 KiB passes; the adjacent over-limit case fails."""
    exact = tmp_path / "exact"
    exact_base = _prepare_fixture(exact)
    _write_policy(exact, _approved_non_applicable_policy())
    _write_secret_scan(
        exact,
        f"python3 -c \"import os; os.write(1, b'x' * {OUTPUT_LIMIT})\"\n",
    )
    _write_single_gate_map(exact, "secret-scan", SECRET_SCAN_COMMAND)

    exact_result = _run_wrapper(exact, exact_base)

    assert exact_result.returncode == 0, exact_result.stdout + exact_result.stderr
    exact_report = _report(exact)
    assert "truncated" not in exact_report.lower()
    assert "output limit" not in exact_report.lower()

    over = tmp_path / "over"
    over_base = _prepare_fixture(over)
    _write_policy(over, _approved_non_applicable_policy())
    _write_secret_scan(
        over,
        f"python3 -c \"import os; os.write(1, b'x' * {OUTPUT_LIMIT + 1})\"\n",
    )
    _write_single_gate_map(over, "secret-scan", SECRET_SCAN_COMMAND)

    over_result = _run_wrapper(over, over_base)

    assert over_result.returncode != 0
    over_report = _report(over)
    assert "truncated" in over_report.lower() or "output limit" in over_report.lower()
    assert "overall-verdict: FAIL" in over_report


def test_wrapper_encodes_render_active_and_control_output_canonically(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — HTML, ANSI, and controls are inert and unambiguous in Markdown."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    raw = b"<unsafe>&\x1b[31m\x01\n"
    _write_secret_scan(
        tmp_path,
        "python3 -c \"import os; os.write(1, b'<unsafe>&\\\\x1b[31m\\\\x01\\\\n')\"\n",
    )
    _write_single_gate_map(tmp_path, "secret-scan", SECRET_SCAN_COMMAND)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    report = _report(tmp_path)
    assert "<unsafe>" not in report
    assert "\x1b" not in report
    assert "\x01" not in report
    assert "&lt;unsafe&gt;&amp;&#x1B;[31m&#x01;" in report
    assert f"output-sha256: {hashlib.sha256(raw).hexdigest()}" in report


def test_wrapper_rejects_a_symlinked_report_directory_without_external_write(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — report parent symlinks are rejected before publication."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    outside = tmp_path.parent / f"{tmp_path.name}-outside-reports"
    outside.mkdir()
    (tmp_path / ".tdd-swarm" / "reports").symlink_to(outside, target_is_directory=True)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not (outside / "T-F00-gates.md").exists()
    assert "symlink" in (result.stdout + result.stderr).lower()


def test_wrapper_rejects_a_symlinked_report_destination_without_clobbering_target(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — no-follow atomic publication preserves a symlink target."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    outside = tmp_path.parent / f"{tmp_path.name}-outside-report.md"
    outside.write_text("sentinel\n", encoding="utf-8")
    report_directory = tmp_path / ".tdd-swarm" / "reports"
    report_directory.mkdir()
    (report_directory / "T-F00-gates.md").symlink_to(outside)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert outside.read_text(encoding="utf-8") == "sentinel\n"
    assert "symlink" in (result.stdout + result.stderr).lower()


def test_wrapper_atomically_replaces_a_preexisting_complete_report(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — publication uses a same-directory replacement, never truncation."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    report_directory = tmp_path / ".tdd-swarm" / "reports"
    report_directory.mkdir()
    report_path = report_directory / "T-F00-gates.md"
    report_path.write_text("prior-complete-report\n", encoding="utf-8")
    prior_inode = report_path.stat().st_ino

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    assert report_path.stat().st_ino != prior_inode
    report = report_path.read_text(encoding="utf-8")
    assert report.startswith("# Local gate report — T-F00\n")
    assert "overall-verdict: PASS" in report
    assert "prior-complete-report" not in report


def test_wrapper_killed_before_publication_preserves_the_prior_complete_report(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — failure before atomic publish cannot unlink or partially rewrite."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    report_directory = tmp_path / ".tdd-swarm" / "reports"
    report_directory.mkdir()
    report_path = report_directory / "T-F00-gates.md"
    prior = b"prior-complete-report\n"
    report_path.write_bytes(prior)
    ready = tmp_path / "failpoint-ready"
    resume = tmp_path / "failpoint-continue"
    process = _start_wrapper_at_failpoint(
        tmp_path,
        base,
        failpoint="before-report-publish",
        ready_file=ready,
        continue_file=resume,
    )

    try:
        assert _poll_until(
            lambda: ready.exists() or process.poll() is not None,
            deadline_seconds=3,
        )
        assert ready.exists(), "wrapper did not expose the generic pre-publication failpoint"
        _terminate_process_group(process)
        assert report_path.read_bytes() == prior
    finally:
        if process.poll() is None:
            _terminate_process_group(process)


def test_fixed_report_publisher_uses_only_one_atomic_replace(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — a fresh audit permits only the fixed boundary's one replace."""
    publisher_path = REPOSITORY_ROOT / ".tdd-swarm" / REPORT_PUBLISHER
    assert publisher_path.is_file(), (
        f"fixed report publisher is missing: .tdd-swarm/{REPORT_PUBLISHER}"
    )

    report_directory = tmp_path / "reports"
    report_directory.mkdir()
    report_path = report_directory / "T-F00-gates.md"
    prior = b"prior-complete-report\n"
    report_path.write_bytes(prior)
    staged_path = report_directory / ".T-F00-gates.prepared"
    staged_bytes = (
        b"# Local gate report \xe2\x80\x94 T-F00\n\n"
        b"ticket: tickets/T-F00.md\n"
        b"overall-verdict: PASS\n"
    )
    staged_path.write_bytes(staged_bytes)
    assert staged_path.parent == report_path.parent
    assert staged_path.is_file() and not staged_path.is_symlink()

    marker = tmp_path / "arbitrary-publisher-ran"
    arbitrary_publisher = tmp_path / "arbitrary-publisher.py"
    arbitrary_publisher.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('unsafe', encoding='utf-8')\n",
        encoding="utf-8",
    )
    arbitrary_publisher.chmod(0o755)
    source_before_state = _file_state(staged_path)
    destination_before_state = _file_state(report_path)
    source_before_hash = hashlib.sha256(staged_bytes).hexdigest()
    destination_before_hash = hashlib.sha256(prior).hexdigest()
    audit_harness = tmp_path / "publisher-audit-harness.py"
    audit_result = tmp_path / "publisher-audit-result.json"
    audit_harness.write_text(
        "import hashlib\n"
        "import importlib.util\n"
        "import json\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n"
        "publisher, source, destination, result_path = map(Path, sys.argv[1:])\n"
        "publisher = publisher.resolve()\n"
        "source = source.resolve()\n"
        "destination = destination.resolve()\n"
        "directory = destination.parent\n"
        "directory_stat = directory.stat()\n"
        "directory_identity = (directory_stat.st_dev, directory_stat.st_ino)\n"
        "phase = 'import'\n"
        "security_events = []\n"
        "replace_calls = []\n"
        "def state(path):\n"
        "    status = path.lstat()\n"
        "    return [status.st_dev, status.st_ino, status.st_mode, status.st_size,\n"
        "            status.st_mtime_ns, status.st_ctime_ns]\n"
        "def digest(path):\n"
        "    return hashlib.sha256(path.read_bytes()).hexdigest()\n"
        "def resolve_at(value, dir_fd=None):\n"
        "    candidate = Path(os.fsdecode(os.fspath(value)))\n"
        "    if candidate.is_absolute() or dir_fd in (None, -1):\n"
        "        return candidate.resolve()\n"
        "    status = os.fstat(dir_fd)\n"
        "    assert (status.st_dev, status.st_ino) == directory_identity\n"
        "    assert candidate.parent == Path('.')\n"
        "    return (directory / candidate).resolve()\n"
        "def deny(event, args):\n"
        "    raise RuntimeError(f'forbidden audit event during {phase}: {event} {args!r}')\n"
        "def audit(event, args):\n"
        "    if phase not in {'import', 'call'}:\n"
        "        return\n"
        "    if event == 'os.rename':\n"
        "        raw_source, raw_destination, source_fd, destination_fd = args\n"
        "        effective_source = resolve_at(raw_source, source_fd)\n"
        "        effective_destination = resolve_at(raw_destination, destination_fd)\n"
        "        entry = {'event': event, 'source': str(effective_source),\n"
        "                 'destination': str(effective_destination)}\n"
        "        security_events.append(entry)\n"
        "        if (phase != 'call' or effective_source != source or\n"
        "                effective_destination != destination or len(security_events) != 1):\n"
        "            deny(event, args)\n"
        "        return\n"
        "    if event == 'open':\n"
        "        _path, mode, flags = args\n"
        "        write_flags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC\n"
        "        if (isinstance(mode, str) and any(flag in mode for flag in 'wax+')) or (\n"
        "                isinstance(flags, int) and flags & write_flags):\n"
        "            deny(event, args)\n"
        "        return\n"
        "    if event.startswith('os.') and event not in {'os.listdir', 'os.scandir'}:\n"
        "        deny(event, args)\n"
        "    if event.startswith(('subprocess.', 'ctypes.', 'cffi.', 'pty.', '_thread.')):\n"
        "        deny(event, args)\n"
        "    if event == 'import' and str(args[0]).split('.')[0] in {\n"
        "            'ctypes', '_ctypes', 'cffi', '_cffi_backend', 'subprocess',\n"
        "            'multiprocessing', 'pty'}:\n"
        "        deny(event, args)\n"
        "    if event in {'sys.addaudithook', 'sys.settrace', 'sys.setprofile'}:\n"
        "        deny(event, args)\n"
        "    if phase == 'call' and event in {'compile', 'exec'}:\n"
        "        deny(event, args)\n"
        "sys.addaudithook(audit)\n"
        "real_replace = os.replace\n"
        "def replace_spy(raw_source, raw_destination, *args, **kwargs):\n"
        "    assert phase == 'call'\n"
        "    assert not args\n"
        "    assert set(kwargs) <= {'src_dir_fd', 'dst_dir_fd'}\n"
        "    effective_source = resolve_at(raw_source, kwargs.get('src_dir_fd'))\n"
        "    effective_destination = resolve_at(raw_destination, kwargs.get('dst_dir_fd'))\n"
        "    assert effective_source == source\n"
        "    assert effective_destination == destination\n"
        "    record = {'source': str(effective_source),\n"
        "              'destination': str(effective_destination),\n"
        "              'source_before_state': state(effective_source),\n"
        "              'destination_before_state': state(effective_destination),\n"
        "              'source_before_hash': digest(effective_source),\n"
        "              'destination_before_hash': digest(effective_destination)}\n"
        "    real_replace(raw_source, raw_destination, *args, **kwargs)\n"
        "    record.update({'source_exists_after': effective_source.exists(),\n"
        "                   'destination_after_state': state(effective_destination),\n"
        "                   'destination_after_hash': digest(effective_destination)})\n"
        "    replace_calls.append(record)\n"
        "os.replace = replace_spy\n"
        "spec = importlib.util.spec_from_file_location('audited_tdd_swarm_publisher', publisher)\n"
        "assert spec is not None and spec.loader is not None\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        "boundary = getattr(module, 'publish_report', None)\n"
        "assert callable(boundary)\n"
        "phase = 'call'\n"
        "boundary(source, destination)\n"
        "assert len(replace_calls) == 1\n"
        "assert security_events == [{'event': 'os.rename', 'source': str(source),\n"
        "                            'destination': str(destination)}]\n"
        "phase = 'done'\n"
        "result_path.write_text(json.dumps({'replace_calls': replace_calls,\n"
        "                                  'security_events': security_events}, sort_keys=True),\n"
        "                       encoding='utf-8')\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "TDD_SWARM_TEST_REPORT_PUBLISHER": str(arbitrary_publisher),
        }
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(audit_harness),
            str(publisher_path),
            str(staged_path),
            str(report_path),
            str(audit_result),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=5,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(audit_result.read_text(encoding="utf-8"))
    destination_after_state = _file_state(report_path)
    assert not marker.exists()
    assert result["security_events"] == [
        {
            "event": "os.rename",
            "source": str(staged_path.resolve()),
            "destination": str(report_path.resolve()),
        }
    ]
    assert result["replace_calls"] == [
        {
            "source": str(staged_path.resolve()),
            "destination": str(report_path.resolve()),
            "source_before_state": list(source_before_state),
            "destination_before_state": list(destination_before_state),
            "source_before_hash": source_before_hash,
            "destination_before_hash": destination_before_hash,
            "source_exists_after": False,
            "destination_after_state": list(destination_after_state),
            "destination_after_hash": source_before_hash,
        }
    ]
    assert not staged_path.exists()
    assert destination_after_state[1] == source_before_state[1]
    assert report_path.read_bytes() == staged_bytes


def test_wrapper_uses_the_fixed_report_publisher_and_ignores_an_env_override(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — ordinary publication cannot select an environment executable."""
    publisher_source = REPOSITORY_ROOT / ".tdd-swarm" / REPORT_PUBLISHER
    assert publisher_source.is_file(), (
        f"fixed report publisher is missing: .tdd-swarm/{REPORT_PUBLISHER}"
    )
    base = _prepare_fixture(tmp_path)
    policy = _write_policy(tmp_path, _approved_non_applicable_policy())
    report_directory = tmp_path / ".tdd-swarm" / "reports"
    report_path = report_directory / "T-F00-gates.md"

    baseline = _run_wrapper(tmp_path, base)

    assert baseline.returncode == 0, baseline.stdout + baseline.stderr
    expected_report = report_path.read_bytes()
    expected_text = expected_report.decode("utf-8")
    assert expected_report.endswith(b"\n")
    assert expected_text.startswith("# Local gate report \u2014 T-F00\n")
    assert expected_text.count("overall-verdict: PASS") == 1
    expected_identities = {
        "ticket": "tickets/T-F00.md",
        "base": base,
        "head": base,
        "coverage-policy-sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
        "import-graph-sha256": _canonical_import_graph_hash(tmp_path),
        "ticket-sha256": hashlib.sha256(
            (tmp_path / "tickets" / "T-F00.md").read_bytes()
        ).hexdigest(),
        "gate-map-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / "gates.md").read_bytes()
        ).hexdigest(),
        "wrapper-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / "run-local-gates.sh").read_bytes()
        ).hexdigest(),
        "publisher-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / REPORT_PUBLISHER).read_bytes()
        ).hexdigest(),
        "spec-lint-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / "spec-lint.sh").read_bytes()
        ).hexdigest(),
        "import-cycle-tool-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / "check-import-cycles.py").read_bytes()
        ).hexdigest(),
        "test-scope-sha256": _canonical_test_scope_hash(
            tmp_path,
            ("tests/swarm/test_secondary.py", "tests/swarm/test_fixture.py"),
        ),
    }
    for label, value in expected_identities.items():
        assert expected_text.count(f"{label}: {value}") == 1
    assert "coverage-decision: non-applicable" in expected_text
    assert "coverage-validation-status: PASS" in expected_text
    _assert_report_row(expected_text, "format", FORMAT_COMMAND, 0, "format-before")
    _assert_report_row(expected_text, "lint", LINT_COMMAND, 0, "lint-ok")
    _assert_report_row(expected_text, "typecheck", TYPECHECK_COMMAND, 0, "typecheck-after")
    assert (
        f"| spec-lint | `bash .tdd-swarm/spec-lint.sh tickets/T-F00.md {base}` | 0 |"
        in expected_text
    )
    assert "| import-cycles | `python3 .tdd-swarm/check-import-cycles.py` | 0 |" in expected_text

    prior = b"prior-complete-report\n"
    report_path.write_bytes(prior)
    marker = tmp_path / "malicious-env-publisher-ran"
    malicious_publisher = tmp_path.parent / f".{tmp_path.name}-malicious-publisher.py"
    malicious_publisher.write_text(
        "#!/usr/bin/env python3\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('unsafe', encoding='utf-8')\n",
        encoding="utf-8",
    )
    malicious_publisher.chmod(0o755)
    ready = tmp_path / "failpoint-ready"
    resume = tmp_path / "failpoint-continue"
    process = _start_wrapper_at_failpoint(
        tmp_path,
        base,
        failpoint="before-report-publish",
        ready_file=ready,
        continue_file=resume,
        extra_environment={"TDD_SWARM_TEST_REPORT_PUBLISHER": str(malicious_publisher)},
    )

    try:
        assert _poll_until(
            lambda: ready.exists() or process.poll() is not None,
            deadline_seconds=3,
        )
        assert ready.exists(), "wrapper did not expose the generic pre-publication failpoint"
        assert report_path.read_bytes() == prior
        destination_before_state = _file_state(report_path)
        staged_candidates = [
            path
            for path in report_directory.iterdir()
            if path != report_path
            and not path.is_symlink()
            and path.is_file()
            and path.read_bytes() == expected_report
        ]
        assert len(staged_candidates) == 1, (
            "pre-publication must expose one complete regular same-directory report"
        )
        staged_path = staged_candidates[0]
        staged_bytes = staged_path.read_bytes()
        staged_state = _file_state(staged_path)
        assert staged_path.parent == report_directory
        assert not staged_path.is_symlink()
        assert staged_path.is_file()

        resume.touch()
        try:
            stdout, stderr = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            stdout, stderr = _terminate_process_group(process)
            raise AssertionError("wrapper did not leave the report precommit boundary") from None
    finally:
        if process.poll() is None:
            _terminate_process_group(process)

    assert process.returncode == 0, stdout + stderr
    published_state = _file_state(report_path)
    assert destination_before_state[1] != staged_state[1]
    assert published_state[1] == staged_state[1]
    assert report_path.read_bytes() == staged_bytes
    assert not staged_path.exists()
    assert not marker.exists()

    trap_nonce = os.urandom(16).hex()
    trap_sentinel = 73
    trap_record = tmp_path.parent / f".{tmp_path.name}-{trap_nonce}.jsonl"
    fixture_publisher = tmp_path / ".tdd-swarm" / REPORT_PUBLISHER
    fixture_publisher.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        f"record = Path({str(trap_record)!r})\n"
        f"payload = {{'nonce': {trap_nonce!r}, 'argv': sys.argv[1:]}}\n"
        "with record.open('a', encoding='utf-8') as stream:\n"
        "    stream.write(json.dumps(payload, sort_keys=True) + '\\n')\n"
        f"raise SystemExit({trap_sentinel})\n",
        encoding="utf-8",
    )
    fixture_publisher.chmod(0o755)
    _run(["git", "add", f".tdd-swarm/{REPORT_PUBLISHER}"], cwd=tmp_path)
    _run(["git", "commit", "-qm", "fixture fixed publisher trap"], cwd=tmp_path)
    trap_head = _run(["git", "rev-parse", "HEAD"], cwd=tmp_path).stdout.strip()
    _write_signed_approval(tmp_path)
    trap_publisher_hash = hashlib.sha256(fixture_publisher.read_bytes()).hexdigest()
    real_publisher_hash = expected_identities["publisher-sha256"]
    assert expected_report.count(f"head: {base}".encode()) == 1
    assert expected_report.count(f"publisher-sha256: {real_publisher_hash}".encode()) == 1
    expected_trap_report = expected_report.replace(
        f"head: {base}".encode(),
        f"head: {trap_head}".encode(),
    ).replace(
        f"publisher-sha256: {real_publisher_hash}".encode(),
        f"publisher-sha256: {trap_publisher_hash}".encode(),
    )

    report_path.write_bytes(prior)
    trap_destination_state = _file_state(report_path)
    trap_ready = tmp_path / "trap-failpoint-ready"
    trap_resume = tmp_path / "trap-failpoint-continue"
    trap_process = _start_wrapper_at_failpoint(
        tmp_path,
        base,
        failpoint="before-report-publish",
        ready_file=trap_ready,
        continue_file=trap_resume,
        extra_environment={"TDD_SWARM_TEST_REPORT_PUBLISHER": str(malicious_publisher)},
    )

    try:
        assert _poll_until(
            lambda: trap_ready.exists() or trap_process.poll() is not None,
            deadline_seconds=3,
        )
        assert trap_ready.exists(), "wrapper did not expose the fixed-publisher trap boundary"
        assert report_path.read_bytes() == prior
        trap_stages = [
            path
            for path in report_directory.iterdir()
            if path != report_path
            and not path.is_symlink()
            and path.is_file()
            and path.read_bytes() == expected_trap_report
        ]
        assert len(trap_stages) == 1, (
            "trap must receive one complete regular same-directory staged report"
        )
        trap_stage = trap_stages[0]
        trap_stage_state = _file_state(trap_stage)
        trap_resume.touch()
        try:
            trap_stdout, trap_stderr = trap_process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            trap_stdout, trap_stderr = _terminate_process_group(trap_process)
            raise AssertionError("wrapper did not leave the fixed-publisher trap") from None
    finally:
        if trap_process.poll() is None:
            _terminate_process_group(trap_process)

    assert trap_process.returncode == trap_sentinel, trap_stdout + trap_stderr
    assert report_path.read_bytes() == prior
    assert _file_state(report_path) == trap_destination_state
    assert trap_stage_state[1] != trap_destination_state[1]
    records = [json.loads(line) for line in trap_record.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["nonce"] == trap_nonce
    assert len(records[0]["argv"]) == 2

    def resolve_fixture_argument(value: str) -> Path:
        path = Path(value)
        return path.resolve() if path.is_absolute() else (tmp_path / path).resolve()

    assert resolve_fixture_argument(records[0]["argv"][0]) == trap_stage.resolve()
    assert resolve_fixture_argument(records[0]["argv"][1]) == report_path.resolve()
    assert not marker.exists()


def test_wrapper_rejects_a_validated_gate_map_swapped_to_a_symlink_before_use(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — validation and later use stay bound to the same gate-map object."""
    base = _prepare_fixture(tmp_path)
    _write_secret_scan(tmp_path, "printf unsafe > external-gate-ran\n")
    _write_policy(tmp_path, _approved_non_applicable_policy())
    outside = tmp_path.parent / f"{tmp_path.name}-outside-gates.md"
    outside_content = (
        "# External gate mapping\n\n"
        "| gate | exact command | current status |\n"
        "|---|---|---|\n"
        f"| secret-scan | {SECRET_SCAN_COMMAND} | AVAILABLE |\n"
    ).encode()
    outside.write_bytes(outside_content)
    ready = tmp_path / "failpoint-ready"
    resume = tmp_path / "failpoint-continue"
    process = _start_wrapper_at_failpoint(
        tmp_path,
        base,
        failpoint="after-input-validation-before-use",
        ready_file=ready,
        continue_file=resume,
    )

    try:
        assert _poll_until(
            lambda: ready.exists() or process.poll() is not None,
            deadline_seconds=3,
        )
        assert ready.exists(), "wrapper did not expose the generic validation/use failpoint"
        gate_map = tmp_path / ".tdd-swarm" / "gates.md"
        gate_map.rename(tmp_path / ".tdd-swarm" / "gates.validated.md")
        gate_map.symlink_to(outside)
        resume.touch()
        try:
            stdout, stderr = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            stdout, stderr = _terminate_process_group(process)
            raise AssertionError("wrapper did not leave the validation/use failpoint") from None
    finally:
        if process.poll() is None:
            _terminate_process_group(process)

    assert process.returncode != 0
    assert not (tmp_path / "external-gate-ran").exists()
    assert outside.read_bytes() == outside_content
    output = (stdout + stderr).lower()
    assert "symlink" in output or "changed" in output or "integrity" in output


def test_wrapper_rejects_a_symlinked_ticket_parent_before_external_read(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — every validated input parent must be a real in-repository directory."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    outside = tmp_path.parent / f"{tmp_path.name}-outside-tickets"
    (tmp_path / "tickets").rename(outside)
    sentinel = (outside / "T-F00.md").read_bytes()
    (tmp_path / "tickets").symlink_to(outside, target_is_directory=True)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert "symlink" in (result.stdout + result.stderr).lower()
    assert (outside / "T-F00.md").read_bytes() == sentinel
    assert not (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").exists()


def test_wrapper_rejects_a_symlinked_package_root_before_external_read(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-2) — import analysis never follows a symlinked package root."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    package_root = tmp_path / "src" / "agentforge"
    outside = tmp_path.parent / f"{tmp_path.name}-outside-agentforge"
    package_root.rename(outside)
    poison = outside / "poison.py"
    poison.write_text("this is not valid Python !!!\n", encoding="utf-8")
    package_root.symlink_to(outside, target_is_directory=True)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "symlink" in output
    assert "syntax" not in output
    assert not (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").exists()


def test_wrapper_rejects_a_diff_base_that_is_not_an_ancestor_of_head(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — report base must be an ancestor of the tested HEAD."""
    _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    tree = _run(["git", "rev-parse", "HEAD^{tree}"], cwd=tmp_path).stdout.strip()
    unrelated = subprocess.run(
        ["git", "commit-tree", tree],
        cwd=tmp_path,
        input="unrelated base\n",
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    result = _run_wrapper(tmp_path, unrelated)

    assert result.returncode != 0
    assert "ancestor" in (result.stdout + result.stderr).lower()


def test_wrapper_rejects_a_dirty_tracked_tested_tree(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — frozen tests and gate inputs must match committed HEAD bytes."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    test_file = tmp_path / "tests" / "swarm" / "test_fixture.py"
    test_file.write_text(test_file.read_text(encoding="utf-8") + "\n# weakened locally\n")

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "dirty" in output or "worktree" in output
    assert "test_fixture.py" in output


def test_wrapper_rechecks_head_after_gate_commands_before_publishing(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — a gate that moves HEAD invalidates the entire evidence report."""
    base = _prepare_fixture(tmp_path)
    (tmp_path / "head-marker.txt").write_text("before\n", encoding="utf-8")
    _write_secret_scan(
        tmp_path,
        "printf 'after\\n' >> head-marker.txt\n"
        "git add head-marker.txt\n"
        "git commit -qm 'gate moved head'\n",
    )
    _write_single_gate_map(tmp_path, "secret-scan", "bash scripts/secret_scan.sh")
    _run(["git", "add", "."], cwd=tmp_path)
    _run(["git", "commit", "-qm", "prepare fixed gate"], cwd=tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    starting_head = _run(["git", "rev-parse", "HEAD"], cwd=tmp_path).stdout.strip()

    result = _run_wrapper(tmp_path, base)

    assert _run(["git", "rev-parse", "HEAD"], cwd=tmp_path).stdout.strip() != starting_head
    assert result.returncode != 0
    assert "head" in (result.stdout + result.stderr).lower()
    assert not (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").exists()


def test_report_hashes_every_input_and_declared_test_scope(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — every evidence digest equals its canonical input bytes."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    report = _report(tmp_path)
    declared_test_scopes = (
        "tests/swarm/test_secondary.py",
        "tests/swarm/test_fixture.py",
    )
    ticket = (tmp_path / "tickets" / "T-F00.md").read_text(encoding="utf-8")
    assert ticket.index(declared_test_scopes[0]) < ticket.index(declared_test_scopes[1])
    canonical_scope_hash = _canonical_test_scope_hash(tmp_path, declared_test_scopes)
    assert canonical_scope_hash != _test_scope_hash_in_order(tmp_path, declared_test_scopes)
    expected_hashes = {
        "ticket-sha256": hashlib.sha256(
            (tmp_path / "tickets" / "T-F00.md").read_bytes()
        ).hexdigest(),
        "gate-map-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / "gates.md").read_bytes()
        ).hexdigest(),
        "wrapper-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / "run-local-gates.sh").read_bytes()
        ).hexdigest(),
        "spec-lint-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / "spec-lint.sh").read_bytes()
        ).hexdigest(),
        "import-cycle-tool-sha256": hashlib.sha256(
            (tmp_path / ".tdd-swarm" / "check-import-cycles.py").read_bytes()
        ).hexdigest(),
        "test-scope-sha256": canonical_scope_hash,
    }
    for label, expected_hash in expected_hashes.items():
        assert f"{label}: {expected_hash}" in report
    assert len(set(expected_hashes.values())) == len(expected_hashes)


def test_coverage_semantic_failure_is_explicit_in_report_and_overall_verdict(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-3) — validation has its own failed status, diagnostic, and FAIL verdict."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "not-a-coverage-result\n")
    _write_policy(
        tmp_path,
        _executable_policy(base=base, baseline=90),
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    report_path = tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md"
    assert report_path.exists(), "semantic coverage failures must still publish bounded evidence"
    report = report_path.read_text(encoding="utf-8")
    assert "coverage-validation-status: FAIL" in report
    assert "exactly one coverage=<percent>" in report
    assert "overall-verdict: FAIL" in report


def test_free_text_coverage_approver_is_not_authorization(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — a waiver without an independent approval record fails closed."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _approval_paths(tmp_path)["record"].unlink()

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "approval" in output
    assert "policy" in output


def test_coverage_approval_must_have_a_detached_signature(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — an unsigned external record is not owner authorization."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _approval_paths(tmp_path)["signature"].unlink()

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert "signature" in (result.stdout + result.stderr).lower()


def test_coverage_approval_rejects_a_bad_signature(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — record bytes must verify under the externally supplied owner key."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    signature = _approval_paths(tmp_path)["signature"]
    signature_bytes = bytearray(signature.read_bytes())
    signature_bytes[0] ^= 0x01
    signature.write_bytes(signature_bytes)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "signature" in output or "verify" in output


def test_coverage_approval_rejects_a_signed_but_unauthorized_identity(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-3) — a valid signature cannot substitute for approver allowlisting."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_signed_approval(tmp_path, approver_id="owner:not-authorized")

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "approver" in output or "identity" in output or "authorized" in output


def test_coverage_approval_record_must_match_policy_hash(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — a valid signature does not excuse a stale policy binding."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_signed_approval(tmp_path, policy_sha256="0" * 64)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "approval" in output
    assert "policy" in output or "hash" in output


def test_coverage_approval_record_must_match_commit(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — a valid signature does not excuse a stale commit binding."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_signed_approval(tmp_path, commit_sha="1" * 40)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "approval" in output
    assert "commit" in output


def test_repository_gate_inventory_and_coverage_policy_are_mechanically_green_capable() -> None:
    """spec(T-F00:AC-3) spec(T-F00:AC-4) — the real local gate has no manual blockers."""
    gate_map = (REPOSITORY_ROOT / ".tdd-swarm" / "gates.md").read_text(encoding="utf-8")
    rows = [
        [cell.strip() for cell in line.strip().split("|")[1:-1]]
        for line in gate_map.splitlines()
        if line.strip().startswith("|")
    ]
    blocked = [
        f"{gate}: {status}"
        for gate, _, status in rows
        if gate not in {"gate", "---"} and status != "AVAILABLE"
    ]
    policy_fields = {}
    for line in (
        (REPOSITORY_ROOT / ".tdd-swarm" / "coverage-policy.md")
        .read_text(encoding="utf-8")
        .splitlines()
    ):
        if ":" in line and not line.lstrip().startswith("#"):
            key, value = line.split(":", 1)
            policy_fields[key.strip()] = value.strip()

    failures = list(blocked)
    if policy_fields.get("decision") != "executable":
        failures.append("coverage decision is not executable")
    if policy_fields.get("coverage-adapter") != COVERAGE_ADAPTER:
        failures.append("coverage adapter is not the fixed pytest-cov adapter")
    baseline = policy_fields.get("baseline-base-sha", "")
    baseline_check = subprocess.run(
        ["git", "cat-file", "-e", f"{baseline}^{{commit}}"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if not baseline or baseline_check.returncode != 0:
        failures.append("coverage baseline is not bound to a repository commit")

    assert not failures, "; ".join(failures)


def test_wrapper_terminates_a_silent_pipe_holding_descendant_after_leader_success(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-4) — a zero-exit leader cannot leave a live descendant or publish PASS."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=100\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=100))
    _write_secret_scan(
        tmp_path,
        "python3 - <<'PY' &\n"
        "import os\n"
        "import time\n"
        "from pathlib import Path\n"
        "Path('silent-child.pid').write_text(str(os.getpid()))\n"
        "time.sleep(30)\n"
        "PY\n"
        "exit 0\n",
    )
    _write_single_gate_map(tmp_path, "secret-scan", SECRET_SCAN_COMMAND)
    child_pid: int | None = None

    try:
        result, _, hit_test_deadline = _run_wrapper_with_test_deadline(
            tmp_path,
            base,
            deadline_seconds=8,
            extra_environment={"TDD_SWARM_GATE_TIMEOUT_SECONDS": "2.00"},
        )
        pid_path = tmp_path / "silent-child.pid"
        assert pid_path.exists(), result.stdout + result.stderr
        child_pid = int(pid_path.read_text(encoding="utf-8"))

        assert not hit_test_deadline
        assert result.returncode != 0
        assert _poll_until(lambda: not _pid_exists(child_pid), deadline_seconds=2)
        report_path = tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md"
        if report_path.exists():
            assert "overall-verdict: PASS" not in report_path.read_text(encoding="utf-8")
    finally:
        if child_pid is not None and _pid_exists(child_pid):
            with contextlib.suppress(ProcessLookupError):
                os.kill(child_pid, signal.SIGKILL)
            _poll_until(lambda: not _pid_exists(child_pid), deadline_seconds=2)


@pytest.mark.parametrize(
    "checker_output",
    [
        "import graph is acyclic\n",
        f"sha256={'1' * 64}\nsha256={'2' * 64}\n",
    ],
    ids=["missing-digest", "duplicate-digest"],
)
def test_wrapper_fails_import_validation_for_noncanonical_success_output(
    tmp_path: Path,
    checker_output: str,
) -> None:
    """spec(T-F00:AC-2) — successful import analysis emits exactly one canonical digest."""
    base = _prepare_fixture(tmp_path)
    _write_import_checker(tmp_path, checker_output)
    _write_coverage_output(tmp_path, "coverage=100\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=100))

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    report = _report(tmp_path)
    assert "import-validation-status: FAIL" in report
    assert "import-validation-diagnostic:" in report
    assert "overall-verdict: FAIL" in report


def test_wrapper_rejects_a_nonfinite_coverage_baseline_cleanly(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-3) — NaN and infinities are policy errors, never tracebacks."""
    violations = []
    for case_name, baseline in (
        ("nan", "NaN"),
        ("positive-infinity", "Infinity"),
        ("negative-infinity", "-Infinity"),
    ):
        repository = tmp_path / case_name
        base = _prepare_fixture(repository)
        _write_policy(
            repository,
            "# Coverage policy\n\n"
            "decision: executable\n"
            f"coverage-adapter: {COVERAGE_ADAPTER}\n"
            f"baseline-base-sha: {base}\n"
            f"baseline-percent: {baseline}\n",
        )

        result = _run_wrapper(repository, base)
        output = result.stdout + result.stderr
        normalized = output.lower()
        if result.returncode != 1:
            violations.append(f"{baseline}: exit {result.returncode}, expected 1")
        if "traceback" in normalized:
            violations.append(f"{baseline}: leaked traceback")
        if "baseline-percent" not in normalized:
            violations.append(f"{baseline}: missing baseline-percent diagnostic")
        if "finite" not in normalized and "between 0 and 100" not in normalized:
            violations.append(f"{baseline}: missing finite-range diagnostic")

    assert not violations, "; ".join(violations)


def test_fixed_report_publisher_rejects_a_symlink_in_an_earlier_ancestor(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — no ancestor component may redirect publication externally."""
    publisher = REPOSITORY_ROOT / ".tdd-swarm" / REPORT_PUBLISHER
    real_parent = tmp_path / "real-parent"
    report_directory = real_parent / "reports"
    report_directory.mkdir(parents=True)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    staged = linked_parent / "reports" / ".T-F00-gates.prepared"
    destination = linked_parent / "reports" / "T-F00-gates.md"
    real_stage = report_directory / staged.name
    real_destination = report_directory / destination.name
    real_stage.write_text("new report\n", encoding="utf-8")
    real_destination.write_text("prior report\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(publisher), str(staged), str(destination)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode != 0
    assert real_destination.read_text(encoding="utf-8") == "prior report\n"
    assert real_stage.read_text(encoding="utf-8") == "new report\n"
    assert "symlink" in (result.stdout + result.stderr).lower()


def test_wrapper_rejects_caller_selected_approval_key_and_identity(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-3) — approval trust comes from a protected anchor, not caller env."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    paths = _approval_paths(tmp_path)
    paths["private_key"].unlink()
    paths["public_key"].unlink()
    _write_signed_approval(tmp_path, approver_id="attacker:self-approved")

    result = _run_wrapper(
        tmp_path,
        base,
        extra_environment={"TDD_SWARM_COVERAGE_APPROVER_IDS": "attacker:self-approved"},
    )

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "trust" in output or "pinned" in output or "fingerprint" in output


def test_verified_approval_identity_and_artifact_digests_are_reported(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-3) spec(T-F00:AC-5) — waiver evidence names what was verified."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    paths = _approval_paths(tmp_path)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    report = _report(tmp_path)
    expected = {
        "coverage-verified-approver-id": "owner:headshot",
        "coverage-approval-key-sha256": hashlib.sha256(
            paths["public_key"].read_bytes()
        ).hexdigest(),
        "coverage-approval-record-sha256": hashlib.sha256(paths["record"].read_bytes()).hexdigest(),
        "coverage-approval-signature-sha256": hashlib.sha256(
            paths["signature"].read_bytes()
        ).hexdigest(),
    }
    for label, value in expected.items():
        assert f"{label}: {value}" in report


@pytest.mark.parametrize("continuation_exists", [True, False], ids=["write", "delay"])
def test_production_failpoint_environment_cannot_touch_or_delay_external_paths(
    tmp_path: Path,
    continuation_exists: bool,
) -> None:
    """spec(T-F00:AC-5) — production environment variables expose no path failpoint."""
    repository = tmp_path / "repository"
    base = _prepare_fixture(repository)
    _write_coverage_output(repository, "coverage=100\n")
    _write_policy(repository, _executable_policy(base=base, baseline=100))
    external_ready = tmp_path / "external-ready"
    external_continue = tmp_path / "external-continue"
    if continuation_exists:
        external_continue.write_text("continue\n", encoding="utf-8")

    result, elapsed, hit_test_deadline = _run_wrapper_with_test_deadline(
        repository,
        base,
        deadline_seconds=5,
        extra_environment={
            "TDD_SWARM_TEST_FAILPOINT": "before-report-publish",
            "TDD_SWARM_TEST_FAILPOINT_READY_FILE": str(external_ready),
            "TDD_SWARM_TEST_FAILPOINT_CONTINUE_FILE": str(external_continue),
        },
    )

    assert not hit_test_deadline, "production failpoint input delayed the wrapper"
    assert elapsed < 5
    assert not external_ready.exists()
    assert result.returncode in {0, 1}


def test_wrapper_uses_fixed_interpreter_provenance_independent_of_path(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — PATH cannot select interpreters and provenance is evidenced."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=100\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=100))
    poison = tmp_path / "poison-path"
    poison.mkdir()
    marker = tmp_path / "path-python-ran"
    fake_python = poison / "python3"
    fake_python.write_text(
        f'#!/bin/sh\nprintf unsafe >> {marker!s}\nexec "{sys.executable!s}" "$@"\n',
        encoding="utf-8",
    )
    fake_python.chmod(0o755)

    result = _run_wrapper(
        tmp_path,
        base,
        extra_environment={"PATH": f"{poison}{os.pathsep}{os.environ['PATH']}"},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert not marker.exists()
    report = _report(tmp_path)
    assert "python-interpreter-sha256:" in report
    assert "execution-environment-sha256:" in report


def test_wrapper_binds_staged_report_content_across_publisher_handoff(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — publisher receives and enforces the validated stage digest."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=100\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=100))
    report_directory = tmp_path / ".tdd-swarm" / "reports"
    report_directory.mkdir()
    destination = report_directory / "T-F00-gates.md"
    prior = b"prior complete report\n"
    destination.write_bytes(prior)
    ready = tmp_path / "stage-binding-ready"
    resume = tmp_path / "stage-binding-continue"
    process = _start_wrapper_at_failpoint(
        tmp_path,
        base,
        failpoint="before-report-publish",
        ready_file=ready,
        continue_file=resume,
    )

    try:
        assert _poll_until(lambda: ready.exists() or process.poll() is not None, deadline_seconds=3)
        assert ready.exists(), "wrapper did not reach the publisher handoff"
        stages = list(report_directory.glob(".T-F00-gates.*.stage"))
        assert len(stages) == 1
        stages[0].write_bytes(b"tampered after validation\n")
        resume.touch()
        try:
            stdout, stderr = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            stdout, stderr = _terminate_process_group(process)
            raise AssertionError("wrapper did not leave the publisher handoff") from None
    finally:
        if process.poll() is None:
            _terminate_process_group(process)

    assert process.returncode != 0, stdout + stderr
    assert destination.read_bytes() == prior
    assert "digest" in (stdout + stderr).lower() or "changed" in (stdout + stderr).lower()


def test_wrapper_encodes_c1_bidi_and_isolate_characters_in_metadata_and_output(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — C1, bidi, and isolate controls are visibly encoded everywhere."""
    base = _prepare_fixture(tmp_path)
    raw_controls = "\u0085\u202e\u2066"
    _write_coverage_output(tmp_path, f"coverage=100 {raw_controls}\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=100))
    _write_single_gate_map(
        tmp_path,
        "typecheck",
        "reason=blocked-\u202e-\u2066",
        status="BLOCKED",
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    console = result.stdout + result.stderr
    report = _report(tmp_path)
    for character in raw_controls:
        assert character not in console
        assert character not in report
    for entity in ("&#x85;", "&#x202E;", "&#x2066;"):
        assert entity in report


@pytest.mark.parametrize("dirty", [False, True], ids=["clean-manifest", "dirty-reject"])
def test_wrapper_binds_declared_implementation_scopes_and_dirty_state(
    tmp_path: Path,
    dirty: bool,
) -> None:
    """spec(T-F00:AC-5) — evidence binds file_scopes and rejects local implementation drift."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=100\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=100))
    implementation = tmp_path / "src" / "agentforge" / "alpha.py"
    expected_hash = _canonical_test_scope_hash(
        tmp_path,
        ("src/agentforge/alpha.py",),
    )
    if dirty:
        implementation.write_text(
            implementation.read_text(encoding="utf-8") + "# dirty implementation\n",
            encoding="utf-8",
        )

    result = _run_wrapper(tmp_path, base)

    if dirty:
        assert result.returncode != 0
        output = (result.stdout + result.stderr).lower()
        assert "alpha.py" in output
        assert "dirty" in output or "worktree" in output
        assert not (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert f"implementation-scope-sha256: {expected_hash}" in _report(tmp_path)


def test_gate_children_receive_a_minimal_allowlisted_environment(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — arbitrary parent credentials are absent from every child."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=100\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=100))
    _write_secret_scan(
        tmp_path,
        "printf 'database=%s\\n' \"${DATABASE_URL-unset}\"\n"
        "printf 'cookie=%s\\n' \"${HTTP_COOKIE-unset}\"\n",
    )
    _write_single_gate_map(tmp_path, "secret-scan", SECRET_SCAN_COMMAND)
    database_secret = "postgresql://fixture-user:fixture-pass@db.invalid/fixture"
    cookie_secret = "fixture-session-cookie-value"

    result = _run_wrapper(
        tmp_path,
        base,
        extra_environment={
            "DATABASE_URL": database_secret,
            "HTTP_COOKIE": cookie_secret,
        },
    )

    console = result.stdout + result.stderr
    report = _report(tmp_path)
    assert database_secret not in console
    assert database_secret not in report
    assert cookie_secret not in console
    assert cookie_secret not in report
    assert "child-environment-policy: minimal-allowlist" in report


def test_failed_invocation_quarantines_a_stale_prior_report(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — a prior success cannot remain presented as the current run."""
    base = _prepare_fixture(tmp_path)
    report_directory = tmp_path / ".tdd-swarm" / "reports"
    report_directory.mkdir()
    report_path = report_directory / "T-F00-gates.md"
    stale = (
        "# Local gate report — T-F00\n\n"
        f"ticket: tickets/T-F00.md\nbase: {base}\nhead: {'0' * 40}\n"
        "overall-verdict: PASS\n"
    ).encode()
    report_path.write_bytes(stale)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not report_path.exists() or report_path.read_bytes() != stale
    assert "stale" in (result.stdout + result.stderr).lower()


def test_wrapper_cleans_only_recognizable_owned_orphan_stages(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-5) — owned crash debris is removed without deleting lookalike files."""
    base = _prepare_fixture(tmp_path)
    _write_coverage_output(tmp_path, "coverage=100\n")
    _write_policy(tmp_path, _executable_policy(base=base, baseline=100))
    report_directory = tmp_path / ".tdd-swarm" / "reports"
    report_directory.mkdir()
    owned = report_directory / f".T-F00-gates.{'a' * 24}.stage"
    owned.write_text(
        "# Local gate report — T-F00\n\n"
        f"ticket: tickets/T-F00.md\nbase: {base}\nhead: {base}\n"
        "overall-verdict: FAIL\n",
        encoding="utf-8",
    )
    owned.chmod(0o600)
    lookalike = report_directory / ".T-F00-gates.user-owned.stage"
    lookalike.write_text("do not delete\n", encoding="utf-8")
    lookalike.chmod(0o644)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not owned.exists()
    assert lookalike.read_text(encoding="utf-8") == "do not delete\n"
