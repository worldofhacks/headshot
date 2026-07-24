"""Contract tests for the fail-closed local gate wrapper and its evidence report."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SWARM_FILES = (
    "run-local-gates.sh",
    "spec-lint.sh",
    "check-import-cycles.py",
    "coverage-policy.md",
)


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def _write_ticket(repository: Path) -> None:
    ticket = repository / "tickets" / "T-F00.md"
    ticket.parent.mkdir(parents=True)
    ticket.write_text(
        "---\nid: T-F00\ntest_scopes:\n  - tests/swarm/test_fixture.py\n---\n\n"
        "## Acceptance Criteria\n- **AC-1**: Fixture.\n"
        "- **AC-2**: Fixture.\n- **AC-3**: Fixture.\n"
        "- **AC-4**: Fixture.\n- **AC-5**: Fixture.\n",
        encoding="utf-8",
    )
    test_file = repository / "tests" / "swarm" / "test_fixture.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(
        '"""spec(T-F00:AC-1) spec(T-F00:AC-2) spec(T-F00:AC-3) '
        'spec(T-F00:AC-4) spec(T-F00:AC-5)"""\n',
        encoding="utf-8",
    )


def _write_gate_map(repository: Path, *, lint_command: str) -> None:
    (repository / ".tdd-swarm").mkdir(parents=True, exist_ok=True)
    (repository / ".tdd-swarm" / "gates.md").write_text(
        "# Fixture gate mapping\n\n"
        "| gate | exact command | current status |\n"
        "|---|---|---|\n"
        "| format | printf format-ok | AVAILABLE |\n"
        f"| lint | {lint_command} | AVAILABLE |\n"
        "| typecheck | printf typecheck-ok | AVAILABLE |\n",
        encoding="utf-8",
    )


def _write_policy(repository: Path, content: str) -> Path:
    policy = repository / ".tdd-swarm" / "coverage-policy.md"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text(content, encoding="utf-8")
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


def _install_swarm_tools(repository: Path) -> None:
    for filename in SWARM_FILES:
        source = REPOSITORY_ROOT / ".tdd-swarm" / filename
        assert source.is_file(), f"spec(T-F00:AC-3) requires {filename}"
        destination = repository / ".tdd-swarm" / filename
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _commit_fixture(repository: Path) -> str:
    _run(["git", "init", "-q"], cwd=repository)
    _run(["git", "config", "user.email", "swarm@example.test"], cwd=repository)
    _run(["git", "config", "user.name", "TDD Swarm"], cwd=repository)
    _run(["git", "add", "."], cwd=repository)
    _run(["git", "commit", "-qm", "fixture"], cwd=repository)
    return _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip()


def _run_wrapper(repository: Path, base: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", ".tdd-swarm/run-local-gates.sh", "tickets/T-F00.md", base],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def test_wrapper_rejects_a_missing_or_expired_coverage_policy(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — coverage may be waived only by a complete, unexpired approval."""
    _install_swarm_tools(tmp_path)
    _write_ticket(tmp_path)
    _write_gate_map(tmp_path, lint_command="printf lint-ok")
    base = _commit_fixture(tmp_path)

    missing = _run_wrapper(tmp_path, base)

    assert missing.returncode != 0
    assert "coverage-policy" in (missing.stdout + missing.stderr).lower()

    _write_policy(tmp_path, _approved_non_applicable_policy(expiry="2000-01-01"))
    expired = _run_wrapper(tmp_path, base)

    assert expired.returncode != 0
    assert "expired" in (expired.stdout + expired.stderr).lower()


def test_wrapper_preserves_failure_output_and_runs_all_mapped_gate_rows(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — one failed gate cannot hide later commands or their report rows."""
    _install_swarm_tools(tmp_path)
    _write_ticket(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_gate_map(tmp_path, lint_command="sh -c 'printf lint-failed >&2; exit 7'")
    base = _commit_fixture(tmp_path)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert "lint-failed" in result.stdout + result.stderr
    report = (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").read_text(encoding="utf-8")
    assert "format" in report
    assert "lint" in report
    assert "typecheck" in report
    assert "exit" in report.lower()


def test_wrapper_writes_a_hash_bound_report_when_all_gates_are_green(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — a green run records immutable identifiers, commands, exits, and hashes."""
    _install_swarm_tools(tmp_path)
    _write_ticket(tmp_path)
    policy = _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_gate_map(tmp_path, lint_command="printf lint-ok")
    base = _commit_fixture(tmp_path)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    report = (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").read_text(encoding="utf-8")
    assert "tickets/T-F00.md" in report
    assert base in report
    assert _run(["git", "rev-parse", "HEAD"], cwd=tmp_path).stdout.strip() in report
    assert "printf format-ok" in report
    assert "printf lint-ok" in report
    assert "exit" in report.lower()
    assert hashlib.sha256(policy.read_bytes()).hexdigest() in report
    assert "import" in report.lower()
    assert "hash" in report.lower()
