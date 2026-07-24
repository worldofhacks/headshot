"""Contract tests for the fail-closed local gate wrapper and its evidence report."""

from __future__ import annotations

import ast
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Final

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SWARM_FILES = (
    "run-local-gates.sh",
    "spec-lint.sh",
    "check-import-cycles.py",
)
FORMAT_COMMAND: Final = "sh -c 'printf format-before; printf 1 >> gate-order.log'"
LINT_OK_COMMAND: Final = "sh -c 'printf lint-ok; printf 2 >> gate-order.log'"
LINT_FAIL_COMMAND: Final = "sh -c 'printf lint-failed >&2; printf 2 >> gate-order.log; exit 7'"
TYPECHECK_COMMAND: Final = "sh -c 'printf typecheck-after; printf 3 >> gate-order.log'"


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
        'def test_ac_1():\n    """spec(T-F00:AC-1)"""\n\n'
        'def test_ac_2():\n    """spec(T-F00:AC-2)"""\n\n'
        'def test_ac_3():\n    """spec(T-F00:AC-3)"""\n\n'
        'def test_ac_4():\n    """spec(T-F00:AC-4)"""\n\n'
        'def test_ac_5():\n    """spec(T-F00:AC-5)"""\n',
        encoding="utf-8",
    )


def _write_gate_map(repository: Path, *, lint_command: str = LINT_OK_COMMAND) -> None:
    (repository / ".tdd-swarm").mkdir(parents=True, exist_ok=True)
    (repository / ".tdd-swarm" / "gates.md").write_text(
        "# Fixture gate mapping\n\n"
        "| gate | exact command | current status |\n"
        "|---|---|---|\n"
        f"| format | {FORMAT_COMMAND} | AVAILABLE |\n"
        f"| lint | {lint_command} | AVAILABLE |\n"
        f"| typecheck | {TYPECHECK_COMMAND} | AVAILABLE |\n",
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


def _executable_policy(*, base: str, observed: float, baseline: float) -> str:
    return (
        "# Coverage policy\n\n"
        "decision: executable\n"
        f"coverage-command: printf 'coverage={observed:.2f}\\n'\n"
        f"baseline-base-sha: {base}\n"
        f"baseline-percent: {baseline:.2f}\n"
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


def _commit_head_change(repository: Path) -> str:
    marker = repository / "head-marker.txt"
    marker.write_text("distinct head\n", encoding="utf-8")
    _run(["git", "add", "head-marker.txt"], cwd=repository)
    _run(["git", "commit", "-qm", "distinct head"], cwd=repository)
    return _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip()


def _run_wrapper(repository: Path, base: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", ".tdd-swarm/run-local-gates.sh", "tickets/T-F00.md", base],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def _prepare_fixture(repository: Path) -> str:
    _install_swarm_tools(repository)
    _write_ticket(repository)
    _write_gate_map(repository)
    package = repository / "src" / "agentforge"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "alpha.py").write_text("import agentforge.beta\n", encoding="utf-8")
    (package / "beta.py").write_text("", encoding="utf-8")
    return _commit_fixture(repository)


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
    _write_policy(tmp_path, _executable_policy(base=base, observed=97.25, baseline=97.25))

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "coverage=97.25" in result.stdout + result.stderr


def test_wrapper_rejects_executable_coverage_without_a_baseline_base_sha(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — executable coverage fails closed without its base-SHA binding."""
    base = _prepare_fixture(tmp_path)
    complete = _executable_policy(base=base, observed=97.25, baseline=97.25)
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
        _executable_policy(base=different_commit, observed=97.25, baseline=97.25),
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 1
    output = result.stdout + result.stderr
    _assert_base_sha_diagnostic(output)
    assert "match" in output.lower()


def test_wrapper_rejects_executable_coverage_regression(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — observed coverage below the base-SHA baseline fails closed."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _executable_policy(base=base, observed=96.50, baseline=97.25))

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
    _write_gate_map(tmp_path, lint_command=LINT_FAIL_COMMAND)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "format-before" in output
    assert "lint-failed" in output
    assert "typecheck-after" in output
    assert (tmp_path / "gate-order.log").read_text(encoding="utf-8") == "123"
    report = (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").read_text(encoding="utf-8")
    _assert_report_row(report, "format", FORMAT_COMMAND, 0, "format-before")
    _assert_report_row(report, "lint", LINT_FAIL_COMMAND, 7, "lint-failed")
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
    expected_import_hash = _canonical_import_graph_hash(tmp_path)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    report = (tmp_path / ".tdd-swarm" / "reports" / "T-F00-gates.md").read_text(encoding="utf-8")
    assert base != head
    assert "ticket: tickets/T-F00.md" in report
    assert f"base: {base}" in report
    assert f"head: {head}" in report
    _assert_report_row(report, "format", FORMAT_COMMAND, 0, "format-before")
    _assert_report_row(report, "lint", LINT_OK_COMMAND, 0, "lint-ok")
    _assert_report_row(report, "typecheck", TYPECHECK_COMMAND, 0, "typecheck-after")
    assert f"coverage-policy-sha256: {hashlib.sha256(policy.read_bytes()).hexdigest()}" in report
    assert f"import-graph-sha256: {expected_import_hash}" in report
