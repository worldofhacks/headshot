"""Contract tests for the fail-closed local gate wrapper and its evidence report."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import time
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
    if "decision: non-applicable" in content and (repository / ".git").exists():
        approval = repository.parent / f".{repository.name}-coverage-approval.json"
        approval.write_text(
            json.dumps(
                {
                    "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
                    "commit_sha": _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip(),
                    "approver_id": "owner:headshot",
                }
            ),
            encoding="utf-8",
        )
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


def _run_wrapper(
    repository: Path,
    base: str,
    *,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    approval = repository.parent / f".{repository.name}-coverage-approval.json"
    if approval.exists():
        environment["TDD_SWARM_COVERAGE_APPROVAL_FILE"] = str(approval)
    if extra_environment:
        environment.update(extra_environment)
    return subprocess.run(
        ["bash", ".tdd-swarm/run-local-gates.sh", "tickets/T-F00.md", base],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=8,
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


def _report(repository: Path) -> str:
    return (repository / ".tdd-swarm" / "reports" / "T-F00-gates.md").read_text(encoding="utf-8")


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


def test_wrapper_rejects_an_arbitrary_gate_executable_without_running_it(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — gate rows select fixed IDs/argv, never arbitrary executables."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    marker = tmp_path / "arbitrary-executable-ran"
    command = (
        "python3 -c 'from pathlib import Path; "
        'Path("arbitrary-executable-ran").write_text("unsafe")\''
    )
    _write_single_gate_map(tmp_path, "format", command)

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    assert "allowlist" in (result.stdout + result.stderr).lower()


def test_wrapper_rejects_an_explicit_shell_gate_without_running_it(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — shell interpreters cannot be selected as gate commands."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    marker = tmp_path / "shell-ran"
    _write_single_gate_map(tmp_path, "lint", "sh -c 'printf unsafe > shell-ran'")

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    assert not marker.exists()
    assert "shell" in (result.stdout + result.stderr).lower()


def test_wrapper_rejects_an_arbitrary_coverage_command_without_running_it(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — coverage uses a fixed adapter rather than policy-supplied code."""
    base = _prepare_fixture(tmp_path)
    marker = tmp_path / "coverage-shell-ran"
    _write_policy(
        tmp_path,
        "# Coverage policy\n\n"
        "decision: executable\n"
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
        "import time\nfrom pathlib import Path\n"
        "time.sleep(0.8)\nPath('orphan-marker').write_text('alive')\n"
        "PY\n"
        "printf '%s' \"$!\" > child.pid\n"
        "sleep 2\n",
    )
    _write_single_gate_map(tmp_path, "secret-scan", "bash scripts/secret_scan.sh")

    started = time.monotonic()
    result = _run_wrapper(
        tmp_path,
        base,
        extra_environment={"TDD_SWARM_GATE_TIMEOUT_SECONDS": "0.20"},
    )
    elapsed = time.monotonic() - started

    assert result.returncode != 0
    assert elapsed < 1.5
    time.sleep(0.9)
    assert not (tmp_path / "orphan-marker").exists()
    assert "timeout" in _report(tmp_path).lower()


def test_wrapper_fails_and_bounds_a_noisy_gate(tmp_path: Path) -> None:
    """spec(T-F00:AC-4) — output over budget stops the gate and stays bounded in evidence."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    _write_secret_scan(tmp_path, "python3 -c \"print('x' * 262144)\"\n")
    _write_single_gate_map(tmp_path, "secret-scan", "bash scripts/secret_scan.sh")

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    report = _report(tmp_path)
    assert len(report.encode()) < 32_768
    assert "truncated" in report.lower() or "output limit" in report.lower()
    assert "overall-verdict: FAIL" in report


def test_wrapper_redacts_console_and_report_output_and_records_a_digest(tmp_path: Path) -> None:
    """spec(T-F00:AC-5) — sensitive output is redacted before emission but remains digest-bound."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    secret = "AKIAIOSFODNN7EXAMPLE"
    raw = f"credential={secret}\n"
    _write_secret_scan(tmp_path, "printf 'credential=%s\\n' \"$FIXTURE_SECRET\"\n")
    _write_single_gate_map(tmp_path, "secret-scan", "bash scripts/secret_scan.sh")

    result = _run_wrapper(
        tmp_path,
        base,
        extra_environment={"FIXTURE_SECRET": secret},
    )

    console = result.stdout + result.stderr
    report = _report(tmp_path)
    assert secret not in console
    assert secret not in report
    assert "[REDACTED]" in console
    assert "[REDACTED]" in report
    assert f"output-sha256: {hashlib.sha256(raw.encode()).hexdigest()}" in report


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
    """spec(T-F00:AC-5) — evidence hashes the ticket, gate map, tools, and frozen test bytes."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())

    result = _run_wrapper(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
    report = _report(tmp_path)
    required_hashes = {
        "ticket-sha256",
        "gate-map-sha256",
        "wrapper-sha256",
        "spec-lint-sha256",
        "import-cycle-tool-sha256",
        "test-scope-sha256",
    }
    assert all(f"{label}:" in report for label in required_hashes)


def test_coverage_semantic_failure_is_explicit_in_report_and_overall_verdict(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-3) — validation has its own failed status, diagnostic, and FAIL verdict."""
    base = _prepare_fixture(tmp_path)
    _write_policy(
        tmp_path,
        "# Coverage policy\n\n"
        "decision: executable\n"
        "coverage-command: printf 'not-a-coverage-result\\n'\n"
        f"baseline-base-sha: {base}\n"
        "baseline-percent: 90\n",
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    report = _report(tmp_path)
    assert "coverage-validation-status: FAIL" in report
    assert "exactly one coverage=<percent>" in report
    assert "overall-verdict: FAIL" in report


def test_free_text_coverage_approver_is_not_authorization(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — a waiver without an independent approval record fails closed."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    approval = tmp_path.parent / f".{tmp_path.name}-coverage-approval.json"
    approval.unlink()

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "approval" in output
    assert "policy" in output


def test_coverage_approval_record_must_match_policy_hash_and_commit(tmp_path: Path) -> None:
    """spec(T-F00:AC-3) — owner approval is cryptographically bound to policy and HEAD."""
    base = _prepare_fixture(tmp_path)
    _write_policy(tmp_path, _approved_non_applicable_policy())
    approval = tmp_path.parent / f".{tmp_path.name}-coverage-approval.json"
    approval.write_text(
        json.dumps(
            {
                "policy_sha256": "0" * 64,
                "commit_sha": "1" * 40,
                "approver_id": "owner:headshot",
            }
        ),
        encoding="utf-8",
    )

    result = _run_wrapper(tmp_path, base)

    assert result.returncode != 0
    output = (result.stdout + result.stderr).lower()
    assert "approval" in output
    assert "hash" in output or "commit" in output
