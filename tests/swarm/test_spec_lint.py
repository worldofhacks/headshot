"""Contract tests for the mechanical acceptance-criterion mapping gate."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SPEC_LINT = REPOSITORY_ROOT / ".tdd-swarm" / "spec-lint.sh"


def _run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True)


def _write_ticket(repository: Path, *, criteria: tuple[str, ...]) -> Path:
    ticket = repository / "tickets" / "T-F00.md"
    ticket.parent.mkdir(parents=True)
    criterion_rows = "\n".join(f"- **{criterion}**: Fixture criterion." for criterion in criteria)
    ticket.write_text(
        "---\n"
        "id: T-F00\n"
        "test_scopes:\n"
        "  - tests/swarm/test_ticket.py\n"
        "---\n\n"
        "## Acceptance Criteria\n"
        f"{criterion_rows}\n",
        encoding="utf-8",
    )
    return ticket


def _write_test(repository: Path, body: str) -> Path:
    test_file = repository / "tests" / "swarm" / "test_ticket.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text(body, encoding="utf-8")
    return test_file


def _commit_fixture(repository: Path) -> str:
    _run(["git", "init", "-q"], cwd=repository)
    _run(["git", "config", "user.email", "swarm@example.test"], cwd=repository)
    _run(["git", "config", "user.name", "TDD Swarm"], cwd=repository)
    _run(["git", "add", "."], cwd=repository)
    _run(["git", "commit", "-qm", "fixture"], cwd=repository)
    return _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip()


def _install_spec_lint(repository: Path) -> Path:
    assert SPEC_LINT.is_file(), "spec(T-F00:AC-1) requires the spec-lint executable"
    destination = repository / ".tdd-swarm" / "spec-lint.sh"
    destination.parent.mkdir(parents=True)
    shutil.copy2(SPEC_LINT, destination)
    return destination


def _invoke_spec_lint(repository: Path, base: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", ".tdd-swarm/spec-lint.sh", "tickets/T-F00.md", base],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def test_spec_lint_rejects_a_ticket_criterion_without_a_test_mapping(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — every declared acceptance criterion needs a tagged test."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1", "AC-2"))
    _write_test(tmp_path, 'def test_mapped():\n    """spec(T-F00:AC-1)"""\n')
    base = _commit_fixture(tmp_path)

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    assert "AC-2" in result.stdout + result.stderr


def test_spec_lint_rejects_a_new_test_that_omits_its_spec_tag(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — newly changed tests may not bypass criterion traceability."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, 'def test_mapped():\n    """spec(T-F00:AC-1)"""\n')
    base = _commit_fixture(tmp_path)
    test_file.write_text("def test_new_behavior():\n    assert True\n", encoding="utf-8")

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    assert "test_ticket.py" in result.stdout + result.stderr
    assert "spec" in (result.stdout + result.stderr).lower()


def test_spec_lint_accepts_a_complete_criterion_to_test_mapping(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — complete mappings are accepted without a manual waiver."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1", "AC-2"))
    _write_test(
        tmp_path,
        'def test_first():\n    """spec(T-F00:AC-1)"""\n\n'
        'def test_second():\n    """spec(T-F00:AC-2)"""\n',
    )
    base = _commit_fixture(tmp_path)

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr
