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


def _write_conftest(repository: Path, body: str) -> Path:
    conftest = repository / "conftest.py"
    conftest.write_text(body, encoding="utf-8")
    return conftest


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


def test_spec_lint_rejects_an_untagged_test_beside_a_tagged_test(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — tagging one test may not launder an untagged test in the same file."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, 'def test_mapped():\n    """spec(T-F00:AC-1)"""\n')
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        'def test_mapped():\n    """spec(T-F00:AC-1)"""\n\n'
        "def test_untagged_new_behavior():\n    assert True\n",
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert "test_untagged_new_behavior" in output
    assert "spec" in output.lower()


def test_spec_lint_checks_only_tests_added_since_the_diff_base(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — a legacy untagged test is outside this ticket's new-test set."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    _write_test(
        tmp_path,
        'def test_existing_mapping():\n    """spec(T-F00:AC-1)"""\n\n'
        "def test_legacy_unmapped_behavior():\n    assert True\n",
    )
    base = _commit_fixture(tmp_path)

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr


def test_spec_lint_accepts_a_spec_tag_in_a_test_name(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — normalized test-name tags map newly added collected tests."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        "def test_spec_T_F00_AC_1():\n    assert True\n",
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr


def test_spec_lint_accepts_a_spec_tag_in_a_test_comment(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — source comments are supported tag locations for new tests."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        "# spec(T-F00:AC-1)\ndef test_comment_mapped():\n    assert True\n",
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr


def test_spec_lint_rejects_an_untagged_sibling_of_a_comment_mapped_test(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-1) — a comment tag applies only to its collected test node."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        "# spec(T-F00:AC-1)\n"
        "def test_comment_mapped():\n    assert True\n\n"
        "def test_untagged_sibling():\n    assert True\n",
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    output = result.stdout + result.stderr
    assert result.returncode == 1
    assert "test_untagged_sibling" in output
    assert "test_comment_mapped" not in output


def test_spec_lint_accepts_a_spec_tag_in_a_test_docstring(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — function docstrings remain supported tag locations."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        'def test_docstring_mapped():\n    """spec(T-F00:AC-1)"""\n',
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 0, result.stdout + result.stderr


def test_spec_lint_rejects_a_skipped_test_as_an_acceptance_mapping(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — skipped tests cannot satisfy an acceptance criterion."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        "import pytest\n\n"
        "@pytest.mark.skip(reason='not executed')\n"
        "def test_skipped_mapping():\n"
        '    """spec(T-F00:AC-1)"""\n',
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    assert "test_skipped_mapping" in result.stdout + result.stderr


def test_spec_lint_rejects_a_mapping_excluded_by_pytest_collect_ignore(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — collection configuration can make a tagged source test invalid."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    _write_conftest(tmp_path, 'collect_ignore = ["tests/swarm/test_ticket.py"]\n')
    test_file.write_text(
        'def test_collect_ignore_mapping():\n    """spec(T-F00:AC-1)"""\n',
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    assert "test_collect_ignore_mapping" in result.stdout + result.stderr


def test_spec_lint_rejects_a_module_level_runtime_skip_as_an_acceptance_mapping(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-1) — a dynamic module skip prevents a mapped node from executing."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        "import pytest\n\n"
        "pytest.skip('dynamic module skip', allow_module_level=True)\n\n"
        "def test_module_skip_mapping():\n"
        '    """spec(T-F00:AC-1)"""\n',
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    assert "test_module_skip_mapping" in result.stdout + result.stderr


def test_spec_lint_rejects_a_tagged_test_file_that_fails_pytest_collection(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-1) — a source tag cannot map an AC when pytest cannot collect its file."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        "raise RuntimeError('collection failure fixture')\n\n"
        "def test_collection_failure_mapping():\n"
        '    """spec(T-F00:AC-1)"""\n',
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    output = result.stdout + result.stderr
    assert result.returncode == 1
    assert "test_collection_failure_mapping" in output
    assert "collection" in output.lower()


def test_spec_lint_rejects_an_uncollected_test_as_an_acceptance_mapping(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — a test disabled from pytest collection cannot map an AC."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        "def test_uncollected_mapping():\n"
        '    """spec(T-F00:AC-1)"""\n\n'
        "test_uncollected_mapping.__test__ = False\n",
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    assert "test_uncollected_mapping" in result.stdout + result.stderr


def test_spec_lint_rejects_a_nested_function_as_an_acceptance_mapping(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — a nested test-like function has no pytest node id to bind."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        'def helper():\n    def test_nested_mapping():\n        """spec(T-F00:AC-1)"""\n',
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    assert "test_nested_mapping" in result.stdout + result.stderr


def test_spec_lint_rejects_a_non_test_class_method_as_an_acceptance_mapping(
    tmp_path: Path,
) -> None:
    """spec(T-F00:AC-1) — methods outside Test* classes are not pytest-collected tests."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    test_file = _write_test(tmp_path, "")
    base = _commit_fixture(tmp_path)
    test_file.write_text(
        "class Helper:\n"
        "    def test_non_test_class_mapping(self):\n"
        '        """spec(T-F00:AC-1)"""\n',
        encoding="utf-8",
    )

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    assert "test_non_test_class_mapping" in result.stdout + result.stderr


def test_spec_lint_rejects_a_test_tagged_to_the_wrong_ticket(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — a tag for another ticket does not map this ticket's test."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    _write_test(tmp_path, 'def test_wrong_ticket():\n    """spec(T-OTHER:AC-1)"""\n')
    base = _commit_fixture(tmp_path)

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert "test_wrong_ticket" in output
    assert "T-OTHER" in output


def test_spec_lint_rejects_a_tag_for_a_nonexistent_acceptance_criterion(tmp_path: Path) -> None:
    """spec(T-F00:AC-1) — tags must name an AC that the ticket actually declares."""
    _install_spec_lint(tmp_path)
    _write_ticket(tmp_path, criteria=("AC-1",))
    _write_test(
        tmp_path,
        'def test_mapped():\n    """spec(T-F00:AC-1)"""\n\n'
        'def test_unknown_criterion():\n    """spec(T-F00:AC-99)"""\n',
    )
    base = _commit_fixture(tmp_path)

    result = _invoke_spec_lint(tmp_path, base)

    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert "test_unknown_criterion" in output
    assert "AC-99" in output


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
