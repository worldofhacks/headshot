"""Contract tests for the package import-cycle gate."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
IMPORT_CYCLE_CHECK = REPOSITORY_ROOT / ".tdd-swarm" / "check-import-cycles.py"


def _install_cycle_check(repository: Path) -> Path:
    assert IMPORT_CYCLE_CHECK.is_file(), "spec(T-F00:AC-2) requires the import-cycle checker"
    destination = repository / ".tdd-swarm" / "check-import-cycles.py"
    destination.parent.mkdir(parents=True)
    shutil.copy2(IMPORT_CYCLE_CHECK, destination)
    return destination


def _run_cycle_check(repository: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, ".tdd-swarm/check-import-cycles.py"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def test_import_cycle_check_rejects_a_declared_package_layer_cycle(tmp_path: Path) -> None:
    """spec(T-F00:AC-2) — a concrete layer cycle fails and names the cycle members."""
    _install_cycle_check(tmp_path)
    package = tmp_path / "src" / "agentforge"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "layer_a.py").write_text("from agentforge import layer_b\n", encoding="utf-8")
    (package / "layer_b.py").write_text("from agentforge import layer_a\n", encoding="utf-8")

    result = _run_cycle_check(tmp_path)

    output = result.stdout + result.stderr
    assert result.returncode == 1
    assert "cycle" in output.lower()
    assert "layer_a" in output
    assert "layer_b" in output


def test_import_cycle_check_accepts_the_current_approved_graph() -> None:
    """spec(T-F00:AC-2) — the repository's approved package graph remains acyclic."""
    assert IMPORT_CYCLE_CHECK.is_file(), "spec(T-F00:AC-2) requires the import-cycle checker"

    result = _run_cycle_check(REPOSITORY_ROOT)

    assert result.returncode == 0, result.stdout + result.stderr
