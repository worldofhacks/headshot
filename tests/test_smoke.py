"""P8 import smoke test — proves the package installs and imports (pytest collects >=1 test)."""

import agentforge


def test_version_present() -> None:
    assert agentforge.__version__ == "0.1.0"


def test_package_imports_without_frameworks() -> None:
    """The core must stay framework-neutral (D10). Importing the package must not pull an
    orchestration framework into the process."""
    import sys

    import agentforge  # noqa: F401  (re-import to trigger any transitive imports)

    assert "langgraph" not in sys.modules
    assert "crewai" not in sys.modules
