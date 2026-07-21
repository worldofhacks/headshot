from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORE_FILES = (
    ROOT / "src/agentforge/target/spec.py",
    ROOT / "src/agentforge/target/registry.py",
    ROOT / "src/agentforge/target/adapter_registry.py",
)


def test_generic_core_and_focused_tests_use_only_generic_vocabulary() -> None:
    token_codes = (
        (111, 112, 101, 110, 101, 109, 114),
        (99, 108, 105, 110, 105, 99, 97, 108),
        (112, 97, 116, 105, 101, 110, 116),
        (99, 111, 112, 105, 108, 111, 116),
    )
    forbidden = tuple("".join(chr(code) for code in codes) for codes in token_codes)
    files = (*CORE_FILES, *sorted((ROOT / "tests/target").glob("*.py")))

    for file in files:
        normalized = re.sub(r"[^a-z0-9]", "", file.read_text(encoding="utf-8").lower())
        assert not any(token in normalized for token in forbidden), file


def test_importing_core_loads_no_network_framework_or_specific_plugin() -> None:
    plugin_name = "".join(chr(code) for code in (111, 112, 101, 110, 101, 109, 114))
    program = "\n".join(
        (
            "import sys",
            "import agentforge.target.spec",
            "import agentforge.target.registry",
            "import agentforge.target.adapter_registry",
            "blocked = {'httpx', 'fastapi', 'sqlalchemy'}",
            "assert not (blocked & set(sys.modules))",
            f"assert 'agentforge.target.{plugin_name}_adapter' not in sys.modules",
        )
    )
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src"), "PYTHONNOUSERSITE": "1"},
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
