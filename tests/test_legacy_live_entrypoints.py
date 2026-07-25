"""Fail-closed contracts for retired direct-live launchers.

These are structural/no-network tests only. They do not create campaign evidence and never stand in
for the post-deployment Langfuse query-back required of an authorized live Railway run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentforge.campaign.runtime import RuntimeConfigError, live_adapter_factory

ROOT = Path(__file__).resolve().parent.parent
RETIRED_SCRIPTS = (
    Path("scripts/platform_live_run.py"),
    Path("scripts/live_campaign.py"),
    Path("scripts/live_retry.py"),
    Path("scripts/live_probe.py"),
)


@pytest.mark.parametrize("relative_path", RETIRED_SCRIPTS, ids=lambda path: path.name)
def test_retired_script_refuses_without_credentials_or_side_effects(relative_path: Path) -> None:
    """Every former direct-live executable exits before asking for target credentials."""

    completed = subprocess.run(
        [sys.executable, str(ROOT / relative_path)],
        cwd=ROOT,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 2
    stderr = completed.stderr.lower()
    assert "legacy live execution is disabled" in stderr
    assert "durablecampaignrunner" in stderr
    assert "langfuse" in stderr
    assert "not set" not in stderr


@pytest.mark.parametrize("relative_path", RETIRED_SCRIPTS, ids=lambda path: path.name)
def test_retired_script_contains_no_target_transport(relative_path: Path) -> None:
    """The retained script surface cannot construct or send through the old target adapter."""

    source = (ROOT / relative_path).read_text(encoding="utf-8")
    assert "OpenEmrAdapter" not in source
    assert "TargetRequest" not in source
    assert ".send(" not in source


def test_legacy_live_adapter_factory_is_permanently_disabled() -> None:
    """Stale callers cannot recover the old lazy live transport from the shared runtime module."""

    with pytest.raises(RuntimeConfigError, match="legacy live execution is disabled"):
        live_adapter_factory()
