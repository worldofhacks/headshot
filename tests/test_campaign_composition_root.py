"""Legacy campaign entry-point tests.

The actual ``python -m agentforge.campaign run …`` command must refuse before reading local run
inputs, credentials, database configuration, or constructing a target adapter. ``scope`` remains a
network-free authorization-request authoring command. The private durable Railway Runner is the
only operational live executor.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# A syntactically-valid DSN the subprocess can compose an engine from. The engine connects LAZILY
# and the no-authorization path blocks BEFORE any DB use, so this is never actually dialed — it only
# has to be present (a missing DATABASE_URL is the separate operational-error case below).
_PRESENT_DATABASE_URL = "postgresql://agentforge:local_dev_only@localhost:5432/agentforge"

# Synthetic-only run inputs (never real PHI / secret / canary).
_BOUND_TARGET_ID = "openemr"
_BOUND_HOST = "copilot.example-openemr.org"
_BOUND_ADAPTER_KIND = "openemr"
_BOUND_CREDENTIAL_REF = "secretref://production/openemr"
_SYNTHETIC_CANARY = "SYNTH_CANARY_COMPOSITION_ROOT_9F1A"


def _write_run_inputs(tmp_path: Path) -> tuple[Path, Path]:
    """Write a valid immutable binding.json + fail-closed caps.json; return their paths."""
    binding = tmp_path / "binding.json"
    binding.write_text(
        json.dumps(
            {
                "target_id": _BOUND_TARGET_ID,
                "host": _BOUND_HOST,
                "adapter_kind": _BOUND_ADAPTER_KIND,
                "credential_ref": _BOUND_CREDENTIAL_REF,
                "auth_mode": "bearer",
            }
        ),
        encoding="utf-8",
    )
    caps = tmp_path / "caps.json"
    caps.write_text(
        json.dumps(
            {
                "budget_usd": 10.0,
                "max_attempts_per_run": 9,
                "target_requests_per_second": 1.0,
                "run_timeout_seconds": 60.0,
                "logical_case_limit": 9,
                "physical_request_limit": 9,
                "target_retries_per_turn": 0,
            }
        ),
        encoding="utf-8",
    )
    return binding, caps


def _run_argv(binding: Path, caps: Path, run_dir: Path) -> list[str]:
    """The ACTUAL documented command (no --authorization — a configured run is not authorized)."""
    return [
        sys.executable,
        "-m",
        "agentforge.campaign",
        "run",
        "--binding",
        str(binding),
        "--caps",
        str(caps),
        "--seeds-dir",
        "evals/seeds",
        "--run-dir",
        str(run_dir),
        "--run-nonce",
        "run-nonce-composition-root-0001",
        "--canary",
        _SYNTHETIC_CANARY,
        "--corpus-id",
        "m11-seed-corpus-v1",
    ]


def _repo_root() -> Path:
    """The repo root (two levels up) so the corpus path resolves in the subprocess cwd."""
    return Path(__file__).resolve().parent.parent


def test_run_command_refuses_before_runtime_composition(tmp_path: Path) -> None:
    """Even a present database URL cannot reactivate the retired direct-live path."""

    binding, caps = _write_run_inputs(tmp_path)
    env = {"DATABASE_URL": _PRESENT_DATABASE_URL}
    completed = subprocess.run(
        _run_argv(binding, caps, tmp_path / "runs"),
        cwd=_repo_root(),
        env={**_base_env(), **env},
        capture_output=True,
        text=True,
        timeout=120,
    )

    stderr = completed.stderr.lower()
    assert completed.returncode == 2, (
        f"expected a fail-closed retired-entry refusal (exit 2); got {completed.returncode}. "
        f"stderr={completed.stderr!r}"
    )
    assert "legacy live execution is disabled" in stderr
    assert "durablecampaignrunner" in stderr
    assert "langfuse" in stderr
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").rglob("config.json"))


def test_run_command_does_not_inspect_database_configuration(
    tmp_path: Path,
) -> None:
    """The same refusal occurs without ``DATABASE_URL`` because no runtime is composed."""

    binding, caps = _write_run_inputs(tmp_path)
    completed = subprocess.run(
        _run_argv(binding, caps, tmp_path / "runs"),
        cwd=_repo_root(),
        env=_base_env(),  # DATABASE_URL deliberately absent
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 2, (
        f"expected a retired-entry refusal (exit 2); "
        f"got {completed.returncode}. stderr={completed.stderr!r}"
    )
    stderr = completed.stderr.lower()
    assert "operational-error" in stderr
    assert "legacy live execution is disabled" in stderr
    assert "database_url" not in stderr


def test_scope_command_runs_without_a_database_url(tmp_path: Path) -> None:
    """The ``scope`` command runs via the ACTUAL module entry with NO ``DATABASE_URL`` — the router
    composes no runtime for it (it is network-free and needs no DB), and it emits an immutable
    authorization-REQUEST that names the operation hash but carries no grant (no deadline).

    This proves the composition root ROUTES scope away from the run runtime: requesting an
    authorization needs no live resource, no DB, and no target — only an authenticated Approver
    (not this command) can later approve the exact hash.
    """
    binding, caps = _write_run_inputs(tmp_path)
    out = tmp_path / "authorization-request.json"
    argv = [
        sys.executable,
        "-m",
        "agentforge.campaign",
        "scope",
        "--binding",
        str(binding),
        "--caps",
        str(caps),
        "--seeds-dir",
        "evals/seeds",
        "--run-nonce",
        "run-nonce-composition-root-0001",
        "--out",
        str(out),
    ]
    completed = subprocess.run(
        argv,
        cwd=_repo_root(),
        env=_base_env(),  # DATABASE_URL deliberately absent — scope needs none
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert completed.returncode == 0, (
        f"scope should run with no DATABASE_URL. stderr={completed.stderr!r}"
    )
    assert out.exists()
    artifact = json.loads(out.read_text(encoding="utf-8"))
    assert artifact["artifact"] == "authorization-request"
    assert "operation_hash" in artifact
    assert "deadline" not in artifact  # a request is not a grant
    assert "approval required" in completed.stdout.lower()


def _base_env() -> dict[str, str]:
    """A minimal, network-free environment for the subprocess with DATABASE_URL stripped.

    Carries PATH (so the interpreter resolves shared libs) and forces production off-switches off;
    DATABASE_URL is intentionally NOT included so callers add it explicitly when they need it.
    """
    import os

    keep = {k: v for k, v in os.environ.items() if k in {"PATH", "HOME", "LANG", "LC_ALL"}}
    # Ensure the editable-installed package is importable even if PATH-python differs.
    keep["PYTHONPATH"] = str(_repo_root() / "src")
    keep.pop("DATABASE_URL", None)
    return keep
