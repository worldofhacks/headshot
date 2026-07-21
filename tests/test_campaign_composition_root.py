"""Composition-root integration tests — the ACTUAL ``python -m agentforge.campaign run …`` command.

Anchors: M11-coordinator composition root (``agentforge.campaign.__main__`` + ``runtime.py``). The
rest of the campaign suite drives the injection-driven ``cli.main`` in-process with fakes; NONE of
it invokes the real module entry, so a non-runnable entry (the old ``exit 2`` guard that built no
dependencies) sailed through CI green. These tests close that gap by launching the documented
command as a SUBPROCESS and asserting it is genuinely runnable — it constructs its real production
dependencies (a real engine, a real live-adapter factory, a real clock, real accounting) and reaches
the fail-closed AUTHORIZATION gate — rather than refusing for want of an injected wiring.

**No network, by construction.** Every case here drives the command down a PRE-DISPATCH path: with
no authorization the coordinator BLOCKS at the authorization gate (step 1) — before the credential
is resolved, before the gateway dispatches, before the lazy adapter/engine ever open a socket. The
real target is never contacted. A missing ``DATABASE_URL`` fails even earlier, at composition. So
the command runs for real, yet no socket to the target or the DB is ever opened.
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


def test_run_command_composes_real_deps_and_reaches_the_authorization_gate(tmp_path: Path) -> None:
    """The documented command is RUNNABLE: it builds its real production dependencies and reaches
    the fail-closed AUTHORIZATION gate, refusing (exit 1) because no grant was supplied — NOT exit 2
    for want of an injected wiring.

    This is the proof the composition root exists: previously ``python -m agentforge.campaign``
    exited 2 unconditionally (it constructed nothing). Now it composes the engine + live-adapter
    factory + clock + accounting and runs the coordinator, which blocks at the authorization gate.
    No network is opened — the block precedes any dispatch.
    """
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
    # It is RUNNABLE and GATED: a fail-closed authorization refusal (exit 1), not the old
    # "not wired" exit 2, and not a crash.
    assert completed.returncode == 1, (
        f"expected a fail-closed authorization refusal (exit 1); got {completed.returncode}. "
        f"stderr={completed.stderr!r}"
    )
    assert "refused" in stderr
    assert "authoriz" in stderr  # blocked at the authorization gate
    # The OLD non-runnable guard message must be GONE — the entry no longer refuses to wire itself.
    assert "requires an explicit authorized wiring" not in stderr
    # Nothing dispatched: no run-config manifest is written for a run refused at the gate.
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").rglob("config.json"))


def test_run_command_missing_database_url_is_a_fail_closed_operational_error(
    tmp_path: Path,
) -> None:
    """A missing ``DATABASE_URL`` fails closed at COMPOSITION with a typed operational error (exit
    2) and a legible message — the bounded run never launches against an unspecified evidence store.

    This is distinct from the authorization refusal above (exit 1): the composition root refuses to
    build a runtime it cannot specify, rather than silently defaulting to some database.
    """
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
        f"expected an operational error (exit 2) for a missing DATABASE_URL; "
        f"got {completed.returncode}. stderr={completed.stderr!r}"
    )
    stderr = completed.stderr.lower()
    assert "operational-error" in stderr
    assert "database_url" in stderr


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
