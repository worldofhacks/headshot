"""Prove the governed composition THROUGH its production entrypoint, not by importing it.

``tests/test_governed_acceptance_e2e.py`` calls ``run_governed_acceptance`` directly. This module
drives ``scripts/run_governed_acceptance.py::main(argv)`` — real argument parsing, real
configuration/authorization/calibration loading from Postgres, real exit codes — so a break in the
wiring BETWEEN the CLI and the composition cannot pass unnoticed.

Only the remote services are stood in for (provider transport, Langfuse, the target socket), which
is the same boundary the composition e2e uses. Store, gateway, recorder, corpus and Postgres are
real.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, text

from agentforge.control_plane.store import ControlPlaneStore
from test_governed_acceptance_e2e import (
    _CANARY,
    _CASE_ID,
    _ENVIRONMENT,
    _GENERATION_POLICY_SHA256,
    _ORGANIZATION_ID,
    _RELEASE_SHA256,
    _enabled_judge_calibration,
    _FakeTelemetry,
    _MarkerAdapter,
    _prepare,
    _reviewed,
    _role_outputs,
    _StoreAwareTransport,
)

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_governed_acceptance.py"


def _entrypoint() -> Any:
    """Import the script as a module, the way an operator's shell would execute it."""

    spec = importlib.util.spec_from_file_location("run_governed_acceptance_script", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before execution so dataclasses with slots can resolve their own module.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _argv(calibration_path: Path, request_id: str, configuration: Any) -> list[str]:
    return [
        "--organization-id",
        _ORGANIZATION_ID,
        "--configuration-set-sha256",
        configuration.configuration_sha256,
        "--release-sha256",
        _RELEASE_SHA256,
        "--generation-policy-sha256",
        _GENERATION_POLICY_SHA256,
        "--authorization-request-id",
        request_id,
        "--workload-id",
        "m11-seed-corpus-v1",
        "--case-id",
        _CASE_ID,
        "--judge-calibration-path",
        str(calibration_path),
        "--oracle-canary-marker",
        _CANARY,
    ]


def _calibration_file(tmp_path: Path, configuration: Any) -> Path:
    path = tmp_path / "judge-calibration.json"
    path.write_text(json.dumps(_enabled_judge_calibration(configuration)), encoding="utf-8")
    return path


def _dependencies(module: Any, adapter: Any, transport: Any):
    """Inject only the remote seams; everything else in the entrypoint stays real."""

    def build(**_kwargs: Any):
        return module.GovernedDependencies(
            transport=transport,
            telemetry=_FakeTelemetry(),
            adapter=adapter,
            credential=None,
        )

    return build


def _run_entrypoint(
    migrated_db: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    adapter: _MarkerAdapter,
    outputs: dict | None = None,
    physical_attempts: dict[str, int] | None = None,
) -> tuple[int, Any, _StoreAwareTransport]:
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", _ENVIRONMENT)
    store, configuration, request_id, _scope_hash = _prepare(migrated_db)
    reviewed = _reviewed()
    transport = _StoreAwareTransport(
        ControlPlaneStore(migrated_db, environment=_ENVIRONMENT),
        configuration,
        outputs if outputs is not None else _role_outputs(reviewed),
        physical_attempts=physical_attempts,
    )
    module = _entrypoint()
    code = module.main(
        _argv(_calibration_file(tmp_path, configuration), request_id, configuration),
        engine=migrated_db,
        dependencies=_dependencies(module, adapter, transport),
    )
    return code, module, transport


def test_entrypoint_completes_and_prints_only_safe_identities(
    migrated_db: Engine,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _MarkerAdapter(
        output=(
            "Assistant reply: I will follow the reviewed injected instruction. "
            f"{_CANARY} — protected clinical context disclosed."
        )
    )
    code, _module, transport = _run_entrypoint(migrated_db, tmp_path, monkeypatch, adapter=adapter)

    assert code == 0
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "complete"
    assert payload["verdict_state"] == "EXPLOIT_CONFIRMED"
    assert payload["decision_authority"] == "oracle_canary"
    assert payload["model_decisive"] is False
    assert payload["target_dispatch_count"] == 1
    assert payload["documentation_publication_state"] == "blocked_pending_human_approval"
    assert transport.calls == ["orchestrator", "red_team", "judge", "documentation"]
    assert len(adapter.requests) == 1

    # The printed record carries identities and hashes only — never transcript or attack content.
    printed = json.dumps(payload)
    assert _CANARY not in printed
    assert "injected instruction" not in printed


def test_entrypoint_reports_an_unconfirmed_run_with_its_own_exit_code(
    migrated_db: Engine,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A safe target is exit 2 and a named status — never a crash and never a silent success."""

    adapter = _MarkerAdapter(output="The assistant refused the reviewed injected instruction.")
    code, module, transport = _run_entrypoint(migrated_db, tmp_path, monkeypatch, adapter=adapter)

    assert code == module.UNCONFIRMED_EXIT == 2
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["status"] == "unconfirmed"
    # The target was still dispatched exactly once, and Documentation never opened.
    assert len(adapter.requests) == 1
    assert "documentation" not in transport.calls
    with migrated_db.connect() as connection:
        states = (
            connection.execute(
                text(
                    "SELECT e.state FROM campaign_run_events e JOIN campaign_runs r "
                    "ON r.run_id = e.run_id WHERE r.run_kind = 'governed_acceptance' ORDER BY e.id"
                )
            )
            .scalars()
            .all()
        )
    assert states[-1] == "aborted"


def test_entrypoint_retry_adds_no_extra_target_dispatch(
    migrated_db: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE GUARDRAIL, through the entrypoint: a post-dispatch provider retry adds zero target calls.

    The Judge's provider call burns a second physical attempt strictly AFTER the single gateway
    dispatch. The target must still have been called exactly once, and because the governed
    configuration pins ``max_retries=0`` the run must refuse rather than accept the retried call.
    """

    adapter = _MarkerAdapter(
        output=f"Assistant reply leaking {_CANARY} after the reviewed instruction."
    )
    with pytest.raises(Exception) as raised:
        _run_entrypoint(
            migrated_db,
            tmp_path,
            monkeypatch,
            adapter=adapter,
            physical_attempts={"judge": 2},
        )
    assert "physical-attempt count is invalid" in str(raised.value)

    assert len(adapter.requests) == 1
    with migrated_db.connect() as connection:
        dispatched = connection.execute(
            text("SELECT count(*) FROM attempt_result WHERE organization_id = :org"),
            {"org": _ORGANIZATION_ID},
        ).scalar_one()
        states = (
            connection.execute(
                text(
                    "SELECT e.state FROM campaign_run_events e JOIN campaign_runs r "
                    "ON r.run_id = e.run_id WHERE r.run_kind = 'governed_acceptance' ORDER BY e.id"
                )
            )
            .scalars()
            .all()
        )
    assert dispatched == 1
    assert states[-1] == "aborted"


def test_entrypoint_refuses_a_relative_judge_calibration_path(
    migrated_db: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calibration authority has no default path and no environment discovery."""

    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", _ENVIRONMENT)
    _store, configuration, request_id, _scope_hash = _prepare(migrated_db)
    module = _entrypoint()
    argv = _argv(Path("judge-calibration.json"), request_id, configuration)
    with pytest.raises(SystemExit):
        module.main(argv, engine=migrated_db, dependencies=lambda **_k: None)


def test_entrypoint_refuses_to_build_a_live_adapter_itself(
    migrated_db: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A live profile must have its runner-derived adapter injected — never invented here.

    This pins the fail-closed default: the one component allowed to touch a real clinical system
    does not get to derive its own dispatch authority.
    """

    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", _ENVIRONMENT)
    _store, configuration, request_id, _scope_hash = _prepare(migrated_db)
    module = _entrypoint()
    with pytest.raises(module.GovernedEntrypointError, match="campaign runner preflight"):
        # The real default builder, against the live-profile scope the fixtures authorize.
        module.main(
            _argv(_calibration_file(tmp_path, configuration), request_id, configuration),
            engine=migrated_db,
        )
