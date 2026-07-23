"""M1d private process and fail-closed runner dispatch contracts."""

from __future__ import annotations

import socket

import pytest

from agentforge.runner import DispatchUnavailable, process_agent_work
from agentforge.scheduler import DurableScheduler, SchedulerUnavailable, enqueue_due_work


class _Job:
    payload = {"campaign_run_id": "run-real", "attempt_id": "attempt-real"}
    campaign_run_id = "run-real"
    attempt_id = "attempt-real"


class _ControlPlane:
    def __init__(self, *, dispatchable: bool) -> None:
        self.dispatchable = dispatchable
        self.completed = False

    def resolve_dispatch(self, campaign_run_id: str, attempt_id: str):
        if not self.dispatchable:
            raise DispatchUnavailable("authorization_not_dispatchable")
        return {"scope": "canonical-server-scope"}

    def record_result_and_complete(self, *_args, **_kwargs) -> None:
        self.completed = True


class _Adapters:
    def __init__(self) -> None:
        self.calls = 0

    def resolve(self, scope):
        self.calls += 1
        return object()


def test_runner_never_constructs_adapter_before_server_authorization() -> None:
    control = _ControlPlane(dispatchable=False)
    adapters = _Adapters()

    with pytest.raises(DispatchUnavailable):
        process_agent_work(_Job(), control_plane=control, adapters=adapters)

    assert adapters.calls == 0
    assert control.completed is False


def test_runner_uses_only_persisted_job_identity_not_payload_routing() -> None:
    class HostileJob(_Job):
        payload = {
            "campaign_run_id": "run-attacker",
            "attempt_id": "attempt-attacker",
            "host": "evil.example",
            "adapter": "attacker.module.Adapter",
            "approved": True,
            "permissions": ["org:campaign:authorize"],
        }

    control = _ControlPlane(dispatchable=False)
    adapters = _Adapters()

    with pytest.raises(DispatchUnavailable):
        process_agent_work(HostileJob(), control_plane=control, adapters=adapters)

    assert adapters.calls == 0


def test_runner_requires_executor_and_atomic_commit_before_adapter_construction() -> None:
    control = _ControlPlane(dispatchable=True)
    adapters = _Adapters()

    with pytest.raises(DispatchUnavailable, match="trusted_execution_composition_missing"):
        process_agent_work(_Job(), control_plane=control, adapters=adapters)
    assert adapters.calls == 0

    class MissingCommit:
        def resolve_dispatch(self, _campaign_run_id: str, _attempt_id: str):
            return {"scope": "canonical-server-scope"}

    with pytest.raises(DispatchUnavailable, match="atomic_result_commit_missing"):
        process_agent_work(
            _Job(),
            control_plane=MissingCommit(),
            adapters=adapters,
            executor=lambda *_args: object(),
        )
    assert adapters.calls == 0


def test_scheduler_without_authoritative_schedule_repository_is_unavailable() -> None:
    with pytest.raises(SchedulerUnavailable):
        enqueue_due_work(schedule_repository=None, queue=None)


def test_private_process_checks_do_not_bind_public_sockets(monkeypatch) -> None:
    def forbidden_bind(self, address):  # pragma: no cover - assertion helper
        raise AssertionError(f"private process attempted to bind {address!r}")

    monkeypatch.setattr(socket.socket, "bind", forbidden_bind)

    from agentforge.runner import check_runtime as check_runner
    from agentforge.scheduler import check_runtime as check_scheduler

    assert check_runner(database_url=None) is False
    assert check_scheduler(database_url=None) is False


def test_scheduler_runs_as_a_private_heartbeat_process(migrated_db) -> None:
    scheduler = DurableScheduler(
        engine=migrated_db,
        environment="staging",
        planner=lambda _engine: 0,
    )

    assert scheduler.run_once() == 0

    from sqlalchemy import text

    with migrated_db.connect() as connection:
        row = connection.execute(
            text(
                "SELECT availability, detail FROM runtime_component_status "
                "WHERE environment = 'staging' AND component_id = 'scheduler'"
            )
        ).one()
    assert row.availability == "operational and evidenced"
    assert "0 replay plan(s)" in row.detail
