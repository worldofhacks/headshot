"""Fail-closed Runner admission immediately before live external I/O."""

from __future__ import annotations

import datetime
import hashlib
from types import SimpleNamespace

import pytest

from agentforge.campaign.coordinator import CampaignAbort
from agentforge.policy.scoped_credentials import (
    SealedEnvironmentCredentialResolver,
    SessionLeaseMetadata,
)
from agentforge.runner import (
    DispatchUnavailable,
    DurableCampaignRunner,
    ExternalIoAdmissionError,
    _RunnerExternalIoGuard,
)

_REFERENCE = "secretref://staging/openemr/session/generation-1"
_VALUE = "synthetic-session-value"


class _Scope:
    def __init__(self, credential_ref: str | None) -> None:
        self.credential_ref = credential_ref

    @staticmethod
    def canonical_bytes() -> bytes:
        return b"exact-scope"


class _Queue:
    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure
        self.extensions: list[datetime.timedelta] = []

    def heartbeat(self, _job: object, *, extension: datetime.timedelta) -> None:
        self.extensions.append(extension)
        if self.failure is not None:
            raise self.failure


class _Store:
    def __init__(self, authorized: object) -> None:
        self.authorized = authorized
        self.calls: list[str] = []

    def load_run_for_execution(self, _run_id: str) -> object:
        self.calls.append("authorization")
        return self.authorized

    def resolve_dispatch(self, _run_id: str, _attempt_id: str) -> object:
        self.calls.append("dispatch")
        return self.authorized

    def assert_job_lease(self, _job: object) -> None:
        self.calls.append("lease")


def _authorized(
    *,
    scope: _Scope,
    expires_at: datetime.datetime,
) -> object:
    return SimpleNamespace(
        run=SimpleNamespace(scope_hash="a" * 64),
        scope=scope,
        approval=SimpleNamespace(decision_id="decision-1"),
        expires_at=expires_at,
    )


def _guard(
    *,
    now: datetime.datetime,
    run_deadline: datetime.datetime,
    authorization_deadline: datetime.datetime,
    session_expires_at: datetime.datetime | None = None,
    queue: _Queue | None = None,
) -> tuple[_RunnerExternalIoGuard, _Queue, _Store]:
    scope = _Scope(_REFERENCE)
    metadata = (
        {
            _REFERENCE: SessionLeaseMetadata(
                generation="generation-1",
                expires_at=session_expires_at,
                value_sha256=hashlib.sha256(_VALUE.encode()).hexdigest(),
                expiry_source="operator_conservative_lease",
            )
        }
        if session_expires_at is not None
        else None
    )
    credentials = SealedEnvironmentCredentialResolver(
        {_REFERENCE: "TARGET_SESSION"},
        environment={"TARGET_SESSION": _VALUE},
        session_metadata=metadata,
    )
    lease = credentials.lease(
        _REFERENCE,
        now=lambda: now,
        require_session_metadata=False,
    )
    authorized = _authorized(scope=scope, expires_at=authorization_deadline)
    selected_queue = queue or _Queue()
    store = _Store(authorized)
    return (
        _RunnerExternalIoGuard(
            queue=selected_queue,
            store=store,
            job=SimpleNamespace(campaign_run_id="run-1"),
            authorized=authorized,
            scope=scope,
            credential_lease=lease,
            clock=SimpleNamespace(now=now.timestamp),
            run_deadline=run_deadline.timestamp(),
            authorization_deadline=authorization_deadline.timestamp(),
        ),
        selected_queue,
        store,
    )


def test_exact_run_deadline_equality_refuses_after_live_lease_revalidation() -> None:
    now = datetime.datetime(2026, 7, 24, 12, 0, tzinfo=datetime.UTC)
    guard, queue, store = _guard(
        now=now,
        run_deadline=now + datetime.timedelta(seconds=30),
        authorization_deadline=now + datetime.timedelta(minutes=5),
    )

    with pytest.raises(ExternalIoAdmissionError) as caught:
        guard.admit(timeout_seconds=30)

    assert caught.value.code == "run-deadline-insufficient"
    assert str(caught.value) == "run-deadline-insufficient"
    assert queue.extensions == [datetime.timedelta(minutes=10)]
    assert store.calls == ["authorization", "lease"]


def test_session_expiry_equality_refuses_while_metadata_absence_does_not() -> None:
    now = datetime.datetime(2026, 7, 24, 12, 0, tzinfo=datetime.UTC)
    timeout = datetime.timedelta(seconds=30)
    guard, _, _ = _guard(
        now=now,
        run_deadline=now + datetime.timedelta(minutes=5),
        authorization_deadline=now + datetime.timedelta(minutes=5),
        session_expires_at=now + timeout,
    )
    with pytest.raises(ExternalIoAdmissionError) as caught:
        guard.admit(timeout_seconds=timeout.total_seconds(), attempt_id="attempt-1")
    assert caught.value.code == "credential-session-deadline-insufficient"

    bearer_guard, _, bearer_store = _guard(
        now=now,
        run_deadline=now + datetime.timedelta(minutes=5),
        authorization_deadline=now + datetime.timedelta(minutes=5),
        session_expires_at=None,
    )
    bearer_guard.admit(timeout_seconds=timeout.total_seconds(), attempt_id="attempt-1")
    assert bearer_store.calls == ["dispatch", "lease"]


def test_lost_lease_is_bounded_typed_and_stops_before_authorization_reload() -> None:
    now = datetime.datetime(2026, 7, 24, 12, 0, tzinfo=datetime.UTC)

    class SyntheticLeaseLost(RuntimeError):
        pass

    guard, queue, store = _guard(
        now=now,
        run_deadline=now + datetime.timedelta(minutes=5),
        authorization_deadline=now + datetime.timedelta(minutes=5),
        queue=_Queue(SyntheticLeaseLost("deployment detail that must not persist")),
    )

    with pytest.raises(ExternalIoAdmissionError) as caught:
        guard.admit(timeout_seconds=30)

    assert caught.value.code == "runner-lease-lost"
    assert str(caught.value) == "runner-lease-lost"
    assert len(str(caught.value)) <= 64
    assert queue.extensions == [datetime.timedelta(minutes=10)]
    assert store.calls == []


def test_run_once_persists_nested_external_io_reason_without_deployment_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = SimpleNamespace(campaign_run_id="run-1")
    state_writes: list[dict[str, object]] = []
    failure_writes: list[dict[str, object]] = []

    class Queue:
        @staticmethod
        def claim(*_args: object, **_kwargs: object) -> object:
            return job

        @staticmethod
        def fail(_job: object, **values: object) -> None:
            failure_writes.append(values)

    class Store:
        @staticmethod
        def append_campaign_state(**values: object) -> None:
            state_writes.append(values)

    class Telemetry:
        @staticmethod
        def flush() -> None:
            return None

        @staticmethod
        def release_campaign(_run_id: str) -> None:
            return None

    runner = object.__new__(DurableCampaignRunner)
    runner.engine = object()
    runner.queue = Queue()
    runner.store = Store()
    runner.telemetry = Telemetry()

    def refuse(_job: object) -> None:
        try:
            raise ExternalIoAdmissionError("runner-lease-lost")
        except ExternalIoAdmissionError as cause:
            raise CampaignAbort(
                "higher-level wrapper without deployment details",
                code="orchestrator_execution_failed",
            ) from cause

    runner.execute_claimed = refuse  # type: ignore[method-assign]
    monkeypatch.setattr("agentforge.runner._schema_is_current", lambda _engine: True)

    with pytest.raises(DispatchUnavailable, match="runner-lease-lost"):
        runner.run_once(worker_id="runner-test")

    assert state_writes == [
        {
            "run_id": "run-1",
            "state": "aborted",
            "reason_code": "runner-lease-lost",
        }
    ]
    assert failure_writes == [
        {
            "failure_code": "runner-lease-lost",
            "retryable": False,
        }
    ]
