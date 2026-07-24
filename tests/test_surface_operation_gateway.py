"""T-F16b RED: gateway-owned, retry-inclusive physical surface operations.

These tests define the generic boundary later evidence/UI/document adapters consume.  A flow is a
pure state machine: it may emit one typed operation and consume one typed response, but only the
Policy Gateway owns the injected one-operation sender.  All collaborators below are deterministic
and networkless.
"""

from __future__ import annotations

import dataclasses
import datetime
import socket
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from agentforge.auth.permissions import CAMPAIGN_AUTHORIZE, CAMPAIGN_LAUNCH
from agentforge.auth.principal import Principal
from agentforge.campaign.authorization import AuthorizationError, RunAuthorization
from agentforge.campaign.binding import BindingError, TargetBinding
from agentforge.campaign.coordinator import (
    RunConfig,
    SecureCampaignCoordinator,
)
from agentforge.campaign.manifest import ManifestStore
from agentforge.config import Settings
from agentforge.control_plane.errors import RecordConflictError
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.policy import gateway as gateway_module
from agentforge.policy.allowlist import Allowlist, AllowlistEntry
from agentforge.policy.gateway import (
    AbortError,
    PolicyGateway,
    RunPolicy,
    WorkUnitCoordinates,
)
from agentforge.storage.queue import JobRecord, LogicalQueue, PostgresJobQueue
from agentforge.target import base as target_base
from agentforge.target.base import (
    TargetRequest,
    TargetResponse,
    TargetSessionExpiredError,
    TargetUnreachableError,
)
from agentforge.target.catalog import TrustedTargetCatalog
from agentforge.target.spec import (
    AuthMode,
    ExecutionProfile,
    FixtureDescriptor,
    SafetyCaps,
    SurfaceOperationTemplate,
    SurfacePolicy,
)

_FAKE_TARGET_ID = "fake"
_BASE_URL = "https://copilot.example.test"
_ATTEMPT_ID = "attempt-t-f16b"
_SECRET_CANARY = "SESSION-CANARY-MUST-NOT-LEAK"
_BODY_CANARY = "BODY-CANARY-MUST-NOT-LEAK"
_ORG = "org_TF16bOperationFixture"
_CORPUS_HASH = "9" * 64
_CORPUS_ID = "headshot-live-100-v1"
_LEASE = datetime.timedelta(minutes=5)


class _Clock:
    def __init__(self, start: float = 0.0) -> None:
        self.value = start

    def now(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _Accounting:
    def __init__(self, per_call_usd: float = 0.01) -> None:
        self.per_call_usd = per_call_usd
        self.spent_usd = 0.0
        self.charges = 0

    def charge(self) -> None:
        self.charges += 1
        self.spent_usd += self.per_call_usd


@dataclasses.dataclass(frozen=True)
class _DurableRun:
    store: ControlPlaneStore
    job: JobRecord
    run_id: str


def _principal(user_id: str, permission: str) -> Principal:
    return Principal(
        user_id=user_id,
        session_id=f"sess_{user_id.removeprefix('user_')}",
        organization_id=_ORG,
        organization_role="org:operator",
        organization_permissions=frozenset({permission}),
    )


def _clean_control_plane(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE campaign_work_unit_reservations, agent_executions, "
                "agent_configuration_versions, regression_dispositions, vuln_reports, "
                "campaign_run_summaries, finding_evidence_links, finding_decision_events, "
                "finding, verdict, attempt_result, audit_events, command_idempotency, "
                "campaign_attempts, campaign_run_events, campaign_runs, "
                "campaign_authorization_decisions, campaign_authorization_requests, "
                "surface_state_events, attack_surface_definitions, surface_identities, "
                "target_lifecycle_events, target_definitions, target_identities, jobs "
                "RESTART IDENTITY CASCADE"
            )
        )


def _running_operation_run(
    engine: Engine,
    *,
    physical_count: int = 3,
    retry_count: int = 2,
) -> _DurableRun:
    _clean_control_plane(engine)
    launcher = _principal("user_TF16bLauncher", CAMPAIGN_LAUNCH)
    approver = _principal("user_TF16bApprover", CAMPAIGN_AUTHORIZE)
    store = ControlPlaneStore(engine, environment="staging")
    TrustedTargetCatalog.from_environment("staging").synchronize(
        store,
        organization_id=_ORG,
    )
    scope = store.build_scope(
        principal=launcher,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=_CORPUS_ID,
        corpus_hash=_CORPUS_HASH,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=1,
            target_requests_per_second=100.0,
            run_timeout_seconds=300.0,
            logical_case_limit=1,
            physical_request_limit=physical_count,
            target_retries_per_turn=retry_count,
        ),
        run_nonce="t-f16b-operation-run-nonce",
        execution_profile=ExecutionProfile.SYNTHETIC,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="request",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="approval",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="launch",
    )
    queue = PostgresJobQueue(
        engine,
        supported_payload_versions={
            LogicalQueue.AGENT_WORK: {"campaign.execute": (1,)},
        },
    )
    job = queue.claim(
        LogicalQueue.AGENT_WORK,
        worker_id="t-f16b-operation-worker",
        lease_duration=_LEASE,
    )
    assert job is not None
    store.append_campaign_state(run_id=run.run_id, state="running")
    return _DurableRun(store=store, job=job, run_id=run.run_id)


def _durable_rows(engine: Engine, run_id: str) -> list[dict[str, Any]]:
    with engine.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT attempt_id, turn_index, retry_index, observed_at, "
                    "observation_outcome FROM campaign_work_unit_reservations "
                    "WHERE run_id = :run_id ORDER BY turn_index, retry_index"
                ),
                {"run_id": run_id},
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


class _ForbiddenLegacyAdapter:
    """The operation path must never fall back to the legacy adapter.send boundary."""

    name = "fake"
    turn_delivery = "atomic"

    def __init__(self) -> None:
        self.calls: list[TargetRequest] = []

    def send(self, request: TargetRequest) -> TargetResponse:
        self.calls.append(request)
        raise AssertionError("surface operation bypassed the injected one-operation sender")


class _CoordinatorLegacyAdapter(_ForbiddenLegacyAdapter):
    name = "openemr"
    base_url = _BASE_URL


class _LegacyAdapter:
    name = "fake"

    def __init__(self, *, sequential: bool = False) -> None:
        self.turn_delivery = "sequential" if sequential else "atomic"
        self.calls: list[TargetRequest] = []

    def send(self, request: TargetRequest) -> TargetResponse:
        self.calls.append(request)
        return TargetResponse(
            output="ok",
            metadata={"adapter": self.name, "trace_id": f"legacy-{len(self.calls)}"},
        )


class _ScriptedFlow:
    """Test-owned pure state machine; deliberately has no sender/client/transport attribute."""

    def __init__(
        self,
        first: Any,
        advance: Callable[[Any, Any, int], Any | None] | None = None,
        *,
        declared_physical_maximum: int | None = None,
    ) -> None:
        self._first = first
        self._advance = advance or (lambda _operation, _response, _completed: None)
        self._completed = 0
        self.declared_physical_maximum = declared_physical_maximum

    def start(self) -> Any:
        return self._first

    def advance(self, operation: Any, response: Any) -> Any | None:
        self._completed += 1
        return self._advance(operation, response, self._completed)


def _require_operation_api() -> tuple[type[Any], type[Any], type[BaseException]]:
    missing = [
        name
        for name in ("SurfaceOperation", "SurfaceOperationResponse")
        if not hasattr(target_base, name)
    ]
    if not hasattr(gateway_module, "OperationFlowAborted"):
        missing.append("OperationFlowAborted")
    if not hasattr(PolicyGateway, "execute_operation_flow"):
        missing.append("PolicyGateway.execute_operation_flow")
    assert not missing, "T-F16b operation-flow boundary is absent; missing " + ", ".join(
        sorted(missing)
    )
    return (
        target_base.__dict__["SurfaceOperation"],
        target_base.__dict__["SurfaceOperationResponse"],
        gateway_module.__dict__["OperationFlowAborted"],
    )


def _operation(
    operation_class: str,
    method: str,
    relative_path: str,
    *,
    payload: Any = None,
) -> Any:
    operation_type, _, _ = _require_operation_api()
    return operation_type(
        operation_class=operation_class,
        method=method,
        relative_path=relative_path,
        payload=payload,
    )


def _response(
    *,
    status: int = 200,
    content_type: str = "application/json",
    byte_count: int = 2,
    payload: Any = None,
    trace_ref: str = "trace-1",
) -> Any:
    _, response_type, _ = _require_operation_api()
    return response_type(
        status=status,
        content_type=content_type,
        byte_count=byte_count,
        payload={} if payload is None else payload,
        trace_ref=trace_ref,
    )


def _template(
    operation_class: str,
    method: str,
    relative_path: str,
    *,
    retry_count: int,
    maximum_logical_operations: int = 1,
    request_content_type: str | None = None,
    response_content_types: tuple[str, ...] = ("application/json",),
    credential_placement: str = "none",
    credential_field_name: str | None = None,
) -> SurfaceOperationTemplate:
    return SurfaceOperationTemplate(
        operation_class=operation_class,
        method=method,
        relative_path=relative_path,
        request_content_type=request_content_type,
        response_content_types=response_content_types,
        credential_placement=credential_placement,
        credential_field_name=credential_field_name,
        retry_count=retry_count,
        maximum_logical_operations=maximum_logical_operations,
    )


def _policy_from(
    *templates: SurfaceOperationTemplate,
    adapter_profile: str = "generic_surface",
    response_size_limit_bytes: int = 1_024,
    auth_mode: AuthMode = AuthMode.NONE,
) -> SurfacePolicy:
    logical = sum(template.maximum_logical_operations for template in templates)
    physical = sum(
        template.maximum_logical_operations * (template.retry_count + 1) for template in templates
    )
    return SurfacePolicy(
        schema="agentforge.target-surface-policy",
        schema_version=2,
        adapter_profile=adapter_profile,
        auth_mode=auth_mode,
        credential_ref=(
            None
            if auth_mode is AuthMode.NONE
            else "secretref://production/clinical-copilot/session/generation-test"
        ),
        explicit_no_auth=auth_mode is AuthMode.NONE,
        redirect_policy="deny",
        response_size_limit_bytes=response_size_limit_bytes,
        request_timeout_seconds=30.0,
        tls_required=True,
        operation_templates=templates,
        maximum_logical_operations=logical,
        physical_request_limit=physical,
        fixture_descriptors=(),
    )


def _generic_policy(*, retries: int = 2) -> SurfacePolicy:
    return _policy_from(
        _template("generic_read", "GET", "resource", retry_count=retries),
    )


def _lab_policy() -> SurfacePolicy:
    templates = (
        _template(
            "upload",
            "POST",
            "documents",
            retry_count=0,
            request_content_type="multipart/form-data",
            credential_placement="multipart",
            credential_field_name="session_id",
        ),
        _template(
            "status_poll",
            "GET",
            "documents/{document_id}/status",
            retry_count=1,
            maximum_logical_operations=30,
            credential_placement="query",
            credential_field_name="session_id",
        ),
        _template(
            "report",
            "GET",
            "documents/{document_id}/report",
            retry_count=1,
            credential_placement="query",
            credential_field_name="session_id",
        ),
        _template(
            "preview",
            "GET",
            "documents/{document_id}/preview",
            retry_count=1,
            response_content_types=("image/png",),
            credential_placement="query",
            credential_field_name="session_id",
        ),
        _template(
            "readback",
            "GET",
            "documents/{document_id}",
            retry_count=1,
            response_content_types=("application/pdf",),
            credential_placement="query",
            credential_field_name="session_id",
        ),
    )
    return SurfacePolicy(
        schema="agentforge.target-surface-policy",
        schema_version=2,
        adapter_profile="generic_document_flow",
        auth_mode=AuthMode.SESSION,
        credential_ref="secretref://production/clinical-copilot/session/generation-test",
        explicit_no_auth=False,
        redirect_policy="deny",
        response_size_limit_bytes=10_485_760,
        request_timeout_seconds=30.0,
        tls_required=True,
        operation_templates=templates,
        maximum_logical_operations=34,
        physical_request_limit=67,
        fixture_descriptors=(
            FixtureDescriptor(
                opaque_ref="fixture://tests/t-f16b/lab",
                sha256="b" * 64,
                byte_length=753,
                media_type="application/pdf",
                doc_type="lab_pdf",
                workflow_id="lab-extraction-v1",
            ),
        ),
    )


def _run_policy(
    *,
    budget_usd: float = 10.0,
    physical_request_limit: int = 100,
    target_requests_per_second: float = 1.0,
    run_timeout_seconds: float = 1_000.0,
) -> RunPolicy:
    return RunPolicy(
        budget_usd=budget_usd,
        max_attempts_per_run=100,
        target_requests_per_second=target_requests_per_second,
        run_timeout_seconds=run_timeout_seconds,
        logical_case_limit=100,
        physical_request_limit=physical_request_limit,
        target_retries_per_turn=0,
    )


def _gateway(
    *,
    sender: Callable[[Any], Any],
    clock: _Clock | None = None,
    accounting: _Accounting | None = None,
    reservation_observer: Callable[[Any], None] | None = None,
    pre_operation_gate: Callable[[Any], None] | None = None,
    operation_observer: Callable[[Any], None] | None = None,
    legacy_adapter: Any | None = None,
) -> tuple[PolicyGateway, _Clock, _Accounting, Any]:
    _require_operation_api()
    actual_clock = clock or _Clock()
    actual_accounting = accounting or _Accounting()
    actual_legacy_adapter = legacy_adapter or _ForbiddenLegacyAdapter()
    try:
        gateway = PolicyGateway(
            allowlist=Allowlist([AllowlistEntry(target_id=_FAKE_TARGET_ID, adapter_name="fake")]),
            adapter=actual_legacy_adapter,
            settings=Settings(environment="local"),
            clock=actual_clock,
            accounting=actual_accounting,
            sleeper=lambda _seconds: None,
            operation_sender=sender,
            operation_flow_reserver=reservation_observer,
            pre_operation_gate=pre_operation_gate,
            post_operation_observer=operation_observer,
        )
    except TypeError as exc:
        pytest.fail(f"T-F16b PolicyGateway injection seams are absent: {exc}")
    return gateway, actual_clock, actual_accounting, actual_legacy_adapter


def _execute_flow(
    gateway: PolicyGateway,
    flow: _ScriptedFlow,
    surface_policy: SurfacePolicy,
    run_policy: RunPolicy | None = None,
    *,
    authorization_expires_at: float = 2_000.0,
    lease_expires_at: float = 2_000.0,
    trace_capacity: int = 100,
    surface_policy_sha256: str | None = None,
) -> Any:
    try:
        return gateway.execute_operation_flow(
            flow,
            surface_policy,
            run_policy or _run_policy(),
            target_id=_FAKE_TARGET_ID,
            base_url=_BASE_URL,
            surface_policy_sha256=surface_policy_sha256 or surface_policy.policy_hash(),
            authorization_expires_at=authorization_expires_at,
            lease_expires_at=lease_expires_at,
            trace_capacity=trace_capacity,
            attempt_id=_ATTEMPT_ID,
        )
    except TypeError as exc:
        pytest.fail(f"T-F16b execute_operation_flow contract is incomplete: {exc}")


def _operation_coordinator(
    engine: Engine,
    manifest_root: Any,
    durable: _DurableRun,
    *,
    clock: _Clock,
    accounting: _Accounting,
    reserver: Callable[[WorkUnitCoordinates], None],
    observer: Callable[[WorkUnitCoordinates, str], None],
    pre_dispatch_gate: Callable[[str], None],
) -> SecureCampaignCoordinator:
    authorized = durable.store.load_run_for_execution(durable.run_id)
    scope = authorized.scope
    binding = TargetBinding(
        target_id=scope.target_id,
        host=scope.exact_host,
        adapter_kind=scope.adapter_kind,
        credential_ref=scope.credential_ref,
        auth_mode=scope.auth_mode.value,
    )
    run_policy = RunPolicy(**scope.caps.canonical_payload())
    adapter = _CoordinatorLegacyAdapter()
    adapter.name = scope.adapter_kind
    adapter.base_url = f"https://{scope.exact_host}"

    def revalidate_then_reserve(coordinates: WorkUnitCoordinates) -> None:
        """Mirror Runner composition: persisted gates precede every durable reservation."""

        pre_dispatch_gate(coordinates.attempt_id)
        reserver(coordinates)

    return SecureCampaignCoordinator(
        config=RunConfig(
            binding=binding,
            authorization=RunAuthorization(
                operation_hash=authorized.run.scope_hash,
                run_nonce=scope.run_nonce,
                deadline=authorized.expires_at.timestamp(),
            ),
            policy=run_policy,
            run_nonce=scope.run_nonce,
            canary_token="synthetic",
            environment="local",
            corpus_id=scope.corpus_id,
            corpus_sha=scope.corpus_hash,
            authorization_operation_hash=authorized.run.scope_hash,
            campaign_run_id=durable.run_id,
            pre_dispatch_gate=pre_dispatch_gate,
            work_unit_reserver=revalidate_then_reserve,
            work_unit_observer=observer,
            dispatch_sleeper=clock.advance,
        ),
        adapter=adapter,
        engine=engine,
        manifests=ManifestStore(root=manifest_root),
        clock=clock,
        accounting=accounting,
    )


def _execute_coordinator_flow(
    coordinator: SecureCampaignCoordinator,
    flow: _ScriptedFlow,
    surface_policy: SurfacePolicy,
    *,
    operation_sender: Callable[[Any], Any],
    attempt_id: str,
    lease_expires_at: float,
    trace_capacity: int,
) -> Any:
    _require_operation_api()
    assert hasattr(SecureCampaignCoordinator, "execute_operation_flow"), (
        "T-F16b coordinator operation-flow entrypoint is absent"
    )
    authorization = coordinator.config.authorization
    assert authorization is not None
    try:
        return coordinator.execute_operation_flow(
            flow,
            surface_policy,
            operation_sender=operation_sender,
            surface_policy_sha256=surface_policy.policy_hash(),
            authorization_expires_at=authorization.deadline,
            lease_expires_at=lease_expires_at,
            trace_capacity=trace_capacity,
            attempt_id=attempt_id,
        )
    except TypeError as exc:
        pytest.fail(f"T-F16b coordinator operation-flow contract is incomplete: {exc}")


# spec(T-F16b:AC-1)
def test_spec_t_f16b_ac_1_lab_preflight_reserves_retry_inclusive_67_before_upload() -> None:
    events: list[str] = []
    reservations: list[Any] = []
    sent: list[Any] = []

    def reserve(reservation: Any) -> None:
        events.append("reserve")
        reservations.append(reservation)

    def send(operation: Any) -> Any:
        events.append("send")
        sent.append(operation)
        return _response(payload={"document_id": "doc_123"}, trace_ref="trace-upload")

    gateway, _clock, accounting, legacy = _gateway(
        sender=send,
        reservation_observer=reserve,
    )
    policy = _lab_policy()
    result = _execute_flow(
        gateway,
        _ScriptedFlow(
            _operation(
                "upload",
                "POST",
                "documents",
                payload={"session_id": _SECRET_CANARY},
            )
        ),
        policy,
        trace_capacity=67,
    )

    assert policy.maximum_logical_operations == 34
    assert policy.physical_request_limit == 67
    assert events[:2] == ["reserve", "send"]
    assert len(reservations) == 1
    reservation = reservations[0]
    assert reservation.maximum_logical_operations == 34
    assert reservation.maximum_physical_attempts == 67
    assert reservation.projected_cost_usd == pytest.approx(0.67)
    assert reservation.minimum_rate_window_seconds == pytest.approx(66.0)
    assert reservation.trace_slots == 67
    assert reservation.authorization_expires_at == 2_000.0
    assert reservation.lease_expires_at == 2_000.0
    assert reservation.run_deadline == 1_000.0
    assert result.physical_attempt_count == accounting.charges == 1
    assert len(sent) == 1
    assert legacy.calls == []


# spec(T-F16b:AC-1)
@pytest.mark.parametrize(
    ("dimension", "run_policy", "authorization_expiry", "lease_expiry", "trace_capacity"),
    [
        ("physical", _run_policy(physical_request_limit=66), 2_000.0, 2_000.0, 67),
        ("budget", _run_policy(budget_usd=0.66), 2_000.0, 2_000.0, 67),
        ("timeout", _run_policy(run_timeout_seconds=65.0), 2_000.0, 2_000.0, 67),
        ("authorization", _run_policy(), 65.0, 2_000.0, 67),
        ("lease", _run_policy(), 2_000.0, 65.0, 67),
        ("trace", _run_policy(), 2_000.0, 2_000.0, 66),
    ],
)
def test_spec_t_f16b_ac_1_any_insufficient_full_flow_capacity_refuses_before_write(
    dimension: str,
    run_policy: RunPolicy,
    authorization_expiry: float,
    lease_expiry: float,
    trace_capacity: int,
) -> None:
    sent: list[Any] = []
    reservations: list[Any] = []
    gateway, _clock, accounting, legacy = _gateway(
        sender=lambda operation: sent.append(operation) or _response(),
        reservation_observer=reservations.append,
    )

    with pytest.raises(AbortError) as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(
                _operation(
                    "upload",
                    "POST",
                    "documents",
                    payload={"session_id": _SECRET_CANARY},
                )
            ),
            _lab_policy(),
            run_policy,
            authorization_expires_at=authorization_expiry,
            lease_expires_at=lease_expiry,
            trace_capacity=trace_capacity,
        )

    assert dimension in str(caught.value).lower()
    assert sent == []
    assert accounting.charges == 0
    assert legacy.calls == []
    assert len(reservations) <= 1


# spec(T-F16b:AC-2)
# spec(T-F16b:AC-4)
def test_spec_t_f16b_ac_2_4_fail_twice_succeed_third_reserves_and_accounts_three() -> None:
    calls: list[Any] = []
    gates: list[Any] = []
    traces: list[Any] = []
    reservations: list[Any] = []

    def send(operation: Any) -> Any:
        calls.append(operation)
        if len(calls) < 3:
            raise TargetUnreachableError(f"transient-{len(calls)}")
        return _response(trace_ref="trace-third")

    gateway, clock, accounting, legacy = _gateway(
        sender=send,
        reservation_observer=reservations.append,
        pre_operation_gate=gates.append,
        operation_observer=traces.append,
    )
    result = _execute_flow(
        gateway,
        _ScriptedFlow(_operation("generic_read", "GET", "resource")),
        _generic_policy(retries=2),
        _run_policy(physical_request_limit=3),
        trace_capacity=3,
    )

    assert reservations[0].maximum_physical_attempts == 3
    assert len(calls) == accounting.charges == result.physical_attempt_count == 3
    assert [gate.coordinates.retry_index for gate in gates] == [0, 1, 2]
    assert [gate.remaining_physical_attempts for gate in gates] == [3, 2, 1]
    assert [trace.outcome for trace in traces] == ["raised", "raised", "returned"]
    assert [trace.trace_ref for trace in traces] == [None, None, "trace-third"]
    assert clock.now() >= 6.0
    assert legacy.calls == []


# spec(T-F16b:AC-2)
# spec(T-F16b:AC-5)
# spec(T-F16b:AC-6)
@pytest.mark.parametrize(
    "mode",
    ["retry-success", "terminal-failure", "lease-revoked"],
)
def test_spec_t_f16b_ac_2_5_6_coordinator_persists_each_physical_operation_once(
    migrated_db: Engine,
    tmp_path: Any,
    mode: str,
) -> None:
    _require_operation_api()
    durable = _running_operation_run(migrated_db)
    attempt = durable.store.ensure_campaign_attempt(
        run_id=durable.run_id,
        ordinal=0,
        case_id="case-operation-flow",
    )
    coordinates: list[WorkUnitCoordinates] = []
    calls: list[Any] = []
    dispatch_checks: list[str] = []
    events: list[str] = []
    clock = _Clock()
    accounting = _Accounting()
    hostile = f"{_SECRET_CANARY} {_BODY_CANARY} " + ("hostile-exception-" * 300)

    def pre_dispatch(attempt_id: str) -> None:
        dispatch_checks.append(attempt_id)
        if mode == "lease-revoked" and calls:
            events.append("gate-blocked")
            raise AbortError("persisted lease revoked", code="lease-revoked")
        durable.store.assert_job_lease(durable.job)
        durable.store.resolve_dispatch(durable.run_id, attempt_id)
        events.append("gate")

    def reserve(item: WorkUnitCoordinates) -> None:
        durable.store.reserve_campaign_work_unit(
            job=durable.job,
            attempt_id=item.attempt_id,
            turn_index=item.turn_index,
            retry_index=item.retry_index,
        )
        coordinates.append(item)
        events.append("reserve")

    def observe(item: WorkUnitCoordinates, outcome: str) -> None:
        durable.store.observe_campaign_work_unit(
            job=durable.job,
            attempt_id=item.attempt_id,
            turn_index=item.turn_index,
            retry_index=item.retry_index,
            outcome=outcome,
        )
        events.append("observe")

    def send(operation: Any) -> Any:
        assert coordinates, "sender ran without a durable reservation"
        current = coordinates[-1]
        with migrated_db.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT observed_at FROM campaign_work_unit_reservations "
                        "WHERE run_id = :run_id AND attempt_id = :attempt_id "
                        "AND turn_index = :turn_index AND retry_index = :retry_index"
                    ),
                    {
                        "run_id": durable.run_id,
                        "attempt_id": current.attempt_id,
                        "turn_index": current.turn_index,
                        "retry_index": current.retry_index,
                    },
                )
                .mappings()
                .one()
            )
        assert row["observed_at"] is None
        calls.append(operation)
        events.append("send")
        if mode == "terminal-failure":
            raise TargetSessionExpiredError(hostile)
        if mode == "lease-revoked":
            raise TargetUnreachableError("retry reaches persisted lease gate")
        if len(calls) < 3:
            raise TargetUnreachableError(f"durable-retry-{len(calls)}")
        return _response(trace_ref="trace-durable-third")

    coordinator = _operation_coordinator(
        migrated_db,
        tmp_path,
        durable,
        clock=clock,
        accounting=accounting,
        reserver=reserve,
        observer=observe,
        pre_dispatch_gate=pre_dispatch,
    )
    flow = _ScriptedFlow(_operation("generic_read", "GET", "resource"))

    caught: BaseException | None = None
    if mode != "retry-success":
        _, _, operation_error = _require_operation_api()
        with pytest.raises(operation_error) as excinfo:
            _execute_coordinator_flow(
                coordinator,
                flow,
                _generic_policy(retries=2),
                operation_sender=send,
                attempt_id=attempt.attempt_id,
                lease_expires_at=durable.job.lease_expires_at.timestamp(),
                trace_capacity=3,
            )
        caught = excinfo.value
    else:
        result = _execute_coordinator_flow(
            coordinator,
            flow,
            _generic_policy(retries=2),
            operation_sender=send,
            attempt_id=attempt.attempt_id,
            lease_expires_at=durable.job.lease_expires_at.timestamp(),
            trace_capacity=3,
        )
        assert result.physical_attempt_count == 3

    expected_count = 3 if mode == "retry-success" else 1
    rows = _durable_rows(migrated_db, durable.run_id)
    assert len(calls) == accounting.charges == len(coordinates) == len(rows) == expected_count
    assert [(row["turn_index"], row["retry_index"]) for row in rows] == [
        (0, retry_index) for retry_index in range(expected_count)
    ]
    assert all(row["observed_at"] is not None for row in rows)
    assert [row["observation_outcome"] for row in rows] == (
        ["raised"] if mode != "retry-success" else ["raised", "raised", "returned"]
    )
    assert dispatch_checks.count(attempt.attempt_id) >= expected_count
    completed_boundary = 0
    for send_index in (index for index, event in enumerate(events) if event == "send"):
        assert events[send_index - 1] == "reserve"
        assert "gate" in events[completed_boundary : send_index - 1]
        assert events[send_index + 1] == "observe"
        completed_boundary = send_index + 2
    if mode == "lease-revoked":
        assert events[-1] == "gate-blocked"

    if mode == "terminal-failure":
        assert caught is not None
        assert 0 < len(caught.terminal_reason) <= 160
        rendered = f"{caught!s} {caught!r} {caught.__cause__!r} {rows!r}"
        assert _SECRET_CANARY not in rendered
        assert _BODY_CANARY not in rendered
        assert "hostile-exception-" not in rendered

    with pytest.raises(RecordConflictError, match="already reserved"):
        durable.store.reserve_campaign_work_unit(
            job=durable.job,
            attempt_id=attempt.attempt_id,
            turn_index=0,
            retry_index=0,
        )
    with pytest.raises(DBAPIError), migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE campaign_work_unit_reservations SET observation_outcome = 'returned' "
                "WHERE run_id = :run_id AND attempt_id = :attempt_id "
                "AND turn_index = 0 AND retry_index = 0"
            ),
            {"run_id": durable.run_id, "attempt_id": attempt.attempt_id},
        )
    assert coordinator.adapter.calls == []


# spec(T-F16b:AC-2)
# spec(T-F16b:AC-6)
@pytest.mark.parametrize("refusal", ["authorization-scope", "binding"])
def test_spec_t_f16b_ac_2_6_coordinator_revalidates_authority_before_operation_sender(
    migrated_db: Engine,
    tmp_path: Any,
    refusal: str,
) -> None:
    _require_operation_api()
    durable = _running_operation_run(migrated_db, physical_count=1, retry_count=0)
    attempt = durable.store.ensure_campaign_attempt(
        run_id=durable.run_id,
        ordinal=0,
        case_id=f"case-{refusal}",
    )
    sends: list[Any] = []
    reservations: list[WorkUnitCoordinates] = []
    clock = _Clock()
    accounting = _Accounting()
    coordinator = _operation_coordinator(
        migrated_db,
        tmp_path,
        durable,
        clock=clock,
        accounting=accounting,
        reserver=reservations.append,
        observer=lambda _coordinates, _outcome: None,
        pre_dispatch_gate=lambda _attempt_id: None,
    )
    if refusal == "authorization-scope":
        authorization = coordinator.config.authorization
        assert authorization is not None
        coordinator.config = dataclasses.replace(
            coordinator.config,
            authorization=dataclasses.replace(authorization, operation_hash="0" * 64),
        )
        expected_error: type[BaseException] = AuthorizationError
        match = "scope"
    else:
        coordinator.adapter.name = "wrong-adapter"
        expected_error = BindingError
        match = "bound adapter|adapter kind"

    with pytest.raises(expected_error, match=match):
        _execute_coordinator_flow(
            coordinator,
            _ScriptedFlow(_operation("generic_read", "GET", "resource")),
            _generic_policy(retries=0),
            operation_sender=lambda operation: sends.append(operation) or _response(),
            attempt_id=attempt.attempt_id,
            lease_expires_at=durable.job.lease_expires_at.timestamp(),
            trace_capacity=1,
        )

    assert sends == []
    assert reservations == []
    assert accounting.charges == 0
    assert _durable_rows(migrated_db, durable.run_id) == []
    assert coordinator.adapter.calls == []


# spec(T-F16b:AC-2)
# spec(T-F16b:AC-5)
@pytest.mark.parametrize(
    "gate_failure",
    ["authorization", "abort", "lease", "integrity", "capacity"],
)
def test_spec_t_f16b_ac_2_5_each_attempt_revalidates_and_gate_failure_stops_before_send(
    gate_failure: str,
) -> None:
    calls: list[Any] = []
    checked: list[Any] = []
    traces: list[Any] = []

    def guard(context: Any) -> None:
        checked.append(context)
        assert context.surface_policy_sha256 == _generic_policy().policy_hash()
        assert context.operation.method == "GET"
        assert context.operation.relative_path == "resource"
        assert context.absolute_url == f"{_BASE_URL}/resource"
        assert context.response_size_limit_bytes == 1_024
        assert context.request_timeout_seconds == 30.0
        if len(checked) == 2:
            raise AbortError(f"{gate_failure} revoked", code=f"{gate_failure}-revoked")

    def send(operation: Any) -> Any:
        calls.append(operation)
        raise TargetUnreachableError("retry me")

    gateway, _clock, accounting, legacy = _gateway(
        sender=send,
        pre_operation_gate=guard,
        operation_observer=traces.append,
    )
    _, _, operation_error = _require_operation_api()
    with pytest.raises(operation_error, match=gate_failure) as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("generic_read", "GET", "resource")),
            _generic_policy(retries=2),
            _run_policy(physical_request_limit=3),
            trace_capacity=3,
        )

    assert len(checked) == 2
    assert len(calls) == accounting.charges == len(traces) == 1
    assert traces[0].outcome == "raised"
    assert caught.value.physical_attempt_count == 1
    assert caught.value.trace_refs == ()
    assert legacy.calls == []


# spec(T-F16b:AC-2)
# spec(T-F16b:AC-5)
@pytest.mark.parametrize("dimension", ["budget", "rate", "timeout"])
def test_spec_t_f16b_ac_2_5_native_budget_rate_or_timeout_stops_before_retry(
    dimension: str,
) -> None:
    calls: list[Any] = []
    traces: list[Any] = []
    clock = _Clock()
    accounting = _Accounting()

    def send(operation: Any) -> Any:
        calls.append(operation)
        if dimension == "budget":
            accounting.spent_usd = 1.0
            raise TargetUnreachableError("retry after concurrent spend")
        if dimension == "rate":
            clock.advance(0.1)
            raise TargetUnreachableError("retry would enter the native rate window")
        clock.advance(31.0)
        raise TargetUnreachableError("retry after deadline")

    gateway, _actual_clock, _actual_accounting, legacy = _gateway(
        sender=send,
        clock=clock,
        accounting=accounting,
        operation_observer=traces.append,
    )
    _, _, operation_error = _require_operation_api()
    with pytest.raises(operation_error, match=dimension) as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("generic_read", "GET", "resource")),
            _generic_policy(retries=2),
            _run_policy(
                budget_usd=1.0,
                physical_request_limit=3,
                target_requests_per_second=1.0,
                run_timeout_seconds=30.0,
            ),
            trace_capacity=3,
        )

    assert len(calls) == accounting.charges == len(traces) == 1
    assert traces[0].outcome == "raised"
    assert caught.value.physical_attempt_count == 1
    assert legacy.calls == []


# spec(T-F16b:AC-2)
# spec(T-F16b:AC-5)
def test_spec_t_f16b_ac_2_5_budget_becoming_insufficient_blocks_later_logical_operation() -> None:
    calls: list[Any] = []
    traces: list[Any] = []
    accounting = _Accounting()
    surface_policy = _policy_from(
        _template("first_read", "GET", "first", retry_count=0),
        _template("second_read", "GET", "second", retry_count=0),
    )

    def advance(_operation_value: Any, _response_value: Any, completed: int) -> Any | None:
        if completed == 1:
            accounting.spent_usd = 1.0
            return _operation("second_read", "GET", "second")
        return None

    gateway, _clock, _actual_accounting, legacy = _gateway(
        sender=lambda operation: calls.append(operation) or _response(trace_ref="trace-first"),
        accounting=accounting,
        operation_observer=traces.append,
    )
    _, _, operation_error = _require_operation_api()
    with pytest.raises(operation_error, match="budget") as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("first_read", "GET", "first"), advance),
            surface_policy,
            _run_policy(budget_usd=1.0, physical_request_limit=2),
            trace_capacity=2,
        )

    assert len(calls) == accounting.charges == len(traces) == 1
    assert traces[0].outcome == "returned"
    assert caught.value.physical_attempt_count == 1
    assert legacy.calls == []


# spec(T-F16b:AC-2)
def test_spec_t_f16b_ac_2_policy_hash_mismatch_refuses_before_sender() -> None:
    sent: list[Any] = []
    checked: list[Any] = []
    gateway, _clock, accounting, legacy = _gateway(
        sender=lambda operation: sent.append(operation) or _response(),
        pre_operation_gate=checked.append,
    )

    with pytest.raises(AbortError, match="policy|hash|integrity"):
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("generic_read", "GET", "resource")),
            _generic_policy(retries=0),
            _run_policy(physical_request_limit=1),
            trace_capacity=1,
            surface_policy_sha256="0" * 64,
        )

    assert sent == []
    assert checked == []
    assert accounting.charges == 0
    assert legacy.calls == []


# spec(T-F16b:AC-3)
def test_spec_t_f16b_ac_3_typed_transition_accepts_one_closed_dynamic_segment() -> None:
    sent: list[Any] = []

    def advance(_operation: Any, response: Any, completed: int) -> Any | None:
        if completed == 1:
            return _operation_factory(
                "status_poll",
                "GET",
                f"documents/{response.payload['document_id']}/status",
            )
        return None

    def send(operation: Any) -> Any:
        sent.append(operation)
        if operation.operation_class == "upload":
            return _response(payload={"document_id": "Doc_7-safe"}, trace_ref="trace-upload")
        return _response(payload={"state": "complete"}, trace_ref="trace-status")

    gateway, _clock, accounting, legacy = _gateway(sender=send)
    flow = _ScriptedFlow(
        _operation("upload", "POST", "documents"),
        advance,
    )
    result = _execute_flow(gateway, flow, _lab_policy(), trace_capacity=67)

    assert [(item.operation_class, item.method, item.relative_path) for item in sent] == [
        ("upload", "POST", "documents"),
        ("status_poll", "GET", "documents/Doc_7-safe/status"),
    ]
    assert result.physical_attempt_count == accounting.charges == 2
    assert legacy.calls == []


def _operation_factory(operation_class: str, method: str, relative_path: str) -> Any:
    """Named separately so flow callbacks cannot be mistaken for a transport callback."""
    return _operation(operation_class, method, relative_path)


def _observation_sink(
    sink: list[tuple[WorkUnitCoordinates, str]],
) -> Callable[[WorkUnitCoordinates, str], None]:
    def observe(coordinates: WorkUnitCoordinates, outcome: str) -> None:
        sink.append((coordinates, outcome))

    return observe


# spec(T-F16b:AC-3)
@pytest.mark.parametrize(
    "hostile_path",
    [
        "https://evil.example/status",
        "//evil.example/status",
        "documents/../secrets/status",
        "documents/doc%2Fescape/status",
        "documents/doc%252Fescape/status",
        "documents/doc/status?next=https://evil.example",
        "documents/doc/extra/status",
        "documents//status",
    ],
)
def test_spec_t_f16b_ac_3_host_query_traversal_encoding_or_extra_segment_is_refused(
    hostile_path: str,
) -> None:
    sent: list[Any] = []

    def advance(_prior_operation: Any, _response_value: Any, completed: int) -> Any | None:
        if completed == 1:
            return _operation("status_poll", "GET", hostile_path)
        return None

    gateway, _clock, accounting, legacy = _gateway(
        sender=lambda operation: (
            sent.append(operation) or _response(payload={"document_id": "doc"})
        ),
    )
    with pytest.raises(AbortError, match="path|template|transition|destination"):
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("upload", "POST", "documents"), advance),
            _lab_policy(),
            trace_capacity=67,
        )

    assert len(sent) == accounting.charges == 1
    assert legacy.calls == []


# spec(T-F16b:AC-3)
@pytest.mark.parametrize(
    ("operation_class", "method", "path"),
    [
        ("status_poll", "POST", "documents/doc_1/status"),
        ("unlisted_delete", "DELETE", "documents/doc_1"),
        ("report", "GET", "documents/doc_1/preview"),
        ("preview", "GET", "documents/doc_1/preview"),
    ],
)
def test_spec_t_f16b_ac_3_unlisted_class_method_or_typed_template_is_refused(
    operation_class: str,
    method: str,
    path: str,
) -> None:
    sent: list[Any] = []

    def advance(_operation: Any, _response_value: Any, completed: int) -> Any | None:
        if completed == 1:
            return _operation_factory(operation_class, method, path)
        return None

    gateway, _clock, accounting, _legacy = _gateway(
        sender=lambda operation: sent.append(operation) or _response(),
    )
    with pytest.raises(AbortError, match="method|template|transition|operation"):
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("upload", "POST", "documents"), advance),
            _lab_policy(),
            trace_capacity=67,
        )

    assert len(sent) == accounting.charges == 1


# spec(T-F16b:AC-3)
# spec(T-F16b:AC-6)
def test_spec_t_f16b_ac_3_6_flow_understatement_cannot_reduce_bound_policy_reservation() -> None:
    reservations: list[Any] = []
    sent: list[Any] = []
    gateway, _clock, _accounting, _legacy = _gateway(
        sender=lambda operation: sent.append(operation) or _response(),
        reservation_observer=reservations.append,
    )
    flow = _ScriptedFlow(
        _operation("upload", "POST", "documents"),
        declared_physical_maximum=1,
    )
    _execute_flow(gateway, flow, _lab_policy(), trace_capacity=67)

    assert flow.declared_physical_maximum == 1
    assert reservations[0].maximum_logical_operations == 34
    assert reservations[0].maximum_physical_attempts == 67
    assert len(sent) == 1


# spec(T-F16b:AC-3)
def test_spec_t_f16b_ac_3_declared_logical_operation_maximum_stops_expansion() -> None:
    sent: list[Any] = []

    def advance(_prior_operation: Any, _response_value: Any, _completed: int) -> Any:
        return _operation("status_poll", "GET", "documents/doc_1/status")

    gateway, _clock, accounting, _legacy = _gateway(
        sender=lambda operation: (
            sent.append(operation)
            or _response(payload={"state": "processing"}, trace_ref=f"trace-{len(sent)}")
        ),
    )
    with pytest.raises(AbortError, match="maximum|operation|flow"):
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("upload", "POST", "documents"), advance),
            _lab_policy(),
            trace_capacity=67,
        )

    assert len(sent) == accounting.charges == 31  # upload + exactly thirty authorized polls


# spec(T-F16b:AC-1)
# spec(T-F16b:AC-3)
# spec(T-F16b:AC-4)
def test_spec_t_f16b_ac_1_3_4_complete_mixed_lab_flow_uses_exactly_67_not_68() -> None:
    operations = [
        _operation("upload", "POST", "documents"),
        *[_operation("status_poll", "GET", "documents/doc_1/status") for _index in range(30)],
        _operation("report", "GET", "documents/doc_1/report"),
        _operation("preview", "GET", "documents/doc_1/preview"),
        _operation("readback", "GET", "documents/doc_1"),
    ]
    sent: list[Any] = []
    gates: list[Any] = []
    traces: list[Any] = []
    reservations: list[Any] = []

    def advance(_prior: Any, _response_value: Any, completed: int) -> Any:
        if completed < len(operations):
            return operations[completed]
        return _operation("readback", "GET", "documents/doc_1")

    def send(operation: Any) -> Any:
        assert gates, "sender ran before the immediate operation gate"
        sent.append(operation)
        if operation.operation_class != "upload" and gates[-1].coordinates.retry_index == 0:
            raise TargetUnreachableError("first read attempt is transient")
        content_type = {
            "preview": "image/png",
            "readback": "application/pdf",
        }.get(operation.operation_class, "application/json")
        payload = (
            {"document_id": "doc_1"}
            if operation.operation_class == "upload"
            else {"state": "complete"}
        )
        return _response(
            content_type=content_type,
            payload=payload,
            trace_ref=f"trace-mixed-{len(sent)}",
        )

    gateway, clock, accounting, legacy = _gateway(
        sender=send,
        reservation_observer=reservations.append,
        pre_operation_gate=gates.append,
        operation_observer=traces.append,
    )
    _, _, operation_error = _require_operation_api()
    with pytest.raises(operation_error, match="maximum|physical|operation|flow") as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(operations[0], advance),
            _lab_policy(),
            _run_policy(
                budget_usd=1.0,
                physical_request_limit=67,
                target_requests_per_second=100.0,
                run_timeout_seconds=300.0,
            ),
            trace_capacity=67,
        )

    assert len(operations) == 34
    assert reservations[0].maximum_physical_attempts == 67
    assert len(sent) == accounting.charges == len(gates) == len(traces) == 67
    assert [operation.operation_class for operation in sent].count("upload") == 1
    assert [operation.operation_class for operation in sent].count("status_poll") == 60
    assert [operation.operation_class for operation in sent].count("report") == 2
    assert [operation.operation_class for operation in sent].count("preview") == 2
    assert [operation.operation_class for operation in sent].count("readback") == 2
    assert [(trace.coordinates.turn_index, trace.coordinates.retry_index) for trace in traces] == [
        (0, 0)
    ] + [(logical_index, retry_index) for logical_index in range(1, 34) for retry_index in (0, 1)]
    assert [trace.outcome for trace in traces].count("raised") == 33
    assert [trace.outcome for trace in traces].count("returned") == 34
    assert caught.value.physical_attempt_count == 67
    assert len(caught.value.trace_refs) == 34
    assert clock.now() >= 66.0
    assert legacy.calls == []


# spec(T-F16b:AC-4)
def test_spec_t_f16b_ac_4_ambiguous_zero_retry_upload_is_sent_exactly_once() -> None:
    calls: list[Any] = []
    traces: list[Any] = []

    def send(operation: Any) -> Any:
        calls.append(operation)
        raise TargetUnreachableError("ambiguous upload timeout")

    policy = _policy_from(
        _template(
            "state_change",
            "POST",
            "documents",
            retry_count=0,
            request_content_type="multipart/form-data",
        )
    )
    gateway, _clock, accounting, legacy = _gateway(
        sender=send,
        operation_observer=traces.append,
    )
    with pytest.raises(AbortError, match="after 1|exhaust|timeout|unreachable"):
        _execute_flow(
            gateway,
            _ScriptedFlow(
                _operation(
                    "state_change",
                    "POST",
                    "documents",
                    payload={"session_id": _SECRET_CANARY},
                )
            ),
            policy,
            _run_policy(physical_request_limit=1),
            trace_capacity=1,
        )

    assert len(calls) == accounting.charges == len(traces) == 1
    assert traces[0].outcome == "raised"
    assert legacy.calls == []


# spec(T-F16b:AC-2)
# spec(T-F16b:AC-4)
@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(
            TargetSessionExpiredError("delegated session ended"),
            id="non-retryable",
        ),
        pytest.param(RuntimeError("unexpected transport failure"), id="unexpected"),
    ],
)
def test_spec_t_f16b_ac_2_4_nonretryable_and_unexpected_failures_are_metered_once(
    failure: Exception,
) -> None:
    calls: list[Any] = []
    gates: list[Any] = []
    traces: list[Any] = []
    advances = 0

    def send(operation: Any) -> Any:
        calls.append(operation)
        raise failure

    def advance(_operation_value: Any, _response_value: Any, _completed: int) -> None:
        nonlocal advances
        advances += 1

    gateway, _clock, accounting, legacy = _gateway(
        sender=send,
        pre_operation_gate=gates.append,
        operation_observer=traces.append,
    )
    _, _, operation_error = _require_operation_api()
    with pytest.raises(operation_error) as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(
                _operation("generic_read", "GET", "resource"),
                advance,
            ),
            _generic_policy(retries=2),
            _run_policy(physical_request_limit=3),
            trace_capacity=3,
        )

    assert len(calls) == accounting.charges == len(gates) == len(traces) == 1
    assert gates[0].coordinates.retry_index == 0
    assert traces[0].coordinates.retry_index == 0
    assert traces[0].outcome == "raised"
    assert caught.value.physical_attempt_count == 1
    assert advances == 0
    assert legacy.calls == []


# spec(T-F16b:AC-4)
def test_spec_t_f16b_ac_4_document_poll_or_read_stops_after_second_failure() -> None:
    calls: list[Any] = []
    traces: list[Any] = []

    def send(operation: Any) -> Any:
        calls.append(operation)
        raise TargetUnreachableError("read unavailable")

    policy = _policy_from(
        _template("bounded_read", "GET", "documents/{document_id}", retry_count=1),
    )
    gateway, _clock, accounting, _legacy = _gateway(
        sender=send,
        operation_observer=traces.append,
    )
    with pytest.raises(AbortError, match="after 2|exhaust|unreachable"):
        _execute_flow(
            gateway,
            _ScriptedFlow(
                _operation("bounded_read", "GET", "documents/doc_1"),
            ),
            policy,
            _run_policy(physical_request_limit=2),
            trace_capacity=2,
        )

    assert len(calls) == accounting.charges == len(traces) == 2
    assert [trace.coordinates.retry_index for trace in traces] == [0, 1]


# spec(T-F16b:AC-5)
def test_spec_t_f16b_ac_5_terminal_trace_is_immutable_bounded_and_sanitized() -> None:
    traces: list[Any] = []
    advances = 0

    def send(_operation_value: Any) -> Any:
        return _response(
            status=200,
            byte_count=2_048,
            payload={"secret": _SECRET_CANARY, "body": _BODY_CANARY},
            trace_ref="trace-oversized",
        )

    def advance(_operation_value: Any, _response_value: Any, _completed: int) -> None:
        nonlocal advances
        advances += 1

    gateway, _clock, accounting, _legacy = _gateway(
        sender=send,
        operation_observer=traces.append,
    )
    _, _, operation_error = _require_operation_api()
    with pytest.raises(operation_error) as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("generic_read", "GET", "resource"), advance),
            _generic_policy(retries=0),
            _run_policy(physical_request_limit=1),
            trace_capacity=1,
        )

    error = caught.value
    assert error.physical_attempt_count == accounting.charges == 1
    assert error.trace_refs == ("trace-oversized",)
    assert 0 < len(error.terminal_reason) <= 160
    rendered = repr(error) + str(error) + repr(traces)
    assert _SECRET_CANARY not in rendered
    assert _BODY_CANARY not in rendered
    assert "payload" not in getattr(traces[0], "__dataclass_fields__", {})
    assert "body" not in getattr(traces[0], "__dataclass_fields__", {})
    assert dataclasses.is_dataclass(traces[0])
    assert advances == 0
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError)):
        traces[0].outcome = "forged"


# spec(T-F16b:AC-2)
# spec(T-F16b:AC-5)
@pytest.mark.parametrize("failure_site", ["transport", "retry-gate"])
def test_spec_t_f16b_ac_2_5_hostile_exception_text_is_bounded_and_never_persisted(
    failure_site: str,
) -> None:
    sent: list[Any] = []
    traces: list[Any] = []
    checks = 0
    hostile = f"{_SECRET_CANARY} {_BODY_CANARY} SESSION=synthetic-session " + (
        "attacker-controlled-" * 300
    )

    def guard(_context: Any) -> None:
        nonlocal checks
        checks += 1
        if failure_site == "retry-gate" and checks == 2:
            raise AbortError(hostile, code="hostile-gate-refusal")

    def send(operation: Any) -> Any:
        sent.append(operation)
        if failure_site == "transport":
            raise RuntimeError(hostile)
        raise TargetUnreachableError("first attempt requires retry")

    gateway, _clock, accounting, legacy = _gateway(
        sender=send,
        pre_operation_gate=guard,
        operation_observer=traces.append,
    )
    _, _, operation_error = _require_operation_api()
    with pytest.raises(operation_error) as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("generic_read", "GET", "resource")),
            _generic_policy(retries=2),
            _run_policy(physical_request_limit=3),
            trace_capacity=3,
        )

    error = caught.value
    expected_sends = 1
    assert len(sent) == accounting.charges == len(traces) == expected_sends
    assert traces[0].outcome == "raised"
    assert 0 < len(error.terminal_reason) <= 160
    rendered = f"{error!s} {error!r} {error.__cause__!r} {traces!r}"
    assert _SECRET_CANARY not in rendered
    assert _BODY_CANARY not in rendered
    assert "synthetic-session" not in rendered
    assert "attacker-controlled-" not in rendered
    assert error.physical_attempt_count == 1
    assert checks == (1 if failure_site == "transport" else 2)
    assert legacy.calls == []


# spec(T-F16b:AC-5)
def test_spec_t_f16b_ac_5_terminal_failure_preserves_completed_trace_and_stops_later_op() -> None:
    sent: list[Any] = []
    traces: list[Any] = []
    gate_calls = 0

    def guard(_context: Any) -> None:
        nonlocal gate_calls
        gate_calls += 1
        if gate_calls == 2:
            raise AbortError("lease expired", code="lease-expired")

    def advance(_operation_value: Any, _response_value: Any, completed: int) -> Any | None:
        if completed == 1:
            return _operation("status_poll", "GET", "documents/doc_1/status")
        return _operation("report", "GET", "documents/doc_1/report")

    gateway, _clock, accounting, _legacy = _gateway(
        sender=lambda operation: sent.append(operation) or _response(trace_ref="trace-upload"),
        pre_operation_gate=guard,
        operation_observer=traces.append,
    )
    _, _, operation_error = _require_operation_api()
    with pytest.raises(operation_error, match="lease") as caught:
        _execute_flow(
            gateway,
            _ScriptedFlow(_operation("upload", "POST", "documents"), advance),
            _lab_policy(),
            trace_capacity=67,
        )

    assert len(sent) == accounting.charges == len(traces) == 1
    assert traces[0].trace_ref == "trace-upload"
    assert traces[0].outcome == "returned"
    assert caught.value.physical_attempt_count == 1
    assert caught.value.trace_refs == ("trace-upload",)
    assert gate_calls == 2


# spec(T-F16b:AC-6)
@pytest.mark.parametrize(
    "sender_path",
    ["success", "retry-success", "typed-terminal", "unexpected-terminal"],
)
def test_spec_t_f16b_ac_6_flow_has_no_transport_bypass_and_sender_is_gateway_owned(
    monkeypatch: pytest.MonkeyPatch,
    sender_path: str,
) -> None:
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("network construction is forbidden")
        ),
    )
    sent: list[Any] = []
    traces: list[Any] = []

    def send(operation: Any) -> Any:
        sent.append(operation)
        if sender_path == "retry-success" and len(sent) == 1:
            raise TargetUnreachableError("one authorized retry")
        if sender_path == "typed-terminal":
            raise TargetSessionExpiredError("typed terminal")
        if sender_path == "unexpected-terminal":
            raise RuntimeError("unexpected terminal")
        return _response(trace_ref=f"trace-{sender_path}")

    flow = _ScriptedFlow(_operation("generic_read", "GET", "resource"))
    gateway, _clock, accounting, legacy = _gateway(
        sender=send,
        operation_observer=traces.append,
    )
    if sender_path.endswith("terminal"):
        _, _, operation_error = _require_operation_api()
        with pytest.raises(operation_error):
            _execute_flow(
                gateway,
                flow,
                _generic_policy(retries=1),
                _run_policy(physical_request_limit=2),
                trace_capacity=2,
            )
    else:
        result = _execute_flow(
            gateway,
            flow,
            _generic_policy(retries=1),
            _run_policy(physical_request_limit=2),
            trace_capacity=2,
        )
        assert result.physical_attempt_count == len(sent)

    assert not any(
        hasattr(flow, attribute)
        for attribute in ("send", "client", "transport", "session", "request")
    )
    expected_calls = 2 if sender_path == "retry-success" else 1
    assert len(sent) == accounting.charges == len(traces) == expected_calls
    expected_outcomes = {
        "success": ["returned"],
        "retry-success": ["raised", "returned"],
        "typed-terminal": ["raised"],
        "unexpected-terminal": ["raised"],
    }
    assert [trace.outcome for trace in traces] == expected_outcomes[sender_path]
    assert legacy.calls == []


# spec(T-F16b:AC-6)
def test_spec_t_f16b_ac_6_existing_atomic_and_sequential_chat_paths_remain_exact() -> None:
    for sequential, expected_calls in ((False, 1), (True, 2)):
        adapter = _LegacyAdapter(sequential=sequential)
        reservations: list[WorkUnitCoordinates] = []
        observations: list[tuple[WorkUnitCoordinates, str]] = []
        gateway = PolicyGateway(
            allowlist=Allowlist([AllowlistEntry(target_id=_FAKE_TARGET_ID, adapter_name="fake")]),
            adapter=adapter,
            settings=Settings(environment="local"),
            clock=_Clock(),
            accounting=_Accounting(),
            sleeper=lambda _seconds: None,
            pre_physical_send_gate=reservations.append,
            post_physical_send_observer=_observation_sink(observations),
        )
        policy = _run_policy(
            physical_request_limit=expected_calls,
            target_requests_per_second=100.0,
        )
        result = gateway.execute(
            {
                "schema_version": "1",
                "case_ref": f"chat-{sequential}",
                "input_sequence": ["one", "two"],
                "category": "prompt_injection",
            },
            policy,
            attempt_id=f"legacy-{sequential}",
        )

        assert len(adapter.calls) == gateway.physical_send_count == expected_calls
        assert gateway.completed_logical_cases == 1
        assert result.content_hash
        expected_coordinates = [
            WorkUnitCoordinates(
                attempt_id=f"legacy-{sequential}",
                turn_index=index,
                retry_index=0,
            )
            for index in range(expected_calls)
        ]
        assert reservations == expected_coordinates
        assert observations == [(coordinates, "returned") for coordinates in expected_coordinates]
