"""T-F16b RED: gateway-owned, retry-inclusive physical surface operations.

These tests define the generic boundary later evidence/UI/document adapters consume.  A flow is a
pure state machine: it may emit one typed operation and consume one typed response, but only the
Policy Gateway owns the injected one-operation sender.  All collaborators below are deterministic
and networkless.
"""

from __future__ import annotations

import dataclasses
import inspect
import socket
from collections.abc import Callable
from typing import Any

import pytest

from agentforge.config import Settings
from agentforge.policy.allowlist import Allowlist, AllowlistEntry
from agentforge.policy.gateway import (
    AbortError,
    PolicyGateway,
    RunPolicy,
    WorkUnitCoordinates,
)
from agentforge.target import base as target_base
from agentforge.target.base import (
    TargetRequest,
    TargetResponse,
    TargetUnreachableError,
)
from agentforge.target.spec import (
    AuthMode,
    FixtureDescriptor,
    SurfaceOperationTemplate,
    SurfacePolicy,
)

_FAKE_TARGET_ID = "fake"
_BASE_URL = "https://copilot.example.test"
_ATTEMPT_ID = "attempt-t-f16b"
_SECRET_CANARY = "SESSION-CANARY-MUST-NOT-LEAK"
_BODY_CANARY = "BODY-CANARY-MUST-NOT-LEAK"


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


class _ForbiddenLegacyAdapter:
    """The operation path must never fall back to the legacy adapter.send boundary."""

    name = "fake"
    turn_delivery = "atomic"

    def __init__(self) -> None:
        self.calls: list[TargetRequest] = []

    def send(self, request: TargetRequest) -> TargetResponse:
        self.calls.append(request)
        raise AssertionError("surface operation bypassed the injected one-operation sender")


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
    gateway_module = inspect.getmodule(PolicyGateway)
    assert gateway_module is not None
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
@pytest.mark.parametrize("gate_failure", ["authorization", "abort", "lease", "integrity"])
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
def test_spec_t_f16b_ac_6_flow_has_no_transport_bypass_and_sender_is_gateway_owned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("network construction is forbidden")
        ),
    )
    sent: list[Any] = []
    flow = _ScriptedFlow(_operation("generic_read", "GET", "resource"))
    gateway, _clock, accounting, legacy = _gateway(
        sender=lambda operation: sent.append(operation) or _response(),
    )
    result = _execute_flow(
        gateway,
        flow,
        _generic_policy(retries=0),
        _run_policy(physical_request_limit=1),
        trace_capacity=1,
    )

    assert not any(
        hasattr(flow, attribute)
        for attribute in ("send", "client", "transport", "session", "request")
    )
    method_source = inspect.getsource(PolicyGateway.execute_operation_flow)
    assert "operation_sender" in method_source
    assert "self.adapter.send" not in method_source
    assert "flow.send" not in method_source
    assert len(sent) == accounting.charges == result.physical_attempt_count == 1
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
