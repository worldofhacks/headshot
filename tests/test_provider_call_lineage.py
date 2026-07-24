"""T-F17b RED contracts for durable physical provider-call lineage.

These tests own the deterministic contract between the Runner, PostgreSQL, and the later
OpenRouter transport integration. They use only synthetic identifiers and a disposable local
PostgreSQL database. No provider, target, credential resolver, or external network is involved.
"""

from __future__ import annotations

import dataclasses
import datetime
import http.client
import importlib
import importlib.util
import os
import socket
import urllib.request
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from decimal import Decimal
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, inspect, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError

from agentforge.control_plane.errors import RecordConflictError, RecordNotFoundError
from agentforge.control_plane.store import ControlPlaneStore

_INVOCATIONS = "provider_call_invocations"
_EVENTS = "provider_call_events"
_LINEAGE_TABLES = {_INVOCATIONS, _EVENTS}
_ROLES = ("orchestrator", "red_team", "judge", "documentation")
_SHA256 = {
    "prompt": "1" * 64,
    "configuration_set": "2" * 64,
    "role_configuration": "3" * 64,
    "generation_policy": "4" * 64,
    "input": "5" * 64,
    "output": "6" * 64,
}
_STARTED = datetime.datetime(2026, 7, 24, 14, 0, tzinfo=datetime.UTC)
_FINISHED = _STARTED + datetime.timedelta(milliseconds=875)
_SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501"


def _lineage_api() -> ModuleType:
    """Load the missing feature inside a test, so collection stays healthy in RED."""

    if importlib.util.find_spec("agentforge.providers.lineage") is None:
        pytest.fail("T-F17b provider-call lineage module is missing")
    return importlib.import_module("agentforge.providers.lineage")


def _symbol(module: ModuleType, name: str) -> Any:
    value = getattr(module, name, None)
    if value is None:
        pytest.fail(f"T-F17b provider-call lineage symbol is missing: {name}")
    return value


def _logical_context(
    module: ModuleType,
    *,
    organization_id: str = "org_LineageA",
    campaign_run_id: str = "run-lineage-a",
    campaign_attempt_id: str = "attempt-lineage-a",
    logical_execution_id: str = "logical-lineage-a",
    parent_execution_id: str | None = "parent-lineage-a",
    agent_role: str = "judge",
    requested_model: str = "google/gemini-2.5-pro",
    configured_upstream: str = "Google",
    **overrides: object,
) -> Any:
    values: dict[str, object] = {
        "organization_id": organization_id,
        "campaign_run_id": campaign_run_id,
        "campaign_attempt_id": campaign_attempt_id,
        "logical_execution_id": logical_execution_id,
        "parent_execution_id": parent_execution_id,
        "agent_role": agent_role,
        "requested_model": requested_model,
        "configured_upstream": configured_upstream,
        "prompt_version": "1",
        "prompt_sha256": _SHA256["prompt"],
        "configuration_set_sha256": _SHA256["configuration_set"],
        "role_configuration_sha256": _SHA256["role_configuration"],
        "generation_policy_sha256": _SHA256["generation_policy"],
    }
    values.update(overrides)
    return _symbol(module, "ProviderLogicalContextV1")(**values)


def _terminal_event(
    module: ModuleType,
    invocation: Any,
    *,
    status: str = "succeeded",
    returned_model: str | None = "google/gemini-2.5-pro",
    upstream_provider: str | None = "Google",
    provider_request_id: str | None = "provider-request-lineage-a",
    input_tokens: int | None = 101,
    output_tokens: int | None = 23,
    reasoning_tokens: int | None = 11,
    cost_measurement_state: str = "measured",
    measured_cost_usd: Decimal | None = Decimal("0.012345"),
    error_code: str | None = None,
    **overrides: object,
) -> Any:
    values: dict[str, object] = {
        "invocation_id": invocation.invocation_id,
        "physical_sequence": invocation.physical_sequence,
        "status": status,
        "returned_model": returned_model,
        "upstream_provider": upstream_provider,
        "provider_request_id": provider_request_id,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning_tokens,
        "cost_measurement_state": cost_measurement_state,
        "measured_cost_usd": measured_cost_usd,
        "error_code": error_code,
        "finished_at": getattr(invocation, "started_at", _STARTED)
        + datetime.timedelta(milliseconds=875),
    }
    values.update(overrides)
    return _symbol(module, "ProviderTerminalEventV1")(**values)


def _store_method(store: ControlPlaneStore, name: str) -> Any:
    method = getattr(store, name, None)
    if method is None:
        pytest.fail(f"T-F17b ControlPlaneStore method is missing: {name}")
    return method


def _begin_physical_attempt(
    store: ControlPlaneStore,
    logical_context: Any,
    sequence: int,
) -> Any:
    return _store_method(store, "begin_physical_attempt")(logical_context, sequence)


def _finish_physical_attempt(
    store: ControlPlaneStore,
    invocation: Any,
    event: Any,
    *,
    final: bool,
) -> Any:
    return _store_method(store, "finish_physical_attempt")(invocation, event, final=final)


def _reconcile_unknown_physical_attempt(store: ControlPlaneStore, invocation: Any) -> Any:
    return _store_method(store, "reconcile_unknown_physical_attempt")(invocation)


def _assert_lineage_schema_exists(engine: Engine) -> None:
    tables = set(inspect(engine).get_table_names())
    missing = sorted(_LINEAGE_TABLES - tables)
    assert not missing, f"T-F17b migration has not created lineage tables: {missing}"


def _sqlstate(error: BaseException) -> str | None:
    current: BaseException | None = error
    while current is not None:
        state = getattr(current, "sqlstate", None)
        if state:
            return str(state)
        current = current.__cause__ or current.__context__
    return None


@contextmanager
def _as_role(connection: Connection, role: str) -> Iterator[None]:
    nested = connection.begin_nested()
    try:
        connection.execute(text(f"SET LOCAL ROLE {role}"))
        yield
    finally:
        if nested.is_active:
            nested.rollback()
        connection.execute(text("RESET ROLE"))


def _seed_logical_execution(
    engine: Engine,
    *,
    organization_id: str = "org_LineageA",
    run_id: str = "run-lineage-a",
    attempt_id: str = "attempt-lineage-a",
    logical_execution_id: str = "logical-lineage-a",
    parent_execution_id: str = "parent-lineage-a",
    measured_cost: Decimal | None = None,
    terminal: bool = False,
) -> None:
    """Seed the existing logical authority without invoking a target or provider."""

    suffix = hashlib_sha256(f"{organization_id}:{run_id}")[:16]
    request_id = f"request-{suffix}"
    scope_hash = hashlib_sha256(f"scope:{organization_id}:{run_id}")
    launcher = f"user_launcher_{suffix}"
    launcher_session = f"sess_launcher_{suffix}"
    approver = f"user_approver_{suffix}"
    approver_session = f"sess_approver_{suffix}"
    has_cost_state = "cost_measurement_state" in {
        column["name"] for column in inspect(engine).get_columns("agent_executions")
    }
    seeded_cost = (
        measured_cost if measured_cost is not None else (None if has_cost_state else Decimal("0"))
    )
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:request_id, :org, :scope_hash, "
                "CAST(:scope_payload AS jsonb), :launcher, :launcher_session, "
                "clock_timestamp() + interval '1 day')"
            ),
            {
                "request_id": request_id,
                "org": organization_id,
                "scope_hash": scope_hash,
                "scope_payload": f'{{"run_nonce":"nonce-{suffix}"}}',
                "launcher": launcher,
                "launcher_session": launcher_session,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) VALUES "
                "(:decision_id, :org, :request_id, :scope_hash, 'approved', "
                ":approver, :approver_session)"
            ),
            {
                "decision_id": f"decision-{suffix}",
                "org": organization_id,
                "request_id": request_id,
                "scope_hash": scope_hash,
                "approver": approver,
                "approver_session": approver_session,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run_id, :org, :request_id, :scope_hash, :launcher, :launcher_session)"
            ),
            {
                "run_id": run_id,
                "org": organization_id,
                "request_id": request_id,
                "scope_hash": scope_hash,
                "launcher": launcher,
                "launcher_session": launcher_session,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_attempts "
                "(organization_id, run_id, attempt_id, ordinal, case_id) VALUES "
                "(:org, :run_id, :attempt_id, 0, :case_id)"
            ),
            {
                "org": organization_id,
                "run_id": run_id,
                "attempt_id": attempt_id,
                "case_id": f"case-{suffix}",
            },
        )
        for execution_id, role, parent, attempt in (
            (parent_execution_id, "orchestrator", None, None),
            (logical_execution_id, "judge", parent_execution_id, attempt_id),
        ):
            terminal_values = (
                {
                    "status": "succeeded",
                    "output_sha256": _SHA256["output"],
                    "finished_at": _FINISHED,
                    "duration_ms": Decimal("875"),
                }
                if terminal
                else {
                    "status": "running",
                    "output_sha256": None,
                    "finished_at": None,
                    "duration_ms": None,
                }
            )
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, attempt_id, "
                    "parent_execution_id, agent_role, status, provider, model, execution_mode, "
                    "configuration_version, input_sha256, output_sha256, measured_cost, trace_id, "
                    "detail, started_at, finished_at, duration_ms) VALUES "
                    "(:execution_id, :org, :run_id, :attempt_id, :parent, :role, :status, "
                    "'openrouter', :model, 'hosted_advisory', 1, :input_hash, :output_hash, "
                    ":measured_cost, :trace_id, '{}'::jsonb, :started_at, :finished_at, :duration)"
                ),
                {
                    "execution_id": execution_id,
                    "org": organization_id,
                    "run_id": run_id,
                    "attempt_id": attempt,
                    "parent": parent,
                    "role": role,
                    "status": terminal_values["status"],
                    "model": (
                        "anthropic/claude-opus-4.8"
                        if role == "orchestrator"
                        else "google/gemini-2.5-pro"
                    ),
                    "input_hash": _SHA256["input"],
                    "output_hash": terminal_values["output_sha256"],
                    "measured_cost": seeded_cost,
                    "trace_id": hashlib_sha256(f"trace:{execution_id}")[:32],
                    "started_at": _STARTED,
                    "finished_at": terminal_values["finished_at"],
                    "duration": terminal_values["duration_ms"],
                },
            )


def hashlib_sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _row(engine: Engine, statement: str, values: Mapping[str, object]) -> Mapping[str, Any]:
    with engine.connect() as connection:
        result = connection.execute(text(statement), values).mappings().one()
        return dict(result)


def _rows(engine: Engine, statement: str, values: Mapping[str, object]) -> list[Mapping[str, Any]]:
    with engine.connect() as connection:
        return [dict(row) for row in connection.execute(text(statement), values).mappings().all()]


# spec(T-F17b:AC-1)
def test_spec_T_F17b_AC_1_success_binds_immutable_requested_and_observed_facts(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)

    invocation = _begin_physical_attempt(store, logical, 1)
    event = _terminal_event(module, invocation)
    persisted = _finish_physical_attempt(store, invocation, event, final=True)

    assert dataclasses.is_dataclass(invocation)
    assert dataclasses.is_dataclass(event)
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError, TypeError)):
        invocation.requested_model = "attacker/model"  # type: ignore[misc]
    with pytest.raises((dataclasses.FrozenInstanceError, AttributeError, TypeError)):
        event.returned_model = "attacker/model"  # type: ignore[misc]
    assert persisted == event

    row = _row(
        migrated_db,
        "SELECT i.*, e.status AS event_status, e.returned_model, e.upstream_provider, "
        "e.provider_request_id, e.input_tokens, e.output_tokens, e.reasoning_tokens, "
        "e.cost_measurement_state, e.measured_cost_usd, e.error_code, e.finished_at, "
        "e.duration_ms FROM provider_call_invocations i "
        "JOIN provider_call_events e "
        "ON e.organization_id = i.organization_id AND e.invocation_id = i.invocation_id "
        "WHERE i.organization_id = :org AND i.logical_execution_id = :execution",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    expected = {
        "campaign_run_id": logical.campaign_run_id,
        "campaign_attempt_id": logical.campaign_attempt_id,
        "logical_execution_id": logical.logical_execution_id,
        "parent_execution_id": logical.parent_execution_id,
        "agent_role": logical.agent_role,
        "physical_sequence": 1,
        "requested_model": logical.requested_model,
        "configured_upstream": logical.configured_upstream,
        "prompt_version": logical.prompt_version,
        "prompt_sha256": logical.prompt_sha256,
        "configuration_set_sha256": logical.configuration_set_sha256,
        "role_configuration_sha256": logical.role_configuration_sha256,
        "generation_policy_sha256": logical.generation_policy_sha256,
        "event_status": "succeeded",
        "returned_model": "google/gemini-2.5-pro",
        "upstream_provider": "Google",
        "provider_request_id": "provider-request-lineage-a",
        "input_tokens": 101,
        "output_tokens": 23,
        "reasoning_tokens": 11,
        "cost_measurement_state": "measured",
        "measured_cost_usd": Decimal("0.012345"),
        "error_code": None,
    }
    for key, value in expected.items():
        assert row[key] == value, f"durable provider fact differs for {key}"
    assert row["started_at"] <= row["finished_at"]
    assert row["duration_ms"] == Decimal("875.000")


# spec(T-F17b:AC-2)
# spec(T-F17b:AC-8)
@pytest.mark.parametrize(
    (
        "status",
        "error_code",
        "returned_model",
        "upstream_provider",
        "provider_request_id",
        "measurement_state",
    ),
    (
        ("timeout", "provider_timeout", None, None, None, "not_observed"),
        ("retryable_failure", "provider_retryable", None, None, None, "not_observed"),
        ("terminal_failure", "provider_terminal", None, None, None, "not_observed"),
        (
            "model_mismatch",
            "returned_model_mismatch",
            "attacker/model",
            "Unexpected",
            "mismatch-request",
            "not_observed",
        ),
        (
            "invalid_usage",
            "invalid_provider_usage",
            "google/gemini-2.5-pro",
            "Google",
            "usage-request",
            "invalid",
        ),
        (
            "invalid_output",
            "invalid_structured_output",
            "google/gemini-2.5-pro",
            "Google",
            "output-request",
            "not_observed",
        ),
    ),
)
def test_spec_T_F17b_AC_2_failures_are_typed_bounded_and_never_fabricate_measurements(
    migrated_db: Engine,
    status: str,
    error_code: str,
    returned_model: str | None,
    upstream_provider: str | None,
    provider_request_id: str | None,
    measurement_state: str,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)
    invocation = _begin_physical_attempt(store, logical, 1)

    event = _terminal_event(
        module,
        invocation,
        status=status,
        error_code=error_code,
        returned_model=returned_model,
        upstream_provider=upstream_provider,
        provider_request_id=provider_request_id,
        input_tokens=None,
        output_tokens=None,
        reasoning_tokens=None,
        cost_measurement_state=measurement_state,
        measured_cost_usd=None,
    )
    persisted = _finish_physical_attempt(store, invocation, event, final=False)

    assert persisted == event
    assert event.error_code == error_code
    assert len(event.error_code) <= 64
    assert event.input_tokens is None
    assert event.output_tokens is None
    assert event.reasoning_tokens is None
    assert event.measured_cost_usd is None
    assert event.cost_measurement_state == measurement_state
    stored = _row(
        migrated_db,
        "SELECT status, error_code, returned_model, upstream_provider, provider_request_id, "
        "input_tokens, output_tokens, reasoning_tokens, cost_measurement_state, "
        "measured_cost_usd FROM provider_call_events "
        "WHERE organization_id = :org AND invocation_id = :invocation",
        {"org": logical.organization_id, "invocation": invocation.invocation_id},
    )
    assert stored == {
        "status": status,
        "error_code": error_code,
        "returned_model": returned_model,
        "upstream_provider": upstream_provider,
        "provider_request_id": provider_request_id,
        "input_tokens": None,
        "output_tokens": None,
        "reasoning_tokens": None,
        "cost_measurement_state": measurement_state,
        "measured_cost_usd": None,
    }
    logical_row = _row(
        migrated_db,
        "SELECT status, finished_at FROM agent_executions "
        "WHERE organization_id = :org AND execution_id = :execution",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    assert logical_row == {"status": "running", "finished_at": None}

    for unsafe_error in (
        "provider_timeout\nraw response",
        "x" * 65,
        "sk-or-" + ("A" * 48),
        '{"exception":"raw provider body"}',
        "made_up_but_well_formed",
    ):
        with pytest.raises(ValueError, match="error"):
            dataclasses.replace(event, error_code=unsafe_error)
    with pytest.raises(ValueError, match="status"):
        dataclasses.replace(event, status="unknown_provider_state")
    with pytest.raises(ValueError, match="token|usage"):
        dataclasses.replace(event, input_tokens=-1)


# spec(T-F17b:AC-3)
# spec(T-F17b:AC-7)
def test_spec_T_F17b_AC_3_retry_uses_two_precommitted_contexts_and_final_only_terminalizes(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)

    first = _begin_physical_attempt(store, logical, 1)
    first_visible = _row(
        migrated_db,
        "SELECT invocation_id, physical_sequence FROM provider_call_invocations "
        "WHERE organization_id = :org AND logical_execution_id = :execution",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    assert first_visible == {
        "invocation_id": first.invocation_id,
        "physical_sequence": 1,
    }, "the first context must be committed before reservation/network work can begin"

    first_event = _terminal_event(
        module,
        first,
        status="retryable_failure",
        returned_model=None,
        upstream_provider=None,
        provider_request_id=None,
        input_tokens=None,
        output_tokens=None,
        reasoning_tokens=None,
        cost_measurement_state="not_observed",
        measured_cost_usd=None,
        error_code="provider_retryable",
    )
    _finish_physical_attempt(store, first, first_event, final=False)
    logical_after_retry = _row(
        migrated_db,
        "SELECT status, finished_at FROM agent_executions "
        "WHERE organization_id = :org AND execution_id = :execution",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    assert logical_after_retry == {"status": "running", "finished_at": None}

    second = _begin_physical_attempt(store, logical, 2)
    attempts = _rows(
        migrated_db,
        "SELECT invocation_id, physical_sequence FROM provider_call_invocations "
        "WHERE organization_id = :org AND logical_execution_id = :execution "
        "ORDER BY physical_sequence",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    assert attempts == [
        {"invocation_id": first.invocation_id, "physical_sequence": 1},
        {"invocation_id": second.invocation_id, "physical_sequence": 2},
    ]
    assert first.invocation_id != second.invocation_id
    assert first.idempotency_key != second.idempotency_key

    second_event = _terminal_event(
        module,
        second,
        provider_request_id="provider-request-lineage-retry-success",
    )
    _finish_physical_attempt(store, second, second_event, final=True)
    logical_after_success = _row(
        migrated_db,
        "SELECT status, finished_at, output_sha256 FROM agent_executions "
        "WHERE organization_id = :org AND execution_id = :execution",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    assert logical_after_success["status"] == "succeeded"
    assert logical_after_success["finished_at"] is not None
    assert logical_after_success["output_sha256"] is not None


# spec(T-F17b:AC-7)
def test_spec_T_F17b_AC_7_final_terminal_failure_atomically_terminalizes_logical_execution(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)
    invocation = _begin_physical_attempt(store, logical, 1)
    event = _terminal_event(
        module,
        invocation,
        status="terminal_failure",
        returned_model=None,
        upstream_provider=None,
        provider_request_id=None,
        input_tokens=None,
        output_tokens=None,
        reasoning_tokens=None,
        cost_measurement_state="not_observed",
        measured_cost_usd=None,
        error_code="provider_terminal",
    )

    persisted = _finish_physical_attempt(store, invocation, event, final=True)

    assert persisted == event
    durable = _row(
        migrated_db,
        "SELECT "
        "(SELECT count(*) FROM provider_call_events "
        " WHERE organization_id = :org AND invocation_id = :invocation) AS events, "
        "status, error_code, finished_at, output_sha256, measured_cost, "
        "cost_measurement_state, provider_event_ids "
        "FROM agent_executions "
        "WHERE organization_id = :org AND execution_id = :execution",
        {
            "org": logical.organization_id,
            "invocation": invocation.invocation_id,
            "execution": logical.logical_execution_id,
        },
    )
    assert durable["events"] == 1
    assert durable["status"] == "failed"
    assert durable["error_code"] == "provider_terminal"
    assert durable["finished_at"] == event.finished_at
    assert durable["output_sha256"] is None
    assert durable["measured_cost"] is None
    assert durable["cost_measurement_state"] == "not_observed"
    assert durable["provider_event_ids"] == [persisted.event_id]


# spec(T-F17b:AC-7)
def test_spec_T_F17b_AC_7_terminal_event_rolls_back_if_logical_terminalization_fails(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)
    invocation = _begin_physical_attempt(store, logical, 1)
    event = _terminal_event(
        module,
        invocation,
        status="terminal_failure",
        returned_model=None,
        upstream_provider=None,
        provider_request_id=None,
        input_tokens=None,
        output_tokens=None,
        reasoning_tokens=None,
        cost_measurement_state="not_observed",
        measured_cost_usd=None,
        error_code="provider_terminal",
    )
    suffix = uuid.uuid4().hex
    function_name = f"fail_lineage_terminal_{suffix}"
    trigger_name = f"trg_fail_lineage_terminal_{suffix}"
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                f"CREATE FUNCTION {function_name}() RETURNS trigger "
                "LANGUAGE plpgsql AS $body$ "
                "BEGIN "
                "IF NEW.status IS DISTINCT FROM OLD.status THEN "
                "IF NOT EXISTS ("
                "SELECT 1 FROM provider_call_events "
                "WHERE organization_id = NEW.organization_id "
                "AND logical_execution_id = NEW.execution_id"
                ") THEN "
                "RAISE EXCEPTION 'terminal event was not inserted before logical update' "
                "USING ERRCODE = '23503'; "
                "END IF; "
                "RAISE EXCEPTION 'injected logical terminalization failure' "
                "USING ERRCODE = '23514'; "
                "END IF; "
                "RETURN NEW; "
                "END "
                "$body$"
            )
        )
        connection.execute(
            text(
                f"CREATE TRIGGER {trigger_name} BEFORE UPDATE ON agent_executions "
                f"FOR EACH ROW EXECUTE FUNCTION {function_name}()"
            )
        )

    try:
        with pytest.raises((DBAPIError, RecordConflictError)) as caught:
            _finish_physical_attempt(store, invocation, event, final=True)
        assert _sqlstate(caught.value) == "23514", (
            "the injected failure must occur only after the terminal event is visible "
            "inside the same transaction"
        )

        counts = _row(
            migrated_db,
            "SELECT "
            "(SELECT count(*) FROM provider_call_invocations "
            " WHERE organization_id = :org AND invocation_id = :invocation) AS invocations, "
            "(SELECT count(*) FROM provider_call_events "
            " WHERE organization_id = :org AND invocation_id = :invocation) AS events",
            {"org": logical.organization_id, "invocation": invocation.invocation_id},
        )
        assert counts == {"invocations": 1, "events": 0}
        logical_row = _row(
            migrated_db,
            "SELECT status, error_code, finished_at, provider_event_ids "
            "FROM agent_executions "
            "WHERE organization_id = :org AND execution_id = :execution",
            {"org": logical.organization_id, "execution": logical.logical_execution_id},
        )
        assert logical_row == {
            "status": "running",
            "error_code": None,
            "finished_at": None,
            "provider_event_ids": [],
        }
    finally:
        with migrated_db.begin() as connection:
            connection.execute(text(f"DROP TRIGGER IF EXISTS {trigger_name} ON agent_executions"))
            connection.execute(text(f"DROP FUNCTION IF EXISTS {function_name}()"))


# spec(T-F17b:AC-3)
def test_spec_T_F17b_AC_3_composite_foreign_keys_and_sequence_uniqueness_reject_reattribution(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)
    _begin_physical_attempt(store, logical, 1)

    with pytest.raises(RecordConflictError):
        _begin_physical_attempt(store, logical, 1)

    cross_org = dataclasses.replace(logical, organization_id="org_LineageB")
    with pytest.raises((RecordConflictError, IntegrityError)):
        _begin_physical_attempt(store, cross_org, 2)

    wrong_attempt = dataclasses.replace(logical, campaign_attempt_id="attempt-not-authorized")
    with pytest.raises((RecordConflictError, IntegrityError)):
        _begin_physical_attempt(store, wrong_attempt, 2)

    assert (
        _row(
            migrated_db,
            "SELECT count(*) AS count FROM provider_call_invocations "
            "WHERE organization_id = :org AND logical_execution_id = :execution",
            {"org": logical.organization_id, "execution": logical.logical_execution_id},
        )["count"]
        == 1
    )


# spec(T-F17b:AC-4)
def test_spec_T_F17b_AC_4_postgres_grants_make_lineage_runner_append_only(
    migrated_db: Engine,
) -> None:
    _assert_lineage_schema_exists(migrated_db)
    roles = (
        "headshot_runner",
        "headshot_web",
        "headshot_redteam",
        "headshot_recorder",
        "headshot_judge",
    )
    with migrated_db.connect() as connection:
        for table in (_INVOCATIONS, _EVENTS):
            assert connection.execute(
                text("SELECT has_table_privilege('headshot_runner', :table, 'INSERT')"),
                {"table": table},
            ).scalar_one()
            for role in roles:
                can_select = connection.execute(
                    text("SELECT has_table_privilege(:role, :table, 'SELECT')"),
                    {"role": role, "table": table},
                ).scalar_one()
                assert can_select is (role in {"headshot_runner", "headshot_web"})
                can_insert = connection.execute(
                    text("SELECT has_table_privilege(:role, :table, 'INSERT')"),
                    {"role": role, "table": table},
                ).scalar_one()
                assert can_insert is (role == "headshot_runner")

                for operation in ("UPDATE", "DELETE", "TRUNCATE"):
                    statement = {
                        "UPDATE": f"UPDATE {table} SET organization_id = organization_id",
                        "DELETE": f"DELETE FROM {table}",
                        "TRUNCATE": f"TRUNCATE TABLE {table}",
                    }[operation]
                    with _as_role(connection, role), pytest.raises(ProgrammingError) as caught:
                        connection.execute(text(statement))
                    assert _sqlstate(caught.value) == _SQLSTATE_INSUFFICIENT_PRIVILEGE

            for role in set(roles) - {"headshot_runner"}:
                with _as_role(connection, role), pytest.raises(ProgrammingError) as caught:
                    connection.execute(text(f"INSERT INTO {table} DEFAULT VALUES"))
                assert _sqlstate(caught.value) == _SQLSTATE_INSUFFICIENT_PRIVILEGE


# spec(T-F17b:AC-4)
def test_spec_T_F17b_AC_4_authenticated_reads_cannot_cross_organization_scope(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    for suffix in ("A", "B"):
        organization_id = f"org_Lineage{suffix}"
        run_id = f"run-lineage-{suffix.lower()}"
        attempt_id = f"attempt-lineage-{suffix.lower()}"
        logical_execution_id = f"logical-lineage-{suffix.lower()}"
        parent_execution_id = f"parent-lineage-{suffix.lower()}"
        _seed_logical_execution(
            migrated_db,
            organization_id=organization_id,
            run_id=run_id,
            attempt_id=attempt_id,
            logical_execution_id=logical_execution_id,
            parent_execution_id=parent_execution_id,
        )
        store = ControlPlaneStore(migrated_db, environment="staging")
        logical = _logical_context(
            module,
            organization_id=organization_id,
            campaign_run_id=run_id,
            campaign_attempt_id=attempt_id,
            logical_execution_id=logical_execution_id,
            parent_execution_id=parent_execution_id,
        )
        invocation = _begin_physical_attempt(store, logical, 1)
        _finish_physical_attempt(
            store,
            invocation,
            _terminal_event(
                module,
                invocation,
                provider_request_id=f"provider-request-{suffix.lower()}",
            ),
            final=True,
        )

    store = ControlPlaneStore(migrated_db, environment="staging")
    list_events = _store_method(store, "list_provider_call_events")
    organization_a = tuple(list_events(organization_id="org_LineageA"))
    assert len(organization_a) == 1
    assert {event.organization_id for event in organization_a} == {"org_LineageA"}
    assert all("org_LineageB" not in repr(event) for event in organization_a)


# spec(T-F17b:AC-5)
def test_spec_T_F17b_AC_5_schema_has_composite_foreign_keys_checks_and_query_indexes(
    migrated_db: Engine,
) -> None:
    _assert_lineage_schema_exists(migrated_db)
    inspector = inspect(migrated_db)
    invocation_columns = {column["name"]: column for column in inspector.get_columns(_INVOCATIONS)}
    event_columns = {column["name"]: column for column in inspector.get_columns(_EVENTS)}
    required_invocation_columns = {
        "invocation_id",
        "organization_id",
        "campaign_run_id",
        "campaign_attempt_id",
        "logical_execution_id",
        "parent_execution_id",
        "agent_role",
        "physical_sequence",
        "idempotency_key",
        "requested_model",
        "configured_upstream",
        "prompt_version",
        "prompt_sha256",
        "configuration_set_sha256",
        "role_configuration_sha256",
        "generation_policy_sha256",
        "started_at",
    }
    required_event_columns = {
        "event_id",
        "invocation_id",
        "organization_id",
        "campaign_run_id",
        "campaign_attempt_id",
        "logical_execution_id",
        "agent_role",
        "physical_sequence",
        "status",
        "returned_model",
        "upstream_provider",
        "provider_request_id",
        "input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "cost_measurement_state",
        "measured_cost_usd",
        "error_code",
        "finished_at",
        "duration_ms",
    }
    assert required_invocation_columns <= invocation_columns.keys()
    assert required_event_columns <= event_columns.keys()
    for nullable in (
        "returned_model",
        "upstream_provider",
        "provider_request_id",
        "input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "measured_cost_usd",
    ):
        assert event_columns[nullable]["nullable"] is True

    invocation_foreign_keys = {
        (
            tuple(foreign_key["constrained_columns"]),
            foreign_key["referred_table"],
            tuple(foreign_key["referred_columns"]),
        )
        for foreign_key in inspector.get_foreign_keys(_INVOCATIONS)
    }
    assert (
        ("organization_id", "logical_execution_id"),
        "agent_executions",
        ("organization_id", "execution_id"),
    ) in invocation_foreign_keys
    assert (
        ("organization_id", "parent_execution_id"),
        "agent_executions",
        ("organization_id", "execution_id"),
    ) in invocation_foreign_keys
    assert (
        ("organization_id", "campaign_run_id", "campaign_attempt_id"),
        "campaign_attempts",
        ("organization_id", "run_id", "attempt_id"),
    ) in invocation_foreign_keys

    event_foreign_keys = {
        (
            tuple(foreign_key["constrained_columns"]),
            foreign_key["referred_table"],
            tuple(foreign_key["referred_columns"]),
        )
        for foreign_key in inspector.get_foreign_keys(_EVENTS)
    }
    assert (
        ("organization_id", "invocation_id"),
        _INVOCATIONS,
        ("organization_id", "invocation_id"),
    ) in event_foreign_keys

    unique_sets = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(_INVOCATIONS)
    }
    assert (
        "organization_id",
        "logical_execution_id",
        "physical_sequence",
    ) in unique_sets
    event_unique_sets = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(_EVENTS)
    } | {
        tuple(index["column_names"])
        for index in inspector.get_indexes(_EVENTS)
        if index.get("unique")
    }
    assert event_unique_sets & {
        ("invocation_id",),
        ("organization_id", "invocation_id"),
    }, "each committed invocation must own at most one terminal event"

    event_indexes = {tuple(index["column_names"]) for index in inspector.get_indexes(_EVENTS)}
    assert ("organization_id", "agent_role", "finished_at") in event_indexes
    assert (
        "organization_id",
        "campaign_run_id",
        "physical_sequence",
    ) in event_indexes
    assert ("organization_id", "provider_request_id") in event_indexes
    assert ("organization_id", "logical_execution_id") in event_indexes


# spec(T-F17b:AC-3)
# spec(T-F17b:AC-7)
def test_spec_T_F17b_AC_3_event_ownership_and_single_terminal_fact_are_database_enforced(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    store = ControlPlaneStore(migrated_db, environment="staging")

    _seed_logical_execution(migrated_db)
    logical_a = _logical_context(module)
    invocation_a = _begin_physical_attempt(store, logical_a, 1)
    event_a = _terminal_event(
        module,
        invocation_a,
        status="retryable_failure",
        returned_model=None,
        upstream_provider=None,
        provider_request_id=None,
        input_tokens=None,
        output_tokens=None,
        reasoning_tokens=None,
        cost_measurement_state="not_observed",
        measured_cost_usd=None,
        error_code="provider_retryable",
    )
    _finish_physical_attempt(store, invocation_a, event_a, final=False)
    unused_invocation_a = _begin_physical_attempt(store, logical_a, 2)

    _seed_logical_execution(
        migrated_db,
        organization_id="org_LineageB",
        run_id="run-lineage-b",
        attempt_id="attempt-lineage-b",
        logical_execution_id="logical-lineage-b",
        parent_execution_id="parent-lineage-b",
    )
    logical_b = _logical_context(
        module,
        organization_id="org_LineageB",
        campaign_run_id="run-lineage-b",
        campaign_attempt_id="attempt-lineage-b",
        logical_execution_id="logical-lineage-b",
        parent_execution_id="parent-lineage-b",
    )
    invocation_b = _begin_physical_attempt(store, logical_b, 1)

    event_columns = (
        "event_id, invocation_id, organization_id, campaign_run_id, campaign_attempt_id, "
        "logical_execution_id, agent_role, physical_sequence, status, returned_model, "
        "upstream_provider, provider_request_id, input_tokens, output_tokens, reasoning_tokens, "
        "cost_measurement_state, measured_cost_usd, error_code, finished_at, duration_ms"
    )
    with pytest.raises(IntegrityError), migrated_db.begin() as connection:
        connection.execute(
            text(
                f"INSERT INTO provider_call_events ({event_columns}) "
                "SELECT :new_event_id, invocation_id, organization_id, campaign_run_id, "
                "campaign_attempt_id, logical_execution_id, agent_role, physical_sequence, "
                "status, returned_model, upstream_provider, provider_request_id, input_tokens, "
                "output_tokens, reasoning_tokens, cost_measurement_state, measured_cost_usd, "
                "error_code, finished_at, duration_ms "
                "FROM provider_call_events "
                "WHERE organization_id = :org AND invocation_id = :invocation"
            ),
            {
                "new_event_id": uuid.uuid4().hex,
                "org": logical_a.organization_id,
                "invocation": invocation_a.invocation_id,
            },
        )

    # All B-side attribution columns are valid for B, and the unused A-side invocation has no
    # event yet. Only the required composite (organization_id, invocation_id) ownership FK can
    # reject this otherwise-new terminal fact.
    with pytest.raises(IntegrityError), migrated_db.begin() as connection:
        connection.execute(
            text(
                f"INSERT INTO provider_call_events ({event_columns}) "
                "SELECT :new_event_id, :cross_org_invocation, i.organization_id, "
                "i.campaign_run_id, i.campaign_attempt_id, i.logical_execution_id, i.agent_role, "
                "i.physical_sequence, e.status, e.returned_model, e.upstream_provider, "
                "e.provider_request_id, e.input_tokens, e.output_tokens, e.reasoning_tokens, "
                "e.cost_measurement_state, e.measured_cost_usd, e.error_code, e.finished_at, "
                "e.duration_ms "
                "FROM provider_call_invocations i CROSS JOIN provider_call_events e "
                "WHERE i.organization_id = :org_b AND i.invocation_id = :invocation_b "
                "AND e.organization_id = :org_a AND e.invocation_id = :event_invocation"
            ),
            {
                "new_event_id": uuid.uuid4().hex,
                "cross_org_invocation": unused_invocation_a.invocation_id,
                "org_b": logical_b.organization_id,
                "invocation_b": invocation_b.invocation_id,
                "org_a": logical_a.organization_id,
                "event_invocation": invocation_a.invocation_id,
            },
        )

    assert (
        _row(
            migrated_db,
            "SELECT count(*) AS count FROM provider_call_events",
            {},
        )["count"]
        == 1
    )


# spec(T-F17b:AC-5)
# spec(T-F17b:AC-8)
def test_spec_T_F17b_AC_5_migration_round_trip_preserves_logical_rows_without_zero_fabrication(
    admin_url: str,
) -> None:
    import _db

    database_name = f"agentforge_f17b_migration_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    base_url, _ = _db.split_db(admin_url)
    database_url = f"{base_url}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(database_url, "0015")
        engine = _db.build_engine(database_url)
        _seed_logical_execution(
            engine,
            organization_id="org_Migration",
            run_id="run-migration",
            attempt_id="attempt-migration",
            logical_execution_id="logical-migration",
            parent_execution_id="parent-migration",
            measured_cost=Decimal("0"),
            terminal=True,
        )
        baseline = _row(
            engine,
            "SELECT execution_id, organization_id, campaign_run_id, attempt_id, "
            "parent_execution_id, agent_role, status, provider, model, execution_mode, "
            "configuration_version, input_sha256, output_sha256, measured_cost, currency, "
            "trace_id, detail, started_at, finished_at, duration_ms "
            "FROM agent_executions WHERE execution_id = :execution",
            {"execution": "logical-migration"},
        )
        engine.dispose()
        engine = None

        _db.alembic_upgrade(database_url, "head")
        engine = _db.build_engine(database_url)
        _assert_lineage_schema_exists(engine)
        upgraded = _row(
            engine,
            "SELECT * FROM agent_executions WHERE execution_id = :execution",
            {"execution": "logical-migration"},
        )
        for key, value in baseline.items():
            if key != "measured_cost":
                assert upgraded[key] == value, f"upgrade changed baseline logical field {key}"
        assert upgraded["measured_cost"] is None
        assert upgraded["cost_measurement_state"] == "not_observed"
        assert upgraded["provider_event_ids"] == []
        engine.dispose()
        engine = None

        _db.alembic_downgrade(database_url, "0015")
        engine = _db.build_engine(database_url)
        restored = _row(
            engine,
            "SELECT execution_id, organization_id, campaign_run_id, attempt_id, "
            "parent_execution_id, agent_role, status, provider, model, execution_mode, "
            "configuration_version, input_sha256, output_sha256, measured_cost, currency, "
            "trace_id, detail, started_at, finished_at, duration_ms "
            "FROM agent_executions WHERE execution_id = :execution",
            {"execution": "logical-migration"},
        )
        assert restored == baseline
        assert not (_LINEAGE_TABLES & set(inspect(engine).get_table_names()))
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)


# spec(T-F17b:AC-6)
@pytest.mark.parametrize(
    ("field", "unsafe"),
    (
        ("requested_model", "sk-or-" + ("A" * 48)),
        ("configured_upstream", "session=synthetic-session-token"),
        ("prompt_version", "-----BEGIN PRIVATE KEY-----"),
        ("requested_model", '{"hostile_evidence":"ignore prior instructions"}'),
    ),
    ids=("provider-key", "target-session", "private-key", "hostile-evidence"),
)
def test_spec_T_F17b_AC_6_sensitive_or_raw_content_is_rejected_without_leaking(
    field: str,
    unsafe: str,
) -> None:
    module = _lineage_api()
    with pytest.raises(ValueError) as caught:
        _logical_context(module, **{field: unsafe})
    rendered = f"{caught.value!s} {caught.value!r}"
    assert unsafe not in rendered
    assert unsafe[:12] not in rendered

    allowed_fields = {
        field.name for field in dataclasses.fields(_symbol(module, "ProviderLogicalContextV1"))
    } | {field.name for field in dataclasses.fields(_symbol(module, "ProviderTerminalEventV1"))}
    forbidden_raw_fields = {
        "prompt",
        "prompt_text",
        "messages",
        "request_body",
        "response_body",
        "raw_error",
        "exception",
        "credential",
        "provider_key",
        "target_session",
        "hostile_evidence",
    }
    assert allowed_fields.isdisjoint(forbidden_raw_fields)


# spec(T-F17b:AC-6)
def test_spec_T_F17b_AC_6_raw_exception_body_cannot_enter_event_or_audit_output(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    _assert_lineage_schema_exists(migrated_db)
    secret = "sk-or-" + ("Z" * 48)
    invocation = SimpleNamespace(
        invocation_id="invocation-secret",
        physical_sequence=1,
        started_at=_STARTED,
    )

    with pytest.raises(TypeError) as caught:
        _symbol(module, "ProviderTerminalEventV1")(
            invocation_id=invocation.invocation_id,
            physical_sequence=1,
            status="timeout",
            returned_model=None,
            upstream_provider=None,
            provider_request_id=None,
            input_tokens=None,
            output_tokens=None,
            reasoning_tokens=None,
            cost_measurement_state="not_observed",
            measured_cost_usd=None,
            error_code="provider_timeout",
            finished_at=_FINISHED,
            raw_error=f"upstream body contained {secret}",
        )
    rendered = f"{caught.value!s} {caught.value!r}"
    assert secret not in rendered
    with migrated_db.connect() as connection:
        persisted_text = connection.execute(
            text(
                "SELECT concat_ws(' ', "
                "coalesce((SELECT string_agg(row_to_json(e)::text, ' ') "
                "FROM provider_call_events e), ''), "
                "coalesce((SELECT string_agg(payload::text, ' ') FROM audit_events), ''))"
            )
        ).scalar_one()
    assert secret not in persisted_text


# spec(T-F17b:AC-7)
def test_spec_T_F17b_AC_7_terminal_replay_is_idempotent_but_changed_replay_conflicts(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)
    invocation = _begin_physical_attempt(store, logical, 1)
    event = _terminal_event(module, invocation)

    first = _finish_physical_attempt(store, invocation, event, final=True)
    replay = _finish_physical_attempt(store, invocation, event, final=True)
    assert replay == first
    assert (
        _row(
            migrated_db,
            "SELECT count(*) AS count FROM provider_call_events "
            "WHERE organization_id = :org AND invocation_id = :invocation",
            {"org": logical.organization_id, "invocation": invocation.invocation_id},
        )["count"]
        == 1
    )

    changed = dataclasses.replace(event, provider_request_id="changed-provider-request")
    with pytest.raises(RecordConflictError):
        _finish_physical_attempt(store, invocation, changed, final=True)
    stored = _row(
        migrated_db,
        "SELECT provider_request_id FROM provider_call_events "
        "WHERE organization_id = :org AND invocation_id = :invocation",
        {"org": logical.organization_id, "invocation": invocation.invocation_id},
    )
    assert stored["provider_request_id"] == event.provider_request_id


# spec(T-F17b:AC-7)
def test_spec_T_F17b_AC_7_crash_reconciles_once_as_unknown_without_new_call(
    migrated_db: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)
    invocation = _begin_physical_attempt(store, logical, 1)
    with migrated_db.connect() as connection:
        connection.execute(text("SELECT 1")).scalar_one()

    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("crash reconciliation attempted provider or target network I/O")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(urllib.request, "urlopen", denied)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", denied)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", denied)

    first = _reconcile_unknown_physical_attempt(store, invocation)
    replay = _reconcile_unknown_physical_attempt(store, invocation)
    assert replay == first
    assert first.status == "outcome_unknown"
    assert first.cost_measurement_state == "not_observed"
    assert first.measured_cost_usd is None
    assert first.returned_model is None
    assert first.upstream_provider is None
    assert first.provider_request_id is None
    assert first.input_tokens is None
    assert first.output_tokens is None
    assert first.reasoning_tokens is None

    counts = _row(
        migrated_db,
        "SELECT "
        "(SELECT count(*) FROM provider_call_invocations "
        " WHERE organization_id = :org AND logical_execution_id = :execution) AS invocations, "
        "(SELECT count(*) FROM provider_call_events "
        " WHERE organization_id = :org AND logical_execution_id = :execution) AS events",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    assert counts == {"invocations": 1, "events": 1}
    unreserved = dataclasses.replace(
        invocation,
        invocation_id="unreserved-invocation",
        physical_sequence=2,
    )
    with pytest.raises((RecordConflictError, RecordNotFoundError)):
        _reconcile_unknown_physical_attempt(store, unreserved)
    logical_row = _row(
        migrated_db,
        "SELECT status, error_code, measured_cost, cost_measurement_state, provider_event_ids "
        "FROM agent_executions "
        "WHERE organization_id = :org AND execution_id = :execution",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    assert logical_row == {
        "status": "failed",
        "error_code": "provider_outcome_unknown",
        "measured_cost": None,
        "cost_measurement_state": "not_observed",
        "provider_event_ids": [first.event_id],
    }


# spec(T-F17b:AC-8)
@pytest.mark.parametrize(
    ("state", "amount"),
    (
        ("measured", Decimal("0.012345")),
        ("partial", Decimal("0.004200")),
        ("not_observed", None),
        ("invalid", None),
    ),
)
def test_spec_T_F17b_AC_8_cost_states_are_closed_decimal_and_nullable(
    state: str,
    amount: Decimal | None,
) -> None:
    module = _lineage_api()
    invocation = SimpleNamespace(
        invocation_id="invocation-cost",
        physical_sequence=1,
        started_at=_STARTED,
    )
    event = _terminal_event(
        module,
        invocation,
        cost_measurement_state=state,
        measured_cost_usd=amount,
    )
    assert event.cost_measurement_state == state
    assert event.measured_cost_usd == amount

    invalid_shapes = (
        ("unknown", None),
        ("not_observed", Decimal("0")),
        ("invalid", Decimal("0")),
        ("measured", None),
        ("partial", None),
        ("measured", 0.01),
    )
    for invalid_state, invalid_amount in invalid_shapes:
        with pytest.raises((TypeError, ValueError), match="cost|measurement|Decimal"):
            dataclasses.replace(
                event,
                cost_measurement_state=invalid_state,
                measured_cost_usd=invalid_amount,
            )


# spec(T-F17b:AC-7)
# spec(T-F17b:AC-8)
def test_spec_T_F17b_AC_8_logical_cost_references_physical_sources_once(
    migrated_db: Engine,
) -> None:
    module = _lineage_api()
    _seed_logical_execution(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    logical = _logical_context(module)

    first = _begin_physical_attempt(store, logical, 1)
    first_event = _terminal_event(
        module,
        first,
        status="retryable_failure",
        returned_model=None,
        upstream_provider=None,
        provider_request_id=None,
        input_tokens=40,
        output_tokens=None,
        reasoning_tokens=None,
        cost_measurement_state="partial",
        measured_cost_usd=Decimal("0.004200"),
        error_code="provider_retryable",
    )
    first_persisted = _finish_physical_attempt(store, first, first_event, final=False)

    second = _begin_physical_attempt(store, logical, 2)
    second_event = _terminal_event(
        module,
        second,
        provider_request_id="provider-request-cost-final",
        measured_cost_usd=Decimal("0.012345"),
    )
    second_persisted = _finish_physical_attempt(store, second, second_event, final=True)
    _finish_physical_attempt(store, second, second_event, final=True)

    logical_row = _row(
        migrated_db,
        "SELECT measured_cost, cost_measurement_state, provider_event_ids "
        "FROM agent_executions WHERE organization_id = :org AND execution_id = :execution",
        {"org": logical.organization_id, "execution": logical.logical_execution_id},
    )
    assert logical_row["measured_cost"] == Decimal("0.016545")
    assert logical_row["cost_measurement_state"] == "partial"
    assert logical_row["provider_event_ids"] == [
        first_persisted.event_id,
        second_persisted.event_id,
    ]
    assert len(set(logical_row["provider_event_ids"])) == 2
    assert (
        _row(
            migrated_db,
            "SELECT count(*) AS count FROM provider_call_events "
            "WHERE organization_id = :org AND logical_execution_id = :execution",
            {"org": logical.organization_id, "execution": logical.logical_execution_id},
        )["count"]
        == 2
    )
