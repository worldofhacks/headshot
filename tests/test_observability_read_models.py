"""Cross-field observability contracts reject internally contradictory projections."""

from __future__ import annotations

import datetime

import pytest
from pydantic import ValidationError

from agentforge.api.read_models import (
    AgentActivityReadModel,
    AgentAssignmentReadModel,
    AgentBudgetReadModel,
    AgentReadModel,
    BirdseyeNodeReadModel,
    CostReadModel,
    TraceReadModel,
)

_NOW = datetime.datetime(2026, 7, 24, tzinfo=datetime.UTC)


def _unavailable_provider_budget() -> dict[str, object]:
    return {
        "status": "unavailable",
        "campaign_run_id": None,
        "configuration_set_sha256": None,
        "role_cost_measurement_state": None,
        "role_usd_cap": None,
        "role_usd_spent": 0,
        "role_unresolved_usd_exposure": 0,
        "role_usd_remaining": None,
        "role_usd_remaining_upper_bound": None,
        "role_usd_overrun": 0,
        "role_call_cap": None,
        "role_physical_calls": 0,
        "role_unresolved_physical_calls": 0,
        "role_calls_remaining": None,
        "role_call_overrun": 0,
        "global_cost_measurement_state": None,
        "global_usd_cap": None,
        "global_usd_spent": 0,
        "global_unresolved_usd_exposure": 0,
        "global_usd_remaining": None,
        "global_usd_remaining_upper_bound": None,
        "global_usd_overrun": 0,
        "global_call_cap": None,
        "global_physical_calls": 0,
        "global_unresolved_physical_calls": 0,
        "global_calls_remaining": None,
        "global_call_overrun": 0,
    }


def _partial_provider_budget() -> dict[str, object]:
    return {
        "status": "active",
        "campaign_run_id": "campaign-1",
        "configuration_set_sha256": "f" * 64,
        "role_cost_measurement_state": "not_observed",
        "role_usd_cap": 1,
        "role_usd_spent": 0,
        "role_unresolved_usd_exposure": 0,
        "role_usd_remaining": None,
        "role_usd_remaining_upper_bound": 1,
        "role_usd_overrun": 0,
        "role_call_cap": 2,
        "role_physical_calls": 1,
        "role_unresolved_physical_calls": 0,
        "role_calls_remaining": 1,
        "role_call_overrun": 0,
        "global_cost_measurement_state": "partial",
        "global_usd_cap": 5,
        "global_usd_spent": 0.25,
        "global_unresolved_usd_exposure": 0,
        "global_usd_remaining": None,
        "global_usd_remaining_upper_bound": 4.75,
        "global_usd_overrun": 0,
        "global_call_cap": 8,
        "global_physical_calls": 2,
        "global_unresolved_physical_calls": 0,
        "global_calls_remaining": 6,
        "global_call_overrun": 0,
    }


def test_incomplete_provider_spend_exposes_only_remaining_upper_bounds() -> None:
    budget = AgentBudgetReadModel(**_partial_provider_budget())
    assert budget.role_usd_remaining is None
    assert budget.role_usd_remaining_upper_bound == 1
    assert budget.global_usd_remaining is None
    assert budget.global_usd_remaining_upper_bound == 4.75

    with pytest.raises(ValidationError, match="cannot claim exact remaining"):
        AgentBudgetReadModel(
            **{
                **_partial_provider_budget(),
                "role_usd_remaining": 1,
            }
        )


def test_agent_summary_requires_latency_and_delivery_for_completed_work() -> None:
    with pytest.raises(ValidationError):
        AgentReadModel(
            role="judge",
            display_name="Judge",
            responsibility="Evaluate evidence",
            trust_level="independent",
            target_access="none",
            input_contract="evidence",
            output_contract="verdict",
            active_assignment={
                "role": "judge",
                "provider": "headshot",
                "model": "oracle-precedence-v1",
                "resolved_model": None,
                "execution_mode": "deterministic",
                "activation_state": "active",
                "version": 1,
                "configuration_sha256": "a" * 64,
            },
            execution_count=1,
            running_count=0,
            succeeded_count=1,
            failed_count=0,
            skipped_count=0,
            measured_cost=0,
            cost_measurement_state="measured",
            accounting_status="measured",
            provider_event_ids=[],
            currency="USD",
            input_tokens=None,
            output_tokens=None,
            reasoning_tokens=None,
            token_observation_count=0,
            physical_call_count=0,
            provider_budget=_unavailable_provider_budget(),
            judge_calibration={
                "state": "unavailable",
                "calibration_id": None,
                "decision_authority": "none",
                "oracle_comparison_count": 0,
                "oracle_agreement_count": 0,
                "oracle_agreement_rate": None,
                "status_label": "not yet measured",
            },
            average_duration_ms=None,
            p50_duration_ms=None,
            p95_duration_ms=None,
            langfuse_not_attempted_count=0,
            langfuse_disabled_count=0,
            langfuse_queued_count=0,
            langfuse_exported_count=1,
            langfuse_error_count=0,
            langfuse_verified_count=0,
            last_langfuse_verified_at=None,
        )


@pytest.mark.parametrize(
    ("resolved_model", "upstream_provider"),
    (
        ("anthropic/claude-opus-4.8", None),
        (None, "Anthropic"),
    ),
)
def test_agent_assignment_rejects_partial_served_identity(
    resolved_model: str | None,
    upstream_provider: str | None,
) -> None:
    with pytest.raises(ValidationError):
        AgentAssignmentReadModel(
            role="orchestrator",
            provider="openrouter",
            model="anthropic/claude-opus-4.8",
            resolved_model=resolved_model,
            upstream_provider=upstream_provider,
            execution_mode="hosted_advisory",
            activation_state="active",
            version=1,
            configuration_sha256="a" * 64,
        )


def test_cost_token_totals_require_an_observation() -> None:
    with pytest.raises(ValidationError):
        CostReadModel(
            accounting_id="campaign-1",
            campaign_id="campaign-1",
            provider="live-target",
            agent_role=None,
            record_kind="campaign",
            measured_cost=0,
            cost_measurement_state="measured",
            accounting_status="measured",
            provider_event_ids=[],
            currency="USD",
            request_count=1,
            execution_count=0,
            attempt_count=1,
            confirmed_finding_count=0,
            average_cost_per_request=0,
            input_tokens=12,
            output_tokens=None,
            reasoning_tokens=None,
            token_observation_count=0,
            physical_call_count=0,
            provider_budget=None,
            duration_ms=10,
            execution_profile="live",
            started_at=_NOW,
            ended_at=_NOW,
            recorded_at=_NOW,
        )


def _agent_cost_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "accounting_id": "agent-cost-1",
        "campaign_id": "campaign-1",
        "provider": "agent:red_team:headshot/full-scan-corpus-v1",
        "agent_role": "red_team",
        "record_kind": "agent",
        "measured_cost": None,
        "cost_measurement_state": "not_applicable",
        "accounting_status": "not_applicable",
        "provider_event_ids": [],
        "currency": "USD",
        "request_count": 0,
        "execution_count": 0,
        "attempt_count": 0,
        "confirmed_finding_count": 0,
        "average_cost_per_request": None,
        "input_tokens": None,
        "output_tokens": None,
        "reasoning_tokens": None,
        "token_observation_count": 0,
        "physical_call_count": 0,
        "provider_budget": _unavailable_provider_budget(),
        "p50_duration_ms": None,
        "p95_duration_ms": None,
        "duration_ms": 0,
        "execution_profile": "live",
        "started_at": _NOW,
        "ended_at": None,
        "recorded_at": _NOW,
    }
    record.update(overrides)
    return record


def test_agent_cost_latency_is_null_only_without_completed_executions() -> None:
    assert CostReadModel(**_agent_cost_record()).p50_duration_ms is None

    completed = _agent_cost_record(
        execution_count=1,
        measured_cost=0,
        cost_measurement_state="measured",
        accounting_status="measured",
        p50_duration_ms=10,
        p95_duration_ms=20,
        ended_at=_NOW,
    )
    assert CostReadModel(**completed).p95_duration_ms == 20

    for malformed in (
        _agent_cost_record(
            execution_count=1,
            measured_cost=0,
            cost_measurement_state="measured",
            accounting_status="measured",
        ),
        _agent_cost_record(p50_duration_ms=10, p95_duration_ms=20),
        {**completed, "p50_duration_ms": 30},
    ):
        with pytest.raises(ValidationError):
            CostReadModel(**malformed)


def test_unavailable_agent_cost_preserves_known_physical_call_lineage() -> None:
    record = CostReadModel(
        **_agent_cost_record(
            execution_count=1,
            physical_call_count=1,
            measured_cost=None,
            cost_measurement_state="not_observed",
            accounting_status="unavailable",
            provider_event_ids=["a" * 64],
            provider_budget=_partial_provider_budget(),
            p50_duration_ms=10,
            p95_duration_ms=10,
            ended_at=_NOW,
        )
    )
    assert record.measured_cost is None
    assert record.average_cost_per_request is None
    assert record.physical_call_count == 1
    assert record.provider_event_ids == ["a" * 64]


def _agent_trace_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "request_id": None,
        "execution_id": "execution-1",
        "parent_execution_id": None,
        "trace_id": "b" * 32,
        "campaign_id": "campaign-1",
        "attempt_id": None,
        "operation": "agent.red_team",
        "provider": "headshot",
        "model": "full-scan-corpus-v1",
        "agent_role": "red_team",
        "execution_mode": "deterministic",
        "method": None,
        "destination_host": None,
        "relative_path": None,
        "status": "running",
        "status_code": None,
        "error_code": None,
        "started_at": _NOW,
        "finished_at": None,
        "duration_ms": None,
        "request_bytes": 0,
        "response_bytes": None,
        "measured_cost": 0,
        "cost_measurement_state": "measured",
        "accounting_status": "measured",
        "provider_event_ids": [],
        "currency": "USD",
        "input_tokens": None,
        "output_tokens": None,
        "p50_duration_ms": None,
        "p95_duration_ms": None,
        "langfuse_status": "queued",
        "langfuse_verified_at": None,
        "request_preview": None,
        "response_preview": None,
        "request_sha256": "a" * 64,
        "response_sha256": None,
        "inspection_flags": [],
        "inspection_owasp_mappings": [],
    }
    record.update(overrides)
    return record


def test_agent_trace_latency_requires_authoritative_paired_percentiles() -> None:
    assert TraceReadModel(**_agent_trace_record()).p50_duration_ms is None
    completed = _agent_trace_record(
        status="succeeded",
        finished_at=_NOW,
        duration_ms=10,
        response_sha256="c" * 64,
        p50_duration_ms=10,
        p95_duration_ms=20,
    )
    assert TraceReadModel(**completed).p95_duration_ms == 20

    for malformed in (
        _agent_trace_record(p50_duration_ms=10),
        {**completed, "p50_duration_ms": 30},
        {**completed, "agent_role": None},
        {**completed, "p50_duration_ms": None, "p95_duration_ms": None},
    ):
        with pytest.raises(ValidationError):
            TraceReadModel(**malformed)


def test_agent_trace_event_cardinality_allows_only_a_running_reservation_gap() -> None:
    running = _agent_trace_record(
        provider="openrouter",
        execution_mode="hosted_advisory",
        configuration_set_sha256="c" * 64,
        role_configuration_sha256="d" * 64,
        generation_policy_sha256="e" * 64,
        physical_attempts=2,
        measured_cost=None,
        cost_measurement_state="not_observed",
        accounting_status="unavailable",
        provider_event_ids=["f" * 64],
    )
    assert TraceReadModel(**running).physical_attempts == 2

    with pytest.raises(ValidationError):
        TraceReadModel(
            **{
                **running,
                "status": "failed",
                "finished_at": _NOW,
                "duration_ms": 10,
                "p50_duration_ms": 10,
                "p95_duration_ms": 10,
            }
        )


def test_terminal_agent_activity_requires_terminal_measurements() -> None:
    with pytest.raises(ValidationError):
        AgentActivityReadModel(
            execution_id="execution-1",
            campaign_run_id="campaign-1",
            agent_role="red_team",
            status="succeeded",
            provider="headshot",
            model="full-scan-corpus-v1",
            execution_mode="deterministic",
            configuration_version=1,
            input_sha256="a" * 64,
            output_sha256=None,
            measured_cost=0,
            cost_measurement_state="measured",
            accounting_status="measured",
            provider_event_ids=[],
            currency="USD",
            trace_id="b" * 32,
            langfuse_status="exported",
            detail={},
            started_at=_NOW,
            finished_at=None,
            duration_ms=None,
        )


@pytest.mark.parametrize(
    ("measured_cost", "input_tokens", "output_tokens"),
    (
        (0.01, None, None),
        (None, 1, None),
        (None, None, 1),
    ),
)
def test_unavailable_agent_activity_rejects_nonzero_accounting(
    measured_cost: float | None,
    input_tokens: int | None,
    output_tokens: int | None,
) -> None:
    with pytest.raises(ValidationError):
        AgentActivityReadModel(
            execution_id="execution-hosted-1",
            campaign_run_id="campaign-1",
            agent_role="red_team",
            status="running",
            provider="openrouter",
            model="provider/model",
            execution_mode="hosted_advisory",
            configuration_version=1,
            input_sha256="a" * 64,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            measured_cost=measured_cost,
            cost_measurement_state="not_observed",
            accounting_status="unavailable",
            provider_event_ids=[],
            currency="USD",
            trace_id="b" * 32,
            langfuse_status="queued",
            detail={},
            started_at=_NOW,
        )


def test_unavailable_agent_activity_preserves_provider_event_identity() -> None:
    activity = AgentActivityReadModel(
        execution_id="execution-hosted-unknown",
        campaign_run_id="campaign-1",
        agent_role="documentation",
        status="running",
        provider="openrouter",
        model="openai/gpt-5.4",
        execution_mode="hosted_advisory",
        configuration_version=1,
        configuration_set_sha256="a" * 64,
        role_configuration_sha256="b" * 64,
        generation_policy_sha256="c" * 64,
        input_sha256="d" * 64,
        physical_attempts=1,
        measured_cost=None,
        cost_measurement_state="not_observed",
        accounting_status="unavailable",
        provider_event_ids=["e" * 64],
        currency="USD",
        trace_id="f" * 32,
        langfuse_status="queued",
        detail={},
        started_at=_NOW,
    )
    assert activity.physical_attempts == 1
    assert activity.provider_event_ids == ["e" * 64]


def test_executed_birdseye_agent_requires_cost_and_delivery_state() -> None:
    with pytest.raises(ValidationError):
        BirdseyeNodeReadModel(
            component_id="agent:red_team",
            name="Red Team",
            kind="agent:red_team",
            trust_zone="execution",
            availability="operational and evidenced",
            runtime_state="ready",
            detail="headshot/full-scan-corpus-v1",
            current_task="Idle",
            is_fresh=True,
            healthy_instances=1,
            total_instances=1,
            execution_count=1,
            measured_cost_usd=None,
            accounting_status="measured",
            currency=None,
            token_observation_count=0,
            langfuse_not_attempted_count=0,
            langfuse_disabled_count=0,
            langfuse_queued_count=0,
            langfuse_exported_count=1,
            langfuse_error_count=0,
            langfuse_verified_count=0,
            last_langfuse_verified_at=None,
            langfuse_status=None,
            target_access="authorized target only",
        )


def test_birdseye_agent_rejects_remote_verification_without_exported_status() -> None:
    with pytest.raises(ValidationError):
        BirdseyeNodeReadModel(
            component_id="agent:documentation",
            name="Documentation",
            kind="agent:documentation",
            trust_zone="governance",
            availability="operational and evidenced",
            runtime_state="ready",
            detail="headshot/report-v1",
            current_task="Latest execution succeeded",
            heartbeat_at=_NOW,
            freshness_seconds=1,
            is_fresh=True,
            healthy_instances=1,
            total_instances=1,
            p50_latency_ms=20,
            p95_latency_ms=20,
            execution_count=1,
            measured_cost_usd=0,
            accounting_status="measured",
            currency="USD",
            token_observation_count=0,
            langfuse_not_attempted_count=0,
            langfuse_disabled_count=0,
            langfuse_queued_count=1,
            langfuse_exported_count=0,
            langfuse_error_count=0,
            langfuse_verified_count=1,
            last_langfuse_verified_at=_NOW,
            langfuse_status="queued",
            target_access="none",
        )
