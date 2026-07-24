"""Structural verifier doubles only; no target transcript or campaign evidence is fabricated."""

from __future__ import annotations

import copy
import json
import runpy
import sys
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import Engine, text

_VERIFIER = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts" / "verify_langfuse_campaign.py")
)
_OBSERVATION_FIELDS = _VERIFIER["_OBSERVATION_FIELDS"]
_assert_canonical_causality = _VERIFIER["_assert_canonical_causality"]
_assert_durable_campaign = _VERIFIER["_assert_durable_campaign"]
_assert_durable_provider_attempts = _VERIFIER["_assert_durable_provider_attempts"]
_assert_durable_requests = _VERIFIER["_assert_durable_requests"]
_assert_environment_binding = _VERIFIER["_assert_environment_binding"]
_assert_observations = _VERIFIER["_assert_observations"]
_assert_provider_observations = _VERIFIER["_assert_provider_observations"]
_assert_target_observations = _VERIFIER["_assert_target_observations"]
_main = _VERIFIER["main"]
_payload_digest = _VERIFIER["_payload_digest"]
_record_queryback_verification = _VERIFIER["_record_queryback_verification"]
_remote_observations = _VERIFIER["_remote_observations"]

_TRACE_ID = "7" * 32
_EXPECTED_ENVIRONMENT = "production"


def _durable_row(
    role: str,
    execution_id: str,
    *,
    parent_execution_id: str | None = None,
    execution_mode: str = "deterministic",
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    reasoning_tokens: int | None = None,
    measured_cost: str = "0",
    detail: dict[str, Any] | None = None,
    langfuse_status: str = "queued",
    langfuse_verified_at: str | None = None,
) -> dict[str, Any]:
    hosted = execution_mode == "hosted_advisory"
    return {
        "execution_id": execution_id,
        "organization_id": "org-live",
        "campaign_run_id": "run-live",
        "attempt_id": "attempt-live",
        "parent_execution_id": parent_execution_id,
        "agent_role": role,
        "provider": "openrouter" if hosted else "headshot",
        "model": "provider/model" if hosted else f"{role}-engine-v1",
        "execution_mode": execution_mode,
        "status": "succeeded",
        "error_code": None,
        "duration_ms": Decimal("12.500"),
        "input_sha256": "a" * 64,
        "output_sha256": "b" * 64,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning_tokens,
        "measured_cost": Decimal(measured_cost),
        "cost_measurement_state": "measured",
        "physical_attempts": 1 if hosted else None,
        "provider_event_ids": ["e" * 64] if hosted else [],
        "currency": "USD",
        "trace_id": _TRACE_ID,
        "langfuse_status": langfuse_status,
        "langfuse_verified_at": langfuse_verified_at,
        "detail": detail or {},
    }


def _base_rows() -> list[dict[str, Any]]:
    return [
        _durable_row("orchestrator", "execution-orchestrator"),
        _durable_row(
            "red_team",
            "execution-red-team",
            parent_execution_id="execution-orchestrator",
            execution_mode="hosted_advisory",
            input_tokens=101,
            output_tokens=23,
            reasoning_tokens=0,
            measured_cost="0.0042",
        ),
        _durable_row(
            "judge",
            "execution-judge",
            parent_execution_id="execution-red-team",
        ),
    ]


def _observation_pair(row: dict[str, Any]) -> list[dict[str, Any]]:
    execution_id = row["execution_id"]
    agent_id = f"observation-agent-{execution_id}"
    common_metadata = {
        "deployment.environment": "production",
        "organization_id": row["organization_id"],
        "campaign_run_id": row["campaign_run_id"],
        "attempt_id": row["attempt_id"],
        "parent_execution_id": row["parent_execution_id"],
        "agent.execution_id": execution_id,
        "agent.role": row["agent_role"],
        "agent.provider": row["provider"],
        "agent.model": row["model"],
        "agent.execution_mode": row["execution_mode"],
        "agent.input_sha256": row["input_sha256"],
        "agent.output_sha256": row["output_sha256"],
        "agent.status": row["status"],
        "agent.duration_ms": float(row["duration_ms"]),
    }
    if row["execution_mode"] == "deterministic":
        cost_source = "deterministic_zero"
        cost_details: dict[str, float] | None = {"total": 0.0}
    else:
        cost_source = "provider_attempt_generations"
        cost_details = None
    usage_details = None
    status_message = row["error_code"] or row["status"]
    return [
        {
            "id": agent_id,
            "trace_id": row["trace_id"],
            "parent_observation_id": (
                f"observation-agent-{row['parent_execution_id']}"
                if row["parent_execution_id"] is not None
                else None
            ),
            "type": "AGENT",
            "name": f"agent.{row['agent_role']}",
            "environment": "production",
            "end_time": "2026-07-24T12:00:00Z",
            "status_message": status_message,
            "input": {"sha256": row["input_sha256"]},
            "output": {"sha256": row["output_sha256"]},
            "metadata": dict(common_metadata),
        },
        {
            "id": f"observation-generation-{execution_id}",
            "trace_id": row["trace_id"],
            "parent_observation_id": agent_id,
            "type": "GENERATION",
            "name": f"agent.{row['agent_role']}.runtime",
            "environment": "production",
            "end_time": "2026-07-24T12:00:00Z",
            "status_message": status_message,
            "provided_model_name": row["model"],
            "input": {"sha256": row["input_sha256"]},
            "output": {"sha256": row["output_sha256"]},
            "usage_details": usage_details,
            "cost_details": cost_details,
            "metadata": {**common_metadata, "cost.source": cost_source},
        },
    ]


def _observations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [observation for row in rows for observation in _observation_pair(row)]


def _provider_row(agent: dict[str, Any]) -> dict[str, Any]:
    return {
        "invocation_id": "1" * 64,
        "organization_id": agent["organization_id"],
        "campaign_run_id": agent["campaign_run_id"],
        "campaign_attempt_id": agent["attempt_id"],
        "logical_execution_id": agent["execution_id"],
        "parent_execution_id": agent["parent_execution_id"],
        "agent_role": agent["agent_role"],
        "physical_sequence": 1,
        "requested_model": agent["model"],
        "configured_upstream": "atlas-cloud/fp8",
        "prompt_version": "red-team-v1",
        "prompt_sha256": "2" * 64,
        "configuration_set_sha256": "3" * 64,
        "role_configuration_sha256": "4" * 64,
        "generation_policy_sha256": "5" * 64,
        "started_at": "2026-07-24T12:00:00Z",
        "event_id": agent["provider_event_ids"][0],
        "event_invocation_id": "1" * 64,
        "event_physical_sequence": 1,
        "status": "succeeded",
        "returned_model": agent["model"],
        "upstream_provider": "AtlasCloud",
        "provider_request_id": "provider-request-live",
        "input_tokens": agent["input_tokens"],
        "output_tokens": agent["output_tokens"],
        "reasoning_tokens": agent["reasoning_tokens"],
        "cost_measurement_state": "measured",
        "measured_cost_usd": agent["measured_cost"],
        "error_code": None,
        "finished_at": "2026-07-24T12:00:00.005250Z",
        "duration_ms": Decimal("5.250000"),
    }


def _provider_observation(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "observation-provider-attempt",
        "trace_id": _TRACE_ID,
        "parent_observation_id": f"observation-agent-{row['logical_execution_id']}",
        "type": "GENERATION",
        "name": "provider.openrouter.attempt",
        "environment": "production",
        "end_time": "2026-07-24T12:00:00.005250Z",
        "status_message": row["status"],
        "provided_model_name": row["returned_model"],
        "input": {
            "prompt_sha256": row["prompt_sha256"],
            "configuration_set_sha256": row["configuration_set_sha256"],
            "role_configuration_sha256": row["role_configuration_sha256"],
            "generation_policy_sha256": row["generation_policy_sha256"],
        },
        "output": {"provider_event_id": row["event_id"]},
        "usage_details": {
            "input": row["input_tokens"],
            "output": row["output_tokens"],
            "reasoning": row["reasoning_tokens"],
            "total": row["input_tokens"] + row["output_tokens"] + row["reasoning_tokens"],
        },
        "cost_details": {"total": float(row["measured_cost_usd"])},
        "metadata": {
            "deployment.environment": "production",
            "organization_id": row["organization_id"],
            "campaign_run_id": row["campaign_run_id"],
            "attempt_id": row["campaign_attempt_id"],
            "parent_execution_id": row["parent_execution_id"],
            "agent.execution_id": row["logical_execution_id"],
            "agent.role": row["agent_role"],
            "provider.name": "openrouter",
            "provider.invocation_id": row["invocation_id"],
            "provider.event_id": row["event_id"],
            "provider.physical_sequence": row["physical_sequence"],
            "provider.retry_number": 0,
            "provider.is_retry": False,
            "provider.requested_model": row["requested_model"],
            "provider.returned_model": row["returned_model"],
            "provider.configured_upstream": row["configured_upstream"],
            "provider.served_upstream": row["upstream_provider"],
            "provider.request_id": row["provider_request_id"],
            "provider.prompt_version": row["prompt_version"],
            "provider.prompt_sha256": row["prompt_sha256"],
            "provider.configuration_set_sha256": row["configuration_set_sha256"],
            "provider.role_configuration_sha256": row["role_configuration_sha256"],
            "provider.generation_policy_sha256": row["generation_policy_sha256"],
            "provider.status": row["status"],
            "provider.error_code": row["error_code"],
            "provider.duration_ms": "5.25",
            "cost.source": "provider_measured",
            "cost.measurement_state": row["cost_measurement_state"],
            "cost.usd": "0.0042",
        },
    }


def _target_row() -> dict[str, Any]:
    request_payload = {"turns": ["authorized live case"]}
    response_payload = '{"answer":"bounded response"}'
    _request_sha256, request_bytes = _payload_digest(request_payload)
    return {
        "request_id": "request-live",
        "organization_id": "org-live",
        "campaign_run_id": "run-live",
        "attempt_id": "attempt-live",
        "trace_id": _TRACE_ID,
        "provider": "openemr",
        "method": "POST",
        "status": "succeeded",
        "error_code": None,
        "started_at": "2026-07-24T12:00:00Z",
        "finished_at": "2026-07-24T12:00:00.020Z",
        "duration_ms": Decimal("20.000"),
        "request_payload": request_payload,
        "response_payload": response_payload,
        "request_bytes": request_bytes,
        "response_bytes": len(response_payload.encode()),
        "measured_cost": Decimal("0.01"),
        "currency": "USD",
        "langfuse_status": "queued",
        "langfuse_verified_at": None,
        "target_id": "openemr-live",
        "target_version": "v1",
        "surface_id": "clinical-copilot",
        "surface_version": "v1",
        "case_id": "case-live",
        "attack_category": "prompt_injection",
    }


def _target_observation(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "observation-target-request-live",
        "trace_id": row["trace_id"],
        "parent_observation_id": "observation-agent-execution-red-team",
        "type": "GENERATION",
        "name": "target-http-request",
        "environment": "production",
        "end_time": "2026-07-24T12:00:00.020Z",
        "provided_model_name": row["provider"],
        "input": {
            "sha256": row["request_sha256"],
            "bytes": row["request_bytes"],
        },
        "output": {
            "sha256": row["response_sha256"],
            "bytes": row["response_bytes"],
        },
        "cost_details": {"total": float(row["measured_cost"])},
        "metadata": {
            "deployment.environment": "production",
            "organization_id": row["organization_id"],
            "campaign_run_id": row["campaign_run_id"],
            "attempt_id": row["attempt_id"],
            "case_id": row["case_id"],
            "attack_category": row["attack_category"],
            "target_id": row["target_id"],
            "target_version": row["target_version"],
            "surface_id": row["surface_id"],
            "surface_version": row["surface_version"],
            "execution_profile": "live",
            "target.provider": row["provider"],
            "http.method": row["method"],
            "http.request.body.size": row["request_bytes"],
            "http.request.body.sha256": row["request_sha256"],
            "http.response.body.size": row["response_bytes"],
            "http.response.body.sha256": row["response_sha256"],
            "transport.status": row["status"],
            "error_code": row["error_code"],
            "ledger.persisted": True,
            "duration_ms": float(row["duration_ms"]),
            "request_id": row["request_id"],
            "red_team_execution_id": "execution-red-team",
        },
    }


def _finding_row() -> dict[str, Any]:
    return {
        "organization_id": "org-live",
        "finding_id": "finding-live",
        "campaign_run_id": "run-live",
        "attempt_id": "attempt-live",
        "evidence_content_hash": "c" * 64,
        "verdict_id": 7,
    }


def _seed_verification_rows(
    engine: Engine,
    *,
    organization_id: str,
    campaign_run_id: str,
    execution_id: str,
    request_id: str,
    request_langfuse_status: str = "queued",
) -> None:
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, attempt_id, agent_role, "
                "status, provider, model, execution_mode, configuration_version, "
                "input_sha256, output_sha256, measured_cost, cost_measurement_state, "
                "trace_id, error_code, "
                "finished_at, duration_ms, langfuse_status) VALUES "
                "(:execution_id, :org, :run_id, 'attempt-verification', 'orchestrator', "
                "'succeeded', 'headshot', 'orchestrator-engine-v1', 'deterministic', 1, "
                ":input_sha256, :output_sha256, 0, 'measured', :trace_id, NULL, "
                "clock_timestamp(), 1, 'queued')"
            ),
            {
                "execution_id": execution_id,
                "org": organization_id,
                "run_id": campaign_run_id,
                "input_sha256": "a" * 64,
                "output_sha256": "b" * 64,
                "trace_id": "8" * 32,
            },
        )
        connection.execute(
            text(
                "INSERT INTO outbound_http_requests "
                "(request_id, organization_id, campaign_run_id, attempt_id, trace_id, "
                "operation, provider, method, destination_host, relative_path, "
                "request_payload, response_payload, status, status_code, request_bytes, "
                "response_bytes, duration_ms, measured_cost, langfuse_status, finished_at) "
                "VALUES (:request_id, :org, :run_id, 'attempt-verification', :trace_id, "
                "'target.http', 'target', 'POST', 'target.example.test', 'chat', "
                "'{}'::jsonb, '{}', 'succeeded', 200, 2, 2, 1, 0, "
                ":langfuse_status, clock_timestamp())"
            ),
            {
                "request_id": request_id,
                "org": organization_id,
                "run_id": campaign_run_id,
                "trace_id": "8" * 32,
                "langfuse_status": request_langfuse_status,
            },
        )


def _delete_verification_rows(
    engine: Engine,
    *,
    execution_ids: list[str],
    request_ids: list[str],
) -> None:
    with engine.begin() as connection:
        connection.execute(
            text("DELETE FROM outbound_http_requests WHERE request_id = ANY(:request_ids)"),
            {"request_ids": request_ids},
        )
        connection.execute(
            text("DELETE FROM agent_executions WHERE execution_id = ANY(:execution_ids)"),
            {"execution_ids": execution_ids},
        )


def test_cli_requires_an_explicit_expected_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["verify_langfuse_campaign.py", "--campaign-run-id", "run-live"],
    )
    with pytest.raises(SystemExit) as exc_info:
        _main()
    assert exc_info.value.code == 2


def test_environment_binding_requires_exact_runner_and_langfuse_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", _EXPECTED_ENVIRONMENT)
    monkeypatch.setenv("LANGFUSE_TRACING_ENVIRONMENT", _EXPECTED_ENVIRONMENT)
    _assert_environment_binding(_EXPECTED_ENVIRONMENT)

    monkeypatch.setenv("LANGFUSE_TRACING_ENVIRONMENT", "staging")
    with pytest.raises(SystemExit, match="LANGFUSE_TRACING_ENVIRONMENT must exactly match"):
        _assert_environment_binding(_EXPECTED_ENVIRONMENT)

    monkeypatch.setenv("LANGFUSE_TRACING_ENVIRONMENT", _EXPECTED_ENVIRONMENT)
    monkeypatch.delenv("AGENTFORGE_ENVIRONMENT")
    with pytest.raises(SystemExit, match="AGENTFORGE_ENVIRONMENT must exactly match"):
        _assert_environment_binding(_EXPECTED_ENVIRONMENT)


def test_record_queryback_verification_is_atomic_exact_and_idempotent(
    migrated_db: Engine,
) -> None:
    organization_id = "org-verifier-persistence"
    campaign_run_id = "run-verifier-persistence"
    execution_id = "execution-verifier-persistence"
    request_id = "request-verifier-persistence"
    _seed_verification_rows(
        migrated_db,
        organization_id=organization_id,
        campaign_run_id=campaign_run_id,
        execution_id=execution_id,
        request_id=request_id,
    )
    try:
        _record_queryback_verification(
            migrated_db.url.render_as_string(hide_password=False),
            organization_id=organization_id,
            campaign_run_id=campaign_run_id,
            agent_execution_ids=[execution_id],
            target_request_ids=[request_id],
            provider_invocation_event_ids=[],
        )
        with migrated_db.connect() as connection:
            first_agent_state = connection.execute(
                text(
                    "SELECT langfuse_status, langfuse_verified_at FROM agent_executions "
                    "WHERE execution_id = :execution_id"
                ),
                {"execution_id": execution_id},
            ).one()
            first_request_state = connection.execute(
                text(
                    "SELECT langfuse_status, langfuse_verified_at FROM outbound_http_requests "
                    "WHERE request_id = :request_id"
                ),
                {"request_id": request_id},
            ).one()
            first_agent_timestamp = first_agent_state.langfuse_verified_at
            first_request_timestamp = first_request_state.langfuse_verified_at
        assert first_agent_state.langfuse_status == "exported"
        assert first_request_state.langfuse_status == "exported"
        assert first_agent_timestamp is not None
        assert first_request_timestamp is not None

        _record_queryback_verification(
            migrated_db.url.render_as_string(hide_password=False),
            organization_id=organization_id,
            campaign_run_id=campaign_run_id,
            agent_execution_ids=[execution_id],
            target_request_ids=[request_id],
            provider_invocation_event_ids=[],
        )
        with migrated_db.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT langfuse_verified_at FROM agent_executions "
                        "WHERE execution_id = :execution_id"
                    ),
                    {"execution_id": execution_id},
                ).scalar_one()
                == first_agent_timestamp
            )
            assert (
                connection.execute(
                    text(
                        "SELECT langfuse_verified_at FROM outbound_http_requests "
                        "WHERE request_id = :request_id"
                    ),
                    {"request_id": request_id},
                ).scalar_one()
                == first_request_timestamp
            )
    finally:
        _delete_verification_rows(
            migrated_db,
            execution_ids=[execution_id],
            request_ids=[request_id],
        )


def test_record_queryback_verification_rolls_back_both_tables_on_mismatch(
    migrated_db: Engine,
) -> None:
    organization_id = "org-verifier-rollback"
    campaign_run_id = "run-verifier-rollback"
    execution_id = "execution-verifier-rollback"
    request_id = "request-verifier-rollback"
    _seed_verification_rows(
        migrated_db,
        organization_id=organization_id,
        campaign_run_id=campaign_run_id,
        execution_id=execution_id,
        request_id=request_id,
        request_langfuse_status="error",
    )
    try:
        with pytest.raises(
            AssertionError,
            match="target request verification persistence did not match expected IDs",
        ):
            _record_queryback_verification(
                migrated_db.url.render_as_string(hide_password=False),
                organization_id=organization_id,
                campaign_run_id=campaign_run_id,
                agent_execution_ids=[execution_id],
                target_request_ids=[request_id],
                provider_invocation_event_ids=[],
            )
        with migrated_db.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT langfuse_verified_at FROM agent_executions "
                        "WHERE execution_id = :execution_id"
                    ),
                    {"execution_id": execution_id},
                ).scalar_one()
                is None
            )
            assert (
                connection.execute(
                    text(
                        "SELECT langfuse_verified_at FROM outbound_http_requests "
                        "WHERE request_id = :request_id"
                    ),
                    {"request_id": request_id},
                ).scalar_one()
                is None
            )
    finally:
        _delete_verification_rows(
            migrated_db,
            execution_ids=[execution_id],
            request_ids=[request_id],
        )


def test_durable_campaign_requires_base_roles_and_conditional_documentation() -> None:
    rows = _base_rows()
    assert _assert_durable_campaign(
        rows,
        finding_evidence_exists=False,
        trace_id=_TRACE_ID,
    ) == {"orchestrator", "red_team", "judge"}

    documented = [
        *rows,
        _durable_row(
            "documentation",
            "execution-documentation",
            parent_execution_id="execution-judge",
            execution_mode="hosted_advisory",
        ),
    ]
    assert _assert_durable_campaign(
        documented,
        finding_evidence_exists=True,
        trace_id=_TRACE_ID,
    ) == {"orchestrator", "red_team", "judge", "documentation"}

    with pytest.raises(AssertionError, match="inconsistent with finding evidence"):
        _assert_durable_campaign(
            rows,
            finding_evidence_exists=True,
            trace_id=_TRACE_ID,
        )
    with pytest.raises(AssertionError, match="inconsistent with finding evidence"):
        _assert_durable_campaign(
            documented,
            finding_evidence_exists=False,
            trace_id=_TRACE_ID,
        )


def test_canonical_causality_reconciles_attempt_and_finding_chains() -> None:
    rows = [
        *_base_rows(),
        _durable_row(
            "documentation",
            "execution-documentation",
            parent_execution_id="execution-judge",
            detail={"finding_id": "finding-live"},
        ),
    ]
    request = _target_row()

    _assert_canonical_causality(rows, [request], [_finding_row()])


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda rows: rows.__setitem__(
                1,
                {**rows[1], "attempt_id": None},
            ),
            "Red Team execution has no durable attempt identity",
        ),
        (
            lambda rows: rows.append(
                {
                    **rows[1],
                    "execution_id": "duplicate-red-team",
                }
            ),
            "exactly one Red Team execution",
        ),
        (
            lambda rows: rows.__setitem__(
                2,
                {**rows[2], "parent_execution_id": "execution-orchestrator"},
            ),
            "Judge is not a child",
        ),
        (
            lambda rows: rows.__setitem__(
                1,
                {**rows[1], "status": "failed"},
            ),
            "non-succeeded canonical agent execution",
        ),
    ],
)
def test_canonical_causality_rejects_incomplete_attempt_chains(
    mutate: Any,
    message: str,
) -> None:
    rows = _base_rows()
    mutate(rows)

    with pytest.raises(AssertionError, match=message):
        _assert_canonical_causality(rows, [_target_row()], [])


@pytest.mark.parametrize(
    ("documentation_update", "message"),
    [
        (
            {"detail": {"finding_id": "different-finding"}},
            "exactly one matching Documentation",
        ),
        (
            {"parent_execution_id": "execution-red-team"},
            "Documentation is not a child",
        ),
    ],
)
def test_canonical_causality_rejects_unmatched_documentation(
    documentation_update: dict[str, Any],
    message: str,
) -> None:
    documentation = _durable_row(
        "documentation",
        "execution-documentation",
        parent_execution_id="execution-judge",
        detail={"finding_id": "finding-live"},
    )
    documentation.update(documentation_update)

    with pytest.raises(AssertionError, match=message):
        _assert_canonical_causality(
            [*_base_rows(), documentation],
            [_target_row()],
            [_finding_row()],
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", "running", "running agent execution"),
        ("langfuse_status", "error", "not awaiting or proven Langfuse delivery"),
    ],
)
def test_durable_campaign_rejects_incomplete_delivery(
    field: str,
    value: str,
    message: str,
) -> None:
    rows = _base_rows()
    rows[1][field] = value
    with pytest.raises(AssertionError, match=message):
        _assert_durable_campaign(
            rows,
            finding_evidence_exists=False,
            trace_id=_TRACE_ID,
        )


def test_durable_campaign_accepts_queued_and_verified_exported_delivery() -> None:
    queued = _base_rows()
    assert _assert_durable_campaign(
        queued,
        finding_evidence_exists=False,
        trace_id=_TRACE_ID,
    )

    verified = [
        {
            **row,
            "langfuse_status": "exported",
            "langfuse_verified_at": "2026-07-24T12:00:01Z",
        }
        for row in queued
    ]
    assert _assert_durable_campaign(
        verified,
        finding_evidence_exists=False,
        trace_id=_TRACE_ID,
    )


@pytest.mark.parametrize(
    ("langfuse_status", "verified_at"),
    [
        ("exported", None),
        ("queued", "2026-07-24T12:00:01Z"),
    ],
)
def test_durable_campaign_rejects_contradictory_delivery_proof(
    langfuse_status: str,
    verified_at: str | None,
) -> None:
    rows = _base_rows()
    rows[0]["langfuse_status"] = langfuse_status
    rows[0]["langfuse_verified_at"] = verified_at
    with pytest.raises(AssertionError, match="contradictory Langfuse delivery proof"):
        _assert_durable_campaign(
            rows,
            finding_evidence_exists=False,
            trace_id=_TRACE_ID,
        )


def test_target_request_query_back_reconciles_one_for_one() -> None:
    row = _target_row()
    _assert_durable_requests([row], trace_id=_TRACE_ID)
    _assert_target_observations(
        [row],
        [*_observations(_base_rows()), _target_observation(row)],
        agent_rows=_base_rows(),
        expected_environment=_EXPECTED_ENVIRONMENT,
    )


def test_provider_attempt_query_back_reconciles_exact_physical_generation() -> None:
    rows = _base_rows()
    provider = _provider_row(rows[1])
    _assert_durable_provider_attempts([provider], agent_rows=rows)
    observations = [*_observations(rows), _provider_observation(provider)]

    _assert_observations(
        rows,
        observations,
        expected_environment=_EXPECTED_ENVIRONMENT,
    )
    _assert_provider_observations(
        [provider],
        observations,
        agent_rows=rows,
        expected_environment=_EXPECTED_ENVIRONMENT,
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda observation: observation["metadata"].update(
                {"provider.request_id": "wrong-request"}
            ),
            "provider metadata does not reconcile",
        ),
        (
            lambda observation: observation["usage_details"].update({"input": 999}),
            "provider token usage does not reconcile",
        ),
        (
            lambda observation: observation.update({"parent_observation_id": "wrong-parent"}),
            "native child of its role agent",
        ),
        (
            lambda observation: observation["metadata"].update(
                {"raw_prompt": "must never be present"}
            ),
            "metadata field set does not reconcile",
        ),
    ],
)
def test_provider_attempt_query_back_rejects_mismatch_and_content_fields(
    mutate: Any,
    message: str,
) -> None:
    rows = _base_rows()
    provider = _provider_row(rows[1])
    observation = _provider_observation(provider)
    mutate(observation)

    with pytest.raises(AssertionError, match=message):
        _assert_provider_observations(
            [provider],
            [*_observations(rows), observation],
            agent_rows=rows,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


def test_hosted_logical_runtime_rejects_double_counted_provider_usage() -> None:
    rows = _base_rows()
    observations = _observations(rows)
    hosted_runtime = observations[3]
    hosted_runtime["usage_details"] = {
        "input": 101,
        "output": 23,
        "reasoning": 0,
        "total": 124,
    }
    hosted_runtime["cost_details"] = {"total": 0.0042}

    with pytest.raises(AssertionError, match="double-counts physical provider usage"):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


def test_query_back_accepts_v2_json_text_io_without_weakening_exactness() -> None:
    rows = _base_rows()
    observations = _observations(rows)
    for observation in observations:
        observation["input"] = json.dumps(observation["input"], sort_keys=True)
        observation["output"] = json.dumps(observation["output"], sort_keys=True)
    _assert_observations(
        rows,
        observations,
        expected_environment=_EXPECTED_ENVIRONMENT,
    )

    target = _target_row()
    _assert_durable_requests([target], trace_id=_TRACE_ID)
    target_observation = _target_observation(target)
    target_observation["input"] = json.dumps(target_observation["input"], sort_keys=True)
    target_observation["output"] = json.dumps(target_observation["output"], sort_keys=True)
    _assert_target_observations(
        [target],
        [*observations, target_observation],
        agent_rows=rows,
        expected_environment=_EXPECTED_ENVIRONMENT,
    )


def test_target_request_query_back_rejects_missing_or_mismatched_remote_evidence() -> None:
    row = _target_row()
    _assert_durable_requests([row], trace_id=_TRACE_ID)
    with pytest.raises(AssertionError, match="not query-visible"):
        _assert_target_observations(
            [row],
            [],
            agent_rows=_base_rows(),
            expected_environment=_EXPECTED_ENVIRONMENT,
        )

    observation = _target_observation(row)
    observation["metadata"]["target_version"] = "wrong-version"
    with pytest.raises(AssertionError, match="target_version"):
        _assert_target_observations(
            [row],
            [*_observations(_base_rows()), observation],
            agent_rows=_base_rows(),
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


def test_target_request_query_back_rejects_the_wrong_environment() -> None:
    row = _target_row()
    _assert_durable_requests([row], trace_id=_TRACE_ID)
    observation = _target_observation(row)
    observation["metadata"]["deployment.environment"] = "staging"

    with pytest.raises(AssertionError, match="deployment environment does not reconcile"):
        _assert_target_observations(
            [row],
            [*_observations(_base_rows()), observation],
            agent_rows=_base_rows(),
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


def test_target_request_query_back_rejects_the_wrong_native_langfuse_environment() -> None:
    row = _target_row()
    _assert_durable_requests([row], trace_id=_TRACE_ID)
    observation = _target_observation(row)
    observation["environment"] = "staging"

    with pytest.raises(AssertionError, match="native Langfuse environment does not reconcile"):
        _assert_target_observations(
            [row],
            [*_observations(_base_rows()), observation],
            agent_rows=_base_rows(),
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


def test_target_request_query_back_requires_native_red_team_parentage() -> None:
    row = _target_row()
    _assert_durable_requests([row], trace_id=_TRACE_ID)
    observation = _target_observation(row)
    observation["parent_observation_id"] = "observation-agent-execution-orchestrator"

    with pytest.raises(AssertionError, match="native child of its Red Team"):
        _assert_target_observations(
            [row],
            [*_observations(_base_rows()), observation],
            agent_rows=_base_rows(),
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


def test_completed_live_campaign_requires_a_physical_target_request() -> None:
    with pytest.raises(AssertionError, match="no durable physical target requests"):
        _assert_durable_requests([], trace_id=_TRACE_ID)


def test_remote_observations_follows_every_cursor_page() -> None:
    class ObservationApi:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []
            self.responses = [
                {"data": [{"id": "first"}], "meta": {"cursor": "cursor-2"}},
                {"data": [{"id": "second"}], "meta": {"cursor": "cursor-3"}},
                {"data": [{"id": "third"}], "meta": {"cursor": None}},
            ]

        def get_many(self, **parameters: Any) -> dict[str, Any]:
            self.calls.append(parameters)
            return self.responses.pop(0)

    observations_api = ObservationApi()
    client = SimpleNamespace(api=SimpleNamespace(observations=observations_api))

    assert [row["id"] for row in _remote_observations(client, _TRACE_ID)] == [
        "first",
        "second",
        "third",
    ]
    assert [call.get("cursor") for call in observations_api.calls] == [
        None,
        "cursor-2",
        "cursor-3",
    ]
    assert all(call["fields"] == _OBSERVATION_FIELDS for call in observations_api.calls)
    assert all(call["trace_id"] == _TRACE_ID for call in observations_api.calls)


def test_remote_observations_rejects_repeated_cursor() -> None:
    class ObservationApi:
        def get_many(self, **parameters: Any) -> dict[str, Any]:
            return {"data": [], "meta": {"cursor": "same-cursor"}}

    client = SimpleNamespace(api=SimpleNamespace(observations=ObservationApi()))
    with pytest.raises(AssertionError, match="repeated a cursor"):
        _remote_observations(client, _TRACE_ID)


def test_exact_observation_pairs_require_measured_hosted_cost() -> None:
    rows = _base_rows()
    rows.append(
        _durable_row(
            "documentation",
            "execution-documentation",
            parent_execution_id="execution-judge",
            execution_mode="hosted_advisory",
            input_tokens=80,
            output_tokens=20,
            measured_cost="0.002",
        )
    )
    _assert_observations(
        rows,
        _observations(rows),
        expected_environment=_EXPECTED_ENVIRONMENT,
    )


@pytest.mark.parametrize("observation_index", [0, 1])
def test_every_agent_observation_requires_the_exact_environment(
    observation_index: int,
) -> None:
    rows = [_durable_row("orchestrator", "execution-orchestrator")]
    observations = _observations(rows)
    observations[observation_index]["metadata"]["deployment.environment"] = "staging"

    with pytest.raises(AssertionError, match="deployment environment does not reconcile"):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


@pytest.mark.parametrize("observation_index", [0, 1])
def test_every_agent_observation_requires_the_exact_native_langfuse_environment(
    observation_index: int,
) -> None:
    rows = [_durable_row("orchestrator", "execution-orchestrator")]
    observations = _observations(rows)
    observations[observation_index]["environment"] = "staging"

    with pytest.raises(AssertionError, match="native Langfuse environment does not reconcile"):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


@pytest.mark.parametrize(
    ("observation_index", "field", "value", "message"),
    [
        (1, "name", "agent.red_team.other", "typed agent/runtime observation pair"),
        (1, "type", "SPAN", "typed agent/runtime observation pair"),
        (1, "provided_model_name", "wrong-model", "generation model does not reconcile"),
        (0, "parent_observation_id", "unexpected-parent", "root agent has a remote parent"),
        (2, "parent_observation_id", "wrong-parent", "cross-agent parentage"),
        (1, "end_time", None, "generation observation is not terminal"),
        (1, "status_message", "running", "terminal status does not reconcile"),
    ],
)
def test_observation_pair_shape_status_and_hierarchy_fail_closed(
    observation_index: int,
    field: str,
    value: Any,
    message: str,
) -> None:
    rows = _base_rows()
    observations = _observations(rows)
    observations[observation_index][field] = value
    with pytest.raises(AssertionError, match=message):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


@pytest.mark.parametrize(
    "metadata_key",
    ["agent.role", "agent.provider", "agent.model", "agent.execution_mode"],
)
def test_observation_metadata_must_match_durable_assignment(metadata_key: str) -> None:
    rows = _base_rows()
    observations = _observations(rows)
    observations[3]["metadata"][metadata_key] = "mismatch"
    with pytest.raises(AssertionError, match=metadata_key):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


def test_observation_pairs_reject_duplicates_and_unknown_executions() -> None:
    rows = _base_rows()
    observations = _observations(rows)
    observations.append(copy.deepcopy(observations[0]))
    with pytest.raises(AssertionError, match="duplicated"):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )

    observations = _observations(rows)
    duplicate_agent = copy.deepcopy(observations[0])
    duplicate_agent["id"] = "another-agent-observation"
    observations.append(duplicate_agent)
    with pytest.raises(AssertionError, match="exactly one typed agent/runtime observation pair"):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )

    observations = _observations(rows)
    observations[0]["metadata"]["agent.execution_id"] = "execution-outside-campaign"
    with pytest.raises(AssertionError, match="unknown execution"):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )


def test_token_and_cost_semantics_fail_closed() -> None:
    rows = _base_rows()

    observations = _observations(rows)
    observations[3]["usage_details"] = {
        "input": 101,
        "output": 23,
        "reasoning": 0,
        "total": 124,
    }
    with pytest.raises(AssertionError, match="double-counts physical provider usage"):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )

    observations = _observations(rows)
    observations[3]["cost_details"] = {"total": 0.0042}
    with pytest.raises(AssertionError, match="double-counts physical provider usage"):
        _assert_observations(
            rows,
            observations,
            expected_environment=_EXPECTED_ENVIRONMENT,
        )

    unavailable = _durable_row(
        "documentation",
        "execution-documentation",
        execution_mode="hosted_advisory",
    )
    with pytest.raises(AssertionError, match="physical provider attempt count"):
        _assert_durable_provider_attempts([], agent_rows=[unavailable])

    deterministic = _durable_row("judge", "execution-judge", measured_cost="0.01")
    with pytest.raises(AssertionError, match="deterministic zero-cost accounting"):
        _assert_observations(
            [deterministic],
            _observation_pair(deterministic),
            expected_environment=_EXPECTED_ENVIRONMENT,
        )
