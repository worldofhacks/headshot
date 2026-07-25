"""Exact, target-free Langfuse query-back for the three-role acceptance chain."""

from __future__ import annotations

import copy
import datetime
import hashlib
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import Engine, text

from agentforge.agent_acceptance import acceptance_generation_policy, acceptance_limits
from agentforge.agent_acceptance_verifier import (
    AcceptanceSnapshot,
    assert_durable_acceptance,
    assert_remote_acceptance,
    load_acceptance_snapshot,
    record_queryback_verification,
)
from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_prompts import hosted_prompt
from agentforge.auth.principal import Principal
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.correlation import campaign_trace_id
from agentforge.providers.lineage import ProviderTerminalEventV1

_RUN_ID = "AR-verifier-fixture"
_ORGANIZATION_ID = "org_acceptance_verifier"
_TRACE_ID = campaign_trace_id(_RUN_ID)
_CALIBRATION_ID = f"JC-{'c' * 64}"
_ATTEMPT_ID = "e" * 64
_ROLES = ("orchestrator", "judge", "documentation")
_MODELS = {
    "orchestrator": "anthropic/claude-opus-4.8",
    "red_team": "qwen/qwen3.5-397b-a17b",
    "judge": "google/gemini-2.5-pro",
    "documentation": "openai/gpt-5.4",
}
_UPSTREAMS = {
    "orchestrator": "anthropic",
    "red_team": "together",
    "judge": "google-vertex",
    "documentation": "openai",
}
_ROLE_CAPS = {
    "orchestrator": Decimal("1.5"),
    "red_team": Decimal("1"),
    "judge": Decimal("4"),
    "documentation": Decimal("1"),
}


def _configuration() -> HostedConfigurationSet:
    return HostedConfigurationSet(
        roles=tuple(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=_MODELS[role],
                upstream_provider=_UPSTREAMS[role],
                credential_reference=f"secretref://local/openrouter/{role}/acceptance-1",
                prompt_sha256=hosted_prompt(role).prompt_sha256,  # type: ignore[arg-type]
                policy_sha256=hashlib.sha256(f"{role}:acceptance".encode()).hexdigest(),
                prices=TokenPrices(
                    input_usd_per_million_tokens=Decimal("100"),
                    output_usd_per_million_tokens=Decimal("100"),
                    reasoning_usd_per_million_tokens=Decimal("100"),
                ),
                limits=HostedLimits(
                    max_calls=1,
                    max_input_tokens=8_192,
                    max_output_tokens=512,
                    max_reasoning_tokens=1_024,
                    max_usd=_ROLE_CAPS[role],
                    max_retries=0,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
            for role in ("orchestrator", "red_team", "judge", "documentation")
        ),
        global_limits=HostedLimits(
            max_calls=3,
            max_input_tokens=24_576,
            max_output_tokens=1_536,
            max_reasoning_tokens=3_072,
            max_usd=Decimal("10"),
            max_retries=0,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _logical_row(
    role: str,
    execution_id: str,
    *,
    parent_execution_id: str | None,
) -> dict[str, Any]:
    judge = role == "judge"
    model = {
        "orchestrator": "anthropic/claude-opus-4.8",
        "judge": "google/gemini-2.5-pro",
        "documentation": "openai/gpt-5.4",
    }[role]
    upstream = {
        "orchestrator": "Anthropic",
        "judge": "Google Vertex",
        "documentation": "OpenAI",
    }[role]
    return {
        "execution_id": execution_id,
        "organization_id": _ORGANIZATION_ID,
        "campaign_run_id": _RUN_ID,
        "attempt_id": _ATTEMPT_ID,
        "parent_execution_id": parent_execution_id,
        "agent_role": role,
        "provider": "openrouter",
        "model": model,
        "execution_mode": "hosted_advisory",
        "status": "succeeded",
        "error_code": None,
        "started_at": "2026-07-24T12:00:00Z",
        "finished_at": "2026-07-24T12:00:01Z",
        "duration_ms": Decimal("1000.000000"),
        "input_sha256": role[0] * 64,
        "output_sha256": role[-1] * 64,
        "returned_model": model,
        "upstream_provider": upstream,
        "provider_request_id": f"provider-request-{role}",
        "input_tokens": 10,
        "output_tokens": 5,
        "reasoning_tokens": 2,
        "measured_cost": Decimal("0.010000000000"),
        "cost_measurement_state": "measured",
        "provider_event_ids": [hashlib.sha256(f"event:{role}".encode()).hexdigest()[:32]],
        "physical_attempts": 1,
        "configuration_set_sha256": "a" * 64,
        "role_configuration_sha256": role[0] * 64,
        "generation_policy_sha256": "b" * 64,
        "judge_calibration_id": _CALIBRATION_ID if judge else None,
        "judge_calibration_state": "failed" if judge else None,
        "oracle_agreement": True if judge else None,
        "decision_authority": "oracle" if judge else None,
        "trace_id": _TRACE_ID,
        "langfuse_status": "queued",
        "langfuse_verified_at": None,
        "detail": {
            "acceptance_id": _RUN_ID,
            "run_kind": "agent_acceptance",
            "synthetic": True,
            "target_call_limit": 0,
        },
    }


def _snapshot() -> AcceptanceSnapshot:
    orchestrator = _logical_row(
        "orchestrator",
        "execution-orchestrator",
        parent_execution_id=None,
    )
    judge = _logical_row(
        "judge",
        "execution-judge",
        parent_execution_id=orchestrator["execution_id"],
    )
    documentation = _logical_row(
        "documentation",
        "execution-documentation",
        parent_execution_id=judge["execution_id"],
    )
    agents = (orchestrator, judge, documentation)
    provider_calls = tuple(
        {
            "invocation_id": f"invocation-{row['agent_role']}",
            "organization_id": _ORGANIZATION_ID,
            "campaign_run_id": _RUN_ID,
            "campaign_attempt_id": _ATTEMPT_ID,
            "logical_execution_id": row["execution_id"],
            "parent_execution_id": row["parent_execution_id"],
            "agent_role": row["agent_role"],
            "physical_sequence": 1,
            "requested_model": row["model"],
            "configured_upstream": {
                "orchestrator": "anthropic",
                "judge": "google-vertex",
                "documentation": "openai",
            }[row["agent_role"]],
            "prompt_version": "1",
            "prompt_sha256": "d" * 64,
            "configuration_set_sha256": row["configuration_set_sha256"],
            "role_configuration_sha256": row["role_configuration_sha256"],
            "generation_policy_sha256": row["generation_policy_sha256"],
            "started_at": row["started_at"],
            "event_id": row["provider_event_ids"][0],
            "event_status": "succeeded",
            "event_is_final": True,
            "event_returned_model": row["returned_model"],
            "event_upstream_provider": row["upstream_provider"],
            "event_provider_request_id": row["provider_request_id"],
            "event_input_tokens": row["input_tokens"],
            "event_output_tokens": row["output_tokens"],
            "event_reasoning_tokens": row["reasoning_tokens"],
            "event_cost_measurement_state": "measured",
            "event_measured_cost_usd": row["measured_cost"],
            "event_error_code": None,
            "event_finished_at": row["finished_at"],
            "event_duration_ms": row["duration_ms"],
        }
        for row in agents
    )
    return AcceptanceSnapshot(
        run={
            "organization_id": _ORGANIZATION_ID,
            "run_id": _RUN_ID,
            "run_kind": "agent_acceptance",
            "acceptance_configuration_sha256": "a" * 64,
            "acceptance_generation_policy_sha256": "b" * 64,
            "acceptance_context_sha256": "c" * 64,
            "acceptance_attempt_id": _ATTEMPT_ID,
            "acceptance_limits": acceptance_limits(),
            "acceptance_actor_id": "system:test",
            "acceptance_provenance": {},
            "state": "complete",
        },
        attempts=(
            {
                "organization_id": _ORGANIZATION_ID,
                "run_id": _RUN_ID,
                "attempt_id": _ATTEMPT_ID,
                "ordinal": 0,
                "case_id": "agentforge-hosted-acceptance-v1",
                "case_content_hash": "c" * 64,
                "category": None,
                "severity": None,
                "attack_class": None,
                "owasp_mappings": None,
                "fixture_provenance": {
                    "classification": "synthetic",
                    "contains_real_phi": False,
                    "schema_version": "1",
                    "source": "agentforge.live_acceptance",
                },
                "source_tool": None,
                "source_technique": None,
            },
        ),
        agents=agents,
        provider_calls=provider_calls,
        target_request_count=0,
    )


def _observation_pair(row: dict[str, Any]) -> list[dict[str, Any]]:
    execution_id = row["execution_id"]
    agent_id = f"observation-agent-{execution_id}"
    metadata = {
        "deployment.environment": "local",
        "organization_id": row["organization_id"],
        "campaign_run_id": row["campaign_run_id"],
        "run.kind": "agent_acceptance",
        "agent.acceptance_run_id": row["campaign_run_id"],
        "attempt_id": row["attempt_id"],
        "parent_execution_id": row["parent_execution_id"],
        "agent.execution_id": execution_id,
        "agent.role": row["agent_role"],
        "agent.provider": row["provider"],
        "agent.model": row["model"],
        "agent.execution_mode": row["execution_mode"],
        "agent.input_sha256": row["input_sha256"],
        "agent.output_sha256": row["output_sha256"],
        "agent.configuration_set_sha256": row["configuration_set_sha256"],
        "agent.role_configuration_sha256": row["role_configuration_sha256"],
        "agent.generation_policy_sha256": row["generation_policy_sha256"],
        "agent.status": row["status"],
        "agent.duration_ms": float(row["duration_ms"]),
        "agent.returned_model": row["returned_model"],
        "agent.upstream_provider": row["upstream_provider"],
        "agent.provider_request_id": row["provider_request_id"],
        "agent.physical_attempts": row["physical_attempts"],
        "agent.provider_event_ids": row["provider_event_ids"],
        "cost.usd": float(row["measured_cost"]),
        "cost.measurement_state": row["cost_measurement_state"],
        "cost.source": "provider_measured",
        "currency": "USD",
        "judge.calibration_id": row["judge_calibration_id"],
        "judge.calibration_state": row["judge_calibration_state"],
        "judge.oracle_agreement": row["oracle_agreement"],
        "judge.decision_authority": row["decision_authority"],
        "error_code": None,
    }
    common = {
        "trace_id": row["trace_id"],
        "environment": "local",
        "end_time": "2026-07-24T12:00:01Z",
        "status_message": "succeeded",
        "input": {"sha256": row["input_sha256"]},
        "output": {"sha256": row["output_sha256"]},
        "metadata": dict(metadata),
    }
    return [
        {
            **common,
            "id": agent_id,
            "parent_observation_id": (
                f"observation-agent-{row['parent_execution_id']}"
                if row["parent_execution_id"] is not None
                else None
            ),
            "type": "AGENT",
            "name": f"agent.{row['agent_role']}",
        },
        {
            **common,
            "id": f"observation-generation-{execution_id}",
            "parent_observation_id": agent_id,
            "type": "GENERATION",
            "name": f"agent.{row['agent_role']}.runtime",
            "provided_model_name": row["returned_model"],
            "usage_details": {
                "input": row["input_tokens"],
                "output": row["output_tokens"],
                "reasoning": row["reasoning_tokens"],
                "total": row["input_tokens"] + row["output_tokens"] + row["reasoning_tokens"],
            },
            "cost_details": {"total": float(row["measured_cost"])},
        },
    ]


def _observations(snapshot: AcceptanceSnapshot) -> list[dict[str, Any]]:
    return [item for row in snapshot.agents for item in _observation_pair(row)]


def test_exact_acceptance_reconciles_durable_and_remote_lineage() -> None:
    snapshot = _snapshot()
    by_role = assert_durable_acceptance(snapshot)
    evidence = assert_remote_acceptance(
        snapshot,
        _observations(snapshot),
        expected_environment="local",
    )

    assert set(by_role) == set(_ROLES)
    assert set(evidence) == set(_ROLES)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: object.__setattr__(value, "target_request_count", 1),
            "target traffic",
        ),
        (
            lambda value: value.agents[1].update(
                {"parent_execution_id": "execution-documentation"}
            ),
            "parent chain",
        ),
        (
            lambda value: value.agents[1].update(
                {
                    "judge_calibration_state": "enabled",
                    "decision_authority": "model",
                }
            ),
            "not advisory",
        ),
        (
            lambda value: object.__setattr__(
                value, "provider_calls", (*value.provider_calls, value.provider_calls[0])
            ),
            "exactly three provider",
        ),
        (
            lambda value: value.agents[1].update({"upstream_provider": "api_key=not-telemetry"}),
            "logical acceptance lineage",
        ),
        (
            lambda value: value.agents[0].update({"returned_model": "anthropic/other-model"}),
            "logical acceptance lineage",
        ),
    ],
)
def test_durable_acceptance_rejects_scope_authority_or_lineage_drift(
    mutation,
    message: str,
) -> None:
    snapshot = copy.deepcopy(_snapshot())
    mutation(snapshot)
    with pytest.raises(AssertionError, match=message):
        assert_durable_acceptance(snapshot)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda rows: rows.pop(),
            "exactly three role pairs",
        ),
        (
            lambda rows: rows[3]["usage_details"].update({"reasoning": 99, "total": 114}),
            "token usage",
        ),
        (
            lambda rows: rows[5]["cost_details"].update({"total": 0.99}),
            "cost",
        ),
        (
            lambda rows: rows[2].update({"parent_observation_id": "wrong-parent"}),
            "cross-agent parentage",
        ),
        (
            lambda rows: rows[1]["metadata"].update({"agent.returned_model": "other/model"}),
            "returned_model",
        ),
    ],
)
def test_remote_acceptance_rejects_missing_or_mismatched_evidence(
    mutate,
    message: str,
) -> None:
    snapshot = _snapshot()
    observations = _observations(snapshot)
    mutate(observations)
    with pytest.raises(AssertionError, match=message):
        assert_remote_acceptance(
            snapshot,
            observations,
            expected_environment="local",
        )


def _seed_completed_acceptance(engine: Engine) -> str:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE campaign_runs, hosted_configuration_sets, "
                "command_idempotency, audit_events RESTART IDENTITY CASCADE"
            )
        )
    configuration = _configuration()
    generation_policy = acceptance_generation_policy()
    store = ControlPlaneStore(engine, environment="local")
    store.stage_hosted_configuration_set(
        principal=Principal(
            user_id="user_acceptance_verifier",
            session_id="sess_acceptance_verifier",
            organization_id=_ORGANIZATION_ID,
            organization_role="org:operator",
            organization_permissions=frozenset({"org:config:manage"}),
        ),
        configuration=configuration,
        release_sha256=hashlib.sha256(b"agent-acceptance-verifier-release").hexdigest(),
        rationale=(
            "Stage the bounded, target-free four-role hosted acceptance configuration through "
            "CONFIG_MANAGE; this does not authorize campaign or target traffic."
        ),
        idempotency_key="agent-acceptance-verifier-stage-0001",
    )
    identity = store.create_agent_acceptance_run(
        organization_id=_ORGANIZATION_ID,
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=generation_policy.policy_sha256,
        acceptance_context={
            "schema_version": "1",
            "synthetic": True,
            "target_scope": "none",
        },
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        limits=acceptance_limits(),
    )
    run_id = identity.run_id
    parent_execution_id: str | None = None
    served_upstreams = {
        "orchestrator": "anthropic",
        "judge": "google-vertex",
        "documentation": "openai",
    }
    for role in _ROLES:
        role_configuration = next(item for item in configuration.roles if item.role == role)
        judge = role == "judge"
        execution_id = store.start_acceptance_agent_execution(
            run_id=run_id,
            agent_role=role,  # type: ignore[arg-type]
            input_payload={"fixture": "acceptance-verifier", "role": role},
            provider=role_configuration.provider,
            model=role_configuration.model_id,
            upstream_provider=role_configuration.upstream_provider,
            configuration_set_sha256=configuration.configuration_sha256,
            role_configuration_sha256=role_configuration.configuration_sha256,
            generation_policy_sha256=generation_policy.policy_sha256,
            judge_calibration_id=_CALIBRATION_ID if judge else None,
            judge_calibration_state="failed" if judge else None,
            parent_execution_id=parent_execution_id,
            detail={
                "synthetic": True,
                "target_call_limit": 0,
                "phase": "agent_only_live_acceptance",
            },
        )
        prompt = hosted_prompt(role)  # type: ignore[arg-type]
        logical = store.provider_logical_context(
            execution_id=execution_id,
            prompt_version=prompt.version,
            prompt_sha256=prompt.prompt_sha256,
        )
        invocation = store.begin_physical_attempt(logical, 1)
        store.finish_physical_attempt(
            invocation,
            ProviderTerminalEventV1(
                invocation_id=invocation.invocation_id,
                physical_sequence=1,
                status="succeeded",
                returned_model=logical.requested_model,
                upstream_provider=served_upstreams[role],
                provider_request_id=f"provider-request-{role}",
                input_tokens=10,
                output_tokens=5,
                reasoning_tokens=2,
                cost_measurement_state="measured",
                measured_cost_usd=Decimal("0.010000000000"),
                error_code=None,
                finished_at=datetime.datetime.now(datetime.UTC),
            ),
            final=True,
        )
        store.finish_hosted_agent_execution(
            execution_id=execution_id,
            status="succeeded",
            output_payload={"fixture": "acceptance-verifier", "role": role},
            returned_model=logical.requested_model,
            upstream_provider=served_upstreams[role],
            provider_request_id=f"provider-request-{role}",
            input_tokens=10,
            output_tokens=5,
            reasoning_tokens=2,
            measured_cost_usd="0.010000000000",
            configuration_set_sha256=configuration.configuration_sha256,
            role_configuration_sha256=role_configuration.configuration_sha256,
            generation_policy_sha256=generation_policy.policy_sha256,
            physical_attempts=1,
            oracle_agreement=True if judge else None,
            decision_authority="oracle" if judge else None,
            detail={
                "synthetic": True,
                "target_call_limit": 0,
                "phase": "agent_only_live_acceptance",
            },
        )
        parent_execution_id = execution_id
    store.complete_agent_acceptance_run(run_id=run_id)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE agent_executions SET langfuse_status = 'queued' "
                "WHERE campaign_run_id = :run_id"
            ),
            {"run_id": run_id},
        )
    return run_id


def test_queryback_marking_is_exact_and_atomic(migrated_db: Engine) -> None:
    run_id = _seed_completed_acceptance(migrated_db)
    with migrated_db.connect() as connection:
        snapshot = load_acceptance_snapshot(connection, run_id=run_id)
    assert_durable_acceptance(snapshot)
    execution_ids = [str(row["execution_id"]) for row in snapshot.agents]

    with pytest.raises(AssertionError, match="differ from durable"):
        record_queryback_verification(
            migrated_db,
            run_id=run_id,
            execution_ids=[*execution_ids[:2], "unknown-execution"],
        )
    with migrated_db.connect() as connection:
        assert set(
            connection.execute(
                text(
                    "SELECT langfuse_status FROM agent_executions WHERE campaign_run_id = :run_id"
                ),
                {"run_id": run_id},
            ).scalars()
        ) == {"queued"}

    record_queryback_verification(
        migrated_db,
        run_id=run_id,
        execution_ids=execution_ids,
    )
    with migrated_db.connect() as connection:
        rows = connection.execute(
            text(
                "SELECT langfuse_status, langfuse_verified_at FROM agent_executions "
                "WHERE campaign_run_id = :run_id"
            ),
            {"run_id": run_id},
        ).mappings()
    assert all(
        row["langfuse_status"] == "exported" and row["langfuse_verified_at"] is not None
        for row in rows
    )
