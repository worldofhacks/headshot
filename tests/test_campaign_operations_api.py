"""Campaign-scoped operations projection and protected route contracts."""

from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import replace
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, text

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.prompts import load_prompt_registry
from agentforge.api.postgres import PostgresApiBackend
from agentforge.api.read_models import validate_ready_data
from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.dependencies import get_clerk_auth_config, require_authenticated
from agentforge.auth.principal import Principal
from agentforge.control_plane import ControlPlaneStore
from agentforge.web import WebSecurityConfig, create_web_app

_ORGANIZATION_ID = "org_CampaignOperationsFixture"
_LAUNCHER_USER_ID = "user_CampaignOperationsLauncher"
_ORIGIN = "https://campaign-operations.example.test"
_RUN_ID = "run-campaign-operations-fixture"
_REQUEST_ID = "request-campaign-operations-fixture"
_ATTEMPT_COMPLETE = "attempt-complete"
_ATTEMPT_FAILED = "attempt-failed"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _operations_hosted_configuration() -> HostedConfigurationSet:
    prompts = {record.role: record for record in load_prompt_registry()}
    identities = {
        "orchestrator": ("anthropic/claude-opus-4.8", "anthropic"),
        "red_team": ("qwen/qwen3.5-397b-a17b", "together"),
        "judge": ("google/gemini-2.5-pro", "google-vertex"),
        "documentation": ("openai/gpt-5.4", "openai"),
    }
    return HostedConfigurationSet(
        roles=tuple(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=model,
                upstream_provider=upstream,
                credential_reference=f"secretref://staging/openrouter/{role}/generation-1",
                prompt_sha256=prompts[role].sha256,
                policy_sha256=_digest(f"{role}:operations-policy"),
                prices=TokenPrices(
                    input_usd_per_million_tokens=Decimal("1"),
                    output_usd_per_million_tokens=Decimal("2"),
                    reasoning_usd_per_million_tokens=Decimal("3"),
                ),
                limits=HostedLimits(
                    max_calls=3,
                    max_input_tokens=100_000,
                    max_output_tokens=20_000,
                    max_reasoning_tokens=20_000,
                    max_usd=Decimal("1"),
                    max_retries=1,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
            for role, (model, upstream) in identities.items()
        ),
        global_limits=HostedLimits(
            max_calls=12,
            max_input_tokens=400_000,
            max_output_tokens=80_000,
            max_reasoning_tokens=80_000,
            max_usd=Decimal("4"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _configuration_with_exhausted_retry_authority(
    authority: str,
) -> HostedConfigurationSet:
    configuration = _operations_hosted_configuration()
    roles = list(configuration.roles)
    global_limits = configuration.global_limits
    if authority in {"campaign_call", "campaign_spend"}:
        pass
    elif authority == "role_call":
        roles = [
            replace(role, limits=replace(role.limits, max_calls=1))
            if role.role == "judge"
            else role
            for role in roles
        ]
    elif authority == "global_call":
        global_limits = replace(global_limits, max_calls=10)
    elif authority == "role_spend":
        roles = [
            replace(role, limits=replace(role.limits, max_usd=Decimal("0.04")))
            if role.role == "judge"
            else role
            for role in roles
        ]
    elif authority == "global_spend":
        global_limits = replace(global_limits, max_usd=Decimal("1.03"))
    elif authority == "role_input_tokens":
        roles = [
            replace(role, limits=replace(role.limits, max_input_tokens=32_768))
            if role.role == "judge"
            else role
            for role in roles
        ]
    elif authority == "effective_prompt_input":
        roles = [
            replace(role, limits=replace(role.limits, max_input_tokens=45_000))
            if role.role == "judge"
            else role
            for role in roles
        ]
    elif authority == "global_input_tokens":
        global_limits = replace(global_limits, max_input_tokens=100_000)
    elif authority == "role_completion_tokens":
        roles = [
            replace(
                role,
                limits=replace(
                    role.limits,
                    max_output_tokens=512,
                    max_reasoning_tokens=1_024,
                ),
            )
            if role.role == "judge"
            else role
            for role in roles
        ]
    elif authority == "global_completion_tokens":
        global_limits = replace(
            global_limits,
            max_output_tokens=20_000,
            max_reasoning_tokens=20_000,
        )
    else:
        raise ValueError("test retry authority is invalid")
    return replace(configuration, roles=tuple(roles), global_limits=global_limits)


def _seed_failed_campaign(
    engine: Engine,
    *,
    organization_id: str,
    launcher_user_id: str,
    run_id: str = _RUN_ID,
    request_id: str = _REQUEST_ID,
    attempt_complete: str = _ATTEMPT_COMPLETE,
    attempt_failed: str = _ATTEMPT_FAILED,
    hosted_configuration: HostedConfigurationSet | None = None,
    provider_model_call_limit_override: int | None = None,
    provider_model_spend_limit_usd_override: str | None = None,
    omitted_hosted_authority: str | None = None,
) -> None:
    provider_model_call_limit = (
        provider_model_call_limit_override
        if provider_model_call_limit_override is not None
        else (
            hosted_configuration.global_limits.max_calls if hosted_configuration is not None else 12
        )
    )
    provider_model_spend_limit_usd = (
        provider_model_spend_limit_usd_override
        if provider_model_spend_limit_usd_override is not None
        else (
            format(hosted_configuration.global_limits.max_usd, "f")
            if hosted_configuration is not None
            else "3.0"
        )
    )
    provider_max_retries = (
        hosted_configuration.global_limits.max_retries if hosted_configuration is not None else 1
    )
    hosted_run = {
        "generation_policy_sha256": DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256,
        "provider_model_call_limit": provider_model_call_limit,
        "provider_model_spend_limit_usd": provider_model_spend_limit_usd,
        "provider_max_retries": provider_max_retries,
    }
    if hosted_configuration is not None:
        hosted_run["configuration_set_sha256"] = hosted_configuration.configuration_sha256
    if omitted_hosted_authority is not None:
        if omitted_hosted_authority not in hosted_run:
            raise ValueError("test hosted authority omission is invalid")
        hosted_run.pop(omitted_hosted_authority)
    scope = {
        "target_id": "copilot-api",
        "target_version": "1.0.0",
        "surface_id": "chat-api",
        "surface_version": "1.0.0",
        "adapter_kind": "openemr",
        "environment": "staging",
        "exact_host": "target.example.test",
        "auth_mode": "bearer",
        "protocol": "https",
        "method": "POST",
        "relative_path": "api/copilot/message",
        "corpus_id": "batch-fixture",
        "corpus_hash": "c" * 64,
        "run_nonce": "campaign-operations-fixture-nonce",
        "execution_profile": "live",
        "caps": {
            "budget_usd": 5.0,
            "max_attempts_per_run": 3,
            "target_requests_per_second": 1.0,
            "run_timeout_seconds": 180.0,
            "logical_case_limit": 3,
            "physical_request_limit": 4,
            "target_retries_per_turn": 0,
        },
        "hosted_run": hosted_run,
    }
    with engine.begin() as connection:
        if hosted_configuration is not None:
            connection.execute(
                text(
                    "INSERT INTO hosted_configuration_sets "
                    "(organization_id, configuration_sha256, schema_version, release_sha256, "
                    "payload, rationale, actor_user_id, actor_session_id) VALUES "
                    "(:org, :configuration, :schema_version, :release, CAST(:payload AS jsonb), "
                    "'Campaign operations retryability fixture.', :launcher, "
                    "'sess_CampaignOperationsFixture')"
                ),
                {
                    "org": organization_id,
                    "configuration": hosted_configuration.configuration_sha256,
                    "schema_version": hosted_configuration.schema_version,
                    "release": _digest(f"release:{organization_id}:{run_id}"),
                    "payload": json.dumps(hosted_configuration.canonical_payload()),
                    "launcher": launcher_user_id,
                },
            )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, "
                "launcher_user_id, launcher_session_id, expires_at) VALUES "
                "(:request_id, :org, :scope_hash, CAST(:scope AS jsonb), "
                ":launcher, :session, clock_timestamp() + interval '30 minutes')"
            ),
            {
                "request_id": request_id,
                "org": organization_id,
                "scope_hash": "a" * 64,
                "scope": json.dumps(scope),
                "launcher": launcher_user_id,
                "session": "sess_CampaignOperationsFixture",
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) VALUES "
                "(:decision_id, :org, :request_id, "
                ":scope_hash, 'approved', 'user_CampaignOperationsApprover', "
                "'sess_CampaignOperationsApprover')"
            ),
            {
                "decision_id": f"decision-{run_id}",
                "org": organization_id,
                "request_id": request_id,
                "scope_hash": "a" * 64,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run_id, :org, :request_id, :scope_hash, :launcher, :session)"
            ),
            {
                "run_id": run_id,
                "org": organization_id,
                "request_id": request_id,
                "scope_hash": "a" * 64,
                "launcher": launcher_user_id,
                "session": "sess_CampaignOperationsFixture",
            },
        )
        for ordinal, (attempt_id, case_id) in enumerate(
            (
                (attempt_complete, "case-complete"),
                (attempt_failed, "case-failed"),
            )
        ):
            connection.execute(
                text(
                    "INSERT INTO campaign_attempts "
                    "(organization_id, run_id, attempt_id, ordinal, case_id) "
                    "VALUES (:org, :run_id, :attempt_id, :ordinal, :case_id)"
                ),
                {
                    "org": organization_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "ordinal": ordinal,
                    "case_id": case_id,
                },
            )
        connection.execute(
            text(
                "INSERT INTO attempt_result "
                "(campaign_run_id, attempt_id, organization_id, content_hash) "
                "VALUES (:run_id, :attempt_id, :org, :content_hash)"
            ),
            {
                "run_id": run_id,
                "attempt_id": attempt_complete,
                "org": organization_id,
                "content_hash": "b" * 64,
            },
        )
        connection.execute(
            text(
                "INSERT INTO verdict "
                "(state, confidence, campaign_run_id, attempt_id, organization_id) "
                "VALUES ('INDETERMINATE', 0.5, :run_id, :attempt_id, :org)"
            ),
            {
                "run_id": run_id,
                "attempt_id": attempt_complete,
                "org": organization_id,
            },
        )
        connection.execute(
            text(
                "INSERT INTO outbound_http_requests "
                "(request_id, organization_id, campaign_run_id, attempt_id, trace_id, "
                "operation, provider, method, destination_host, relative_path, "
                "request_payload, response_payload, status, status_code, request_bytes, "
                "response_bytes, duration_ms, measured_cost, currency, langfuse_status, "
                "finished_at) VALUES "
                "(:target_request_id, :org, :run_id, :attempt_id, "
                ":trace_id, 'target.http', 'openemr', 'POST', 'target.example.test', "
                "'api/copilot/message', '{}'::jsonb, '{}', 'succeeded', 200, 2, 2, "
                "12.5, 0.01, 'USD', 'disabled', clock_timestamp())"
            ),
            {
                "org": organization_id,
                "run_id": run_id,
                "attempt_id": attempt_complete,
                "target_request_id": f"target-{run_id}",
                "trace_id": "1" * 32,
            },
        )

    store = ControlPlaneStore(engine, environment="staging")
    execution_id = store.start_agent_execution(
        run_id=run_id,
        agent_role="judge",
        attempt_id=attempt_failed,
        input_payload={"case_id": "case-failed"},
        detail={"phase": "response_adjudication"},
    )
    store.finish_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"attempt_id": attempt_failed},
        error_code="invalid_structured_output",
        detail={"phase": "response_adjudication"},
    )
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_run_events "
                "(organization_id, run_id, state, reason_code) "
                "VALUES (:org, :run_id, 'failed', 'campaign_execution_failed')"
            ),
            {"org": organization_id, "run_id": run_id},
        )


def _seed_invalid_output_provider_failure(
    engine: Engine,
    *,
    organization_id: str,
    run_id: str,
    attempt_id: str,
    configuration: HostedConfigurationSet,
    cost_measurement_state: str,
    logical_error_code: str = "invalid_structured_output",
    provider_event_status: str = "invalid_output",
    physical_error_code: str = "invalid_structured_output",
    provider_user_content: str = '{"case_id":"case-failed"}',
    include_prompt_snapshot: bool = True,
    corrupt_prompt_transcript: bool = False,
) -> None:
    if cost_measurement_state not in {"measured", "not_observed"}:
        raise ValueError("test provider cost state is invalid")
    role = next(item for item in configuration.roles if item.role == "judge")
    prompt = next(record for record in load_prompt_registry() if record.role == "judge")
    execution_id = f"execution-{cost_measurement_state}-{run_id}"
    invocation_id = _digest(f"invocation:{execution_id}")
    event_id = _digest(f"event:{execution_id}")
    generation_policy_sha256 = DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256
    provider_request_id = (
        f"provider-request-{cost_measurement_state}"
        if cost_measurement_state == "measured"
        else None
    )
    returned_model = role.model_id if cost_measurement_state == "measured" else None
    upstream_provider = "Google Vertex" if cost_measurement_state == "measured" else None
    input_tokens = 30 if cost_measurement_state == "measured" else None
    output_tokens = 5 if cost_measurement_state == "measured" else None
    reasoning_tokens = 5 if cost_measurement_state == "measured" else None
    measured_cost = Decimal("0.01") if cost_measurement_state == "measured" else None
    event_started_at = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1)
    event_finished_at = event_started_at + datetime.timedelta(seconds=1)
    provider_messages = [
        {"role": "system", "content": prompt.content},
        {"role": "user", "content": provider_user_content},
    ]
    transcript_json = json.dumps(
        {"messages": provider_messages},
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, attempt_id, agent_role, "
                "provider, model, execution_mode, configuration_version, input_sha256, trace_id, "
                "configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, detail, started_at) VALUES "
                "(:execution, :org, :run, :attempt, 'judge', 'openrouter', :model, "
                "'hosted_advisory', 1, :input_sha, :trace, :configuration, "
                ":role_configuration, :generation_policy, "
                '\'{"provider_lineage_state":"canonical_physical",'
                '"phase":"response_adjudication"}\'::jsonb, :started_at)'
            ),
            {
                "execution": execution_id,
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "model": role.model_id,
                "input_sha": _digest(f"input:{execution_id}"),
                "trace": _digest(f"trace:{run_id}")[:32],
                "configuration": configuration.configuration_sha256,
                "role_configuration": role.configuration_sha256,
                "generation_policy": generation_policy_sha256,
                "started_at": event_started_at - datetime.timedelta(seconds=1),
            },
        )
        if include_prompt_snapshot:
            connection.execute(
                text(
                    "INSERT INTO agent_prompt_snapshots "
                    "(organization_id, execution_id, campaign_run_id, attempt_id, agent_role, "
                    "system_prompt_version, system_prompt_sha256, system_prompt_content, "
                    "provider_messages, transcript_sha256, redactions) VALUES "
                    "(:org, :execution, :run, :attempt, 'judge', :prompt_version, :prompt_sha, "
                    ":prompt_content, CAST(:messages AS jsonb), :transcript_sha, '[]'::jsonb)"
                ),
                {
                    "org": organization_id,
                    "execution": execution_id,
                    "run": run_id,
                    "attempt": attempt_id,
                    "prompt_version": prompt.version,
                    "prompt_sha": prompt.sha256,
                    "prompt_content": prompt.content,
                    "messages": json.dumps(
                        provider_messages,
                        allow_nan=False,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    "transcript_sha": (
                        "0" * 64 if corrupt_prompt_transcript else _digest(transcript_json)
                    ),
                },
            )
        connection.execute(
            text(
                "INSERT INTO provider_call_invocations "
                "(invocation_id, organization_id, campaign_run_id, campaign_attempt_id, "
                "logical_execution_id, parent_execution_id, agent_role, physical_sequence, "
                "idempotency_key, requested_model, configured_upstream, prompt_version, "
                "prompt_sha256, configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, started_at) VALUES "
                "(:invocation, :org, :run, :attempt, :execution, NULL, 'judge', 1, "
                ":idempotency, :model, :upstream, :prompt_version, :prompt_sha, "
                ":configuration, :role_configuration, :generation_policy, :started_at)"
            ),
            {
                "invocation": invocation_id,
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "execution": execution_id,
                "idempotency": f"provider-call:{invocation_id}",
                "model": role.model_id,
                "upstream": role.upstream_provider,
                "prompt_version": prompt.version,
                "prompt_sha": prompt.sha256,
                "configuration": configuration.configuration_sha256,
                "role_configuration": role.configuration_sha256,
                "generation_policy": generation_policy_sha256,
                "started_at": event_started_at,
            },
        )
        connection.execute(
            text(
                "INSERT INTO provider_call_events "
                "(event_id, invocation_id, organization_id, campaign_run_id, "
                "campaign_attempt_id, logical_execution_id, agent_role, physical_sequence, "
                "status, returned_model, upstream_provider, provider_request_id, "
                "input_tokens, output_tokens, reasoning_tokens, cost_measurement_state, "
                "measured_cost_usd, error_code, finished_at, duration_ms) VALUES "
                "(:event, :invocation, :org, :run, :attempt, :execution, 'judge', 1, "
                ":event_status, :returned_model, :upstream_provider, :provider_request_id, "
                ":input_tokens, :output_tokens, :reasoning_tokens, :cost_state, :cost, "
                ":physical_error_code, :finished_at, 1000)"
            ),
            {
                "event": event_id,
                "invocation": invocation_id,
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "execution": execution_id,
                "event_status": provider_event_status,
                "returned_model": returned_model,
                "upstream_provider": upstream_provider,
                "provider_request_id": provider_request_id,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reasoning_tokens": reasoning_tokens,
                "cost_state": cost_measurement_state,
                "cost": measured_cost,
                "physical_error_code": physical_error_code,
                "finished_at": event_finished_at,
            },
        )
        connection.execute(
            text(
                "UPDATE agent_executions SET status = 'failed', output_sha256 = :output_sha, "
                "returned_model = :returned_model, upstream_provider = :upstream_provider, "
                "provider_request_id = :provider_request_id, input_tokens = :input_tokens, "
                "output_tokens = :output_tokens, reasoning_tokens = :reasoning_tokens, "
                "measured_cost = :cost, cost_measurement_state = :cost_state, "
                "error_code = :logical_error_code, finished_at = :finished_at, "
                "duration_ms = 2000 WHERE organization_id = :org AND execution_id = :execution"
            ),
            {
                "output_sha": _digest(f"output:{execution_id}"),
                "returned_model": returned_model,
                "upstream_provider": upstream_provider,
                "provider_request_id": provider_request_id,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reasoning_tokens": reasoning_tokens,
                "cost": measured_cost,
                "cost_state": cost_measurement_state,
                "logical_error_code": logical_error_code,
                "finished_at": event_finished_at,
                "org": organization_id,
                "execution": execution_id,
            },
        )


def _seed_measured_provider_usage(
    engine: Engine,
    *,
    organization_id: str,
    run_id: str,
    attempt_id: str,
    configuration: HostedConfigurationSet,
    agent_role: str,
    usage_index: int,
    measured_cost: Decimal,
    input_tokens: int,
    output_tokens: int,
    reasoning_tokens: int,
) -> None:
    role = next(item for item in configuration.roles if item.role == agent_role)
    prompt = next(record for record in load_prompt_registry() if record.role == agent_role)
    identity = f"{run_id}:{agent_role}:{usage_index}"
    execution_id = _digest(f"execution:{identity}")
    invocation_id = _digest(f"invocation:{identity}")
    event_id = _digest(f"event:{identity}")
    started_at = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=10)
    finished_at = started_at + datetime.timedelta(seconds=1)
    generation_policy_sha256 = DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256
    provider_request_id = f"measured-usage-{agent_role}-{usage_index}"
    returned_upstream = {
        "anthropic": "Anthropic",
        "together": "Together",
        "google-vertex": "Google Vertex",
        "openai": "OpenAI",
    }[role.upstream_provider]
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, attempt_id, agent_role, "
                "provider, model, execution_mode, configuration_version, input_sha256, trace_id, "
                "configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, detail, started_at) VALUES "
                "(:execution, :org, :run, :attempt, :role, 'openrouter', :model, "
                "'hosted_advisory', 1, :input_sha, :trace, :configuration, "
                ":role_configuration, :generation_policy, "
                '\'{"provider_lineage_state":"canonical_physical"}\'::jsonb, :started_at)'
            ),
            {
                "execution": execution_id,
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "role": agent_role,
                "model": role.model_id,
                "input_sha": _digest(f"input:{identity}"),
                "trace": _digest(f"trace:{identity}")[:32],
                "configuration": configuration.configuration_sha256,
                "role_configuration": role.configuration_sha256,
                "generation_policy": generation_policy_sha256,
                "started_at": started_at - datetime.timedelta(seconds=1),
            },
        )
        connection.execute(
            text(
                "INSERT INTO provider_call_invocations "
                "(invocation_id, organization_id, campaign_run_id, campaign_attempt_id, "
                "logical_execution_id, parent_execution_id, agent_role, physical_sequence, "
                "idempotency_key, requested_model, configured_upstream, prompt_version, "
                "prompt_sha256, configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, started_at) VALUES "
                "(:invocation, :org, :run, :attempt, :execution, NULL, :role, 1, "
                ":idempotency, :model, :upstream, :prompt_version, :prompt_sha, "
                ":configuration, :role_configuration, :generation_policy, :started_at)"
            ),
            {
                "invocation": invocation_id,
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "execution": execution_id,
                "role": agent_role,
                "idempotency": f"provider-call:{invocation_id}",
                "model": role.model_id,
                "upstream": role.upstream_provider,
                "prompt_version": prompt.version,
                "prompt_sha": prompt.sha256,
                "configuration": configuration.configuration_sha256,
                "role_configuration": role.configuration_sha256,
                "generation_policy": generation_policy_sha256,
                "started_at": started_at,
            },
        )
        connection.execute(
            text(
                "INSERT INTO provider_call_events "
                "(event_id, invocation_id, organization_id, campaign_run_id, "
                "campaign_attempt_id, logical_execution_id, agent_role, physical_sequence, "
                "status, returned_model, upstream_provider, provider_request_id, "
                "input_tokens, output_tokens, reasoning_tokens, cost_measurement_state, "
                "measured_cost_usd, finished_at, duration_ms) VALUES "
                "(:event, :invocation, :org, :run, :attempt, :execution, :role, 1, "
                "'succeeded', :model, :returned_upstream, :provider_request_id, :input_tokens, "
                ":output_tokens, :reasoning_tokens, 'measured', :cost, :finished_at, 1000)"
            ),
            {
                "event": event_id,
                "invocation": invocation_id,
                "org": organization_id,
                "run": run_id,
                "attempt": attempt_id,
                "execution": execution_id,
                "role": agent_role,
                "model": role.model_id,
                "returned_upstream": returned_upstream,
                "provider_request_id": provider_request_id,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reasoning_tokens": reasoning_tokens,
                "cost": measured_cost,
                "finished_at": finished_at,
            },
        )
        connection.execute(
            text(
                "UPDATE agent_executions SET status = 'succeeded', "
                "output_sha256 = :output_sha, returned_model = :model, "
                "upstream_provider = :upstream, provider_request_id = :provider_request_id, "
                "input_tokens = :input_tokens, output_tokens = :output_tokens, "
                "reasoning_tokens = :reasoning_tokens, measured_cost = :cost, "
                "cost_measurement_state = 'measured', finished_at = :finished_at, "
                "duration_ms = 2000 WHERE organization_id = :org AND execution_id = :execution"
            ),
            {
                "output_sha": _digest(f"output:{identity}"),
                "model": role.model_id,
                "upstream": returned_upstream,
                "provider_request_id": provider_request_id,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reasoning_tokens": reasoning_tokens,
                "cost": measured_cost,
                "finished_at": finished_at,
                "org": organization_id,
                "execution": execution_id,
            },
        )


def _principal(organization_id: str) -> Principal:
    return Principal(
        user_id="user_CampaignOperationsReader",
        session_id="sess_CampaignOperationsReader",
        organization_id=organization_id,
        organization_role="org:operator",
        organization_permissions=frozenset({"org:console:read"}),
    )


@pytest.fixture(scope="module")
def operations_db(migrated_db: Engine) -> Engine:
    _seed_failed_campaign(
        migrated_db,
        organization_id=_ORGANIZATION_ID,
        launcher_user_id=_LAUNCHER_USER_ID,
    )
    return migrated_db


def test_campaign_operations_projection_reconciles_partial_failed_run(
    operations_db: Engine,
) -> None:
    backend = PostgresApiBackend(operations_db, environment="staging")
    with operations_db.connect() as connection:
        direct_projection = backend._campaign_operations_projection(
            connection,
            organization_id=_ORGANIZATION_ID,
            run_id=_RUN_ID,
        )
    assert direct_projection is not None

    result = backend.read(
        "campaign_operations",
        _principal(_ORGANIZATION_ID),
        identifiers={"campaign_id": _RUN_ID},
    )

    assert result.state == "ready", result
    assert result.data["campaign_id"] == _RUN_ID
    assert result.data["state"] == "failed"
    assert result.data["progress"] == {
        "planned": 3,
        "started": 2,
        "running": 0,
        "completed": 1,
        "failed": 1,
        "skipped": None,
        "remaining": 1,
    }
    assert result.data["executions"] == {
        "logical_attempts": 2,
        "physical_target_requests": 1,
        "provider_calls": 0,
    }
    assert result.data["costs"] == {
        "provider_measured_usd": 0.0,
        "provider_measurement_state": "measured",
        "target_measured_usd": 0.01,
        "target_measurement_state": "measured",
        "total_measured_usd": 0.01,
        "measurement_state": "measured",
        "currency": "USD",
    }
    assert result.data["limits"]["target_budget_remaining_usd"] == 4.99
    assert result.data["limits"]["provider_budget_remaining_usd"] == 3.0
    assert result.data["limits"]["physical_requests_remaining"] == 3
    assert result.data["limits"]["provider_calls_remaining"] == 12
    assert result.data["limits"]["max_attempts_per_run"] == 3
    assert result.data["limits"]["target_retries_per_turn"] == 0
    assert result.data["limits"]["provider_max_retries"] == 1
    assert result.data["limits"]["provider_max_concurrency"] is None
    assert result.data["limits"]["provider_timeout_seconds"] is None
    assert result.data["verdict_distribution"] == {"INDETERMINATE": 1}
    assert result.data["queue"] == {
        "queued_jobs": 0,
        "leased_jobs": 0,
        "dead_lettered_jobs": 0,
        "rate_limit_active": None,
    }
    failure = result.data["terminal_failure"]
    assert failure["stage"] == "response_adjudication"
    assert failure["error_code"] == "invalid_structured_output"
    assert failure["attempt_id"] == _ATTEMPT_FAILED
    assert failure["agent_role"] == "judge"
    assert failure["retryable"] is None
    assert failure["retries_remaining"] is None
    assert "invalid structured output" in failure["operator_summary"]
    assert result.data["as_of"] == result.as_of
    assert result.data["cursor"] == result.cursor

    cross_organization = backend.read(
        "campaign_operations",
        _principal("org_OtherCampaignOperationsTenant"),
        identifiers={"campaign_id": _RUN_ID},
    )
    assert cross_organization.state == "empty"


def test_campaign_operations_route_is_authenticated_and_console_permission_protected(
    operations_db: Engine,
) -> None:
    backend = PostgresApiBackend(operations_db, environment="staging")
    app = create_web_app(
        backend=backend,
        readiness_check=lambda: True,
        security_config=WebSecurityConfig(
            environment="staging",
            allowed_origins=(_ORIGIN,),
            clerk_frontend_api_origin="https://campaign-operations.clerk.accounts.dev",
        ),
    )
    app.dependency_overrides[get_clerk_auth_config] = lambda: ClerkAuthConfig(
        environment="staging",
        publishable_key="public-test-identifier-not-used",
        jwt_key="public-test-verification-key-not-used",
        authorized_parties=(_ORIGIN,),
        required_organization_id=_ORGANIZATION_ID,
    )
    path = f"/api/v1/campaigns/{_RUN_ID}/operations"

    assert TestClient(app).get(path).status_code == 401
    app.dependency_overrides[require_authenticated] = lambda: Principal(
        user_id="user_CampaignOperationsDenied",
        session_id="sess_CampaignOperationsDenied",
        organization_id=_ORGANIZATION_ID,
        organization_role="org:operator",
        organization_permissions=frozenset(),
    )
    assert TestClient(app).get(path).status_code == 403
    app.dependency_overrides[require_authenticated] = lambda: _principal(_ORGANIZATION_ID)
    accepted = TestClient(app).get(path)

    assert accepted.status_code == 200
    assert accepted.json()["state"] == "ready", accepted.text
    assert accepted.json()["data"]["terminal_failure"]["error_code"] == (
        "invalid_structured_output"
    )


@pytest.mark.parametrize(
    (
        "cost_measurement_state",
        "logical_error_code",
        "expected_retryable",
        "expected_retries_remaining",
    ),
    (
        ("not_observed", "invalid_structured_output", False, 0),
        ("measured", "invalid_structured_output", True, 1),
        ("measured", "provider-structured-output-ambiguous", False, 0),
    ),
)
def test_campaign_operations_invalid_output_retryability_requires_settled_usage(
    migrated_db: Engine,
    cost_measurement_state: str,
    logical_error_code: str,
    expected_retryable: bool,
    expected_retries_remaining: int,
) -> None:
    failure_kind = (
        "ambiguous" if logical_error_code == "provider-structured-output-ambiguous" else "schema"
    )
    cost_kind = "unobserved" if cost_measurement_state == "not_observed" else "measured"
    suffix = f"{cost_kind}-{failure_kind}"
    organization_id = f"org_CampaignOperations-{suffix}"
    run_id = f"run-campaign-operations-{suffix}"
    request_id = f"request-campaign-operations-{suffix}"
    attempt_complete = f"attempt-complete-{suffix}"
    attempt_failed = f"attempt-failed-{suffix}"
    configuration = _operations_hosted_configuration()
    _seed_failed_campaign(
        migrated_db,
        organization_id=organization_id,
        launcher_user_id=f"user_CampaignOperations-{suffix}",
        run_id=run_id,
        request_id=request_id,
        attempt_complete=attempt_complete,
        attempt_failed=attempt_failed,
        hosted_configuration=configuration,
    )
    _seed_invalid_output_provider_failure(
        migrated_db,
        organization_id=organization_id,
        run_id=run_id,
        attempt_id=attempt_failed,
        configuration=configuration,
        cost_measurement_state=cost_measurement_state,
        logical_error_code=logical_error_code,
    )

    result = PostgresApiBackend(migrated_db, environment="staging").read(
        "campaign_operations",
        _principal(organization_id),
        identifiers={"campaign_id": run_id},
    )

    assert result.state == "ready", result
    failure = result.data["terminal_failure"]
    assert failure["error_code"] == logical_error_code
    assert failure["retryable"] is expected_retryable
    assert failure["retries_remaining"] == expected_retries_remaining


@pytest.mark.parametrize(
    ("exhausted_role_call_cap", "expected_retryable", "expected_retries_remaining"),
    (
        (False, None, None),
        (True, False, 0),
    ),
)
def test_campaign_operations_transport_retryability_requires_provable_capacity(
    migrated_db: Engine,
    exhausted_role_call_cap: bool,
    expected_retryable: bool | None,
    expected_retries_remaining: int | None,
) -> None:
    suffix = "tx" if exhausted_role_call_cap else "tu"
    organization_id = f"org_CampaignOperations-{suffix}"
    run_id = f"run-campaign-operations-{suffix}"
    attempt_failed = f"attempt-failed-{suffix}"
    configuration = (
        _configuration_with_exhausted_retry_authority("role_call")
        if exhausted_role_call_cap
        else _operations_hosted_configuration()
    )
    _seed_failed_campaign(
        migrated_db,
        organization_id=organization_id,
        launcher_user_id=f"user_CampaignOperations-{suffix}",
        run_id=run_id,
        request_id=f"request-campaign-operations-{suffix}",
        attempt_complete=f"attempt-complete-{suffix}",
        attempt_failed=attempt_failed,
        hosted_configuration=configuration,
    )
    _seed_invalid_output_provider_failure(
        migrated_db,
        organization_id=organization_id,
        run_id=run_id,
        attempt_id=attempt_failed,
        configuration=configuration,
        cost_measurement_state="not_observed",
        logical_error_code="hosted-provider-unavailable",
        provider_event_status="timeout",
        physical_error_code="provider_timeout",
    )

    result = PostgresApiBackend(migrated_db, environment="staging").read(
        "campaign_operations",
        _principal(organization_id),
        identifiers={"campaign_id": run_id},
    )

    assert result.state == "ready", result
    failure = result.data["terminal_failure"]
    assert failure["error_code"] == "hosted-provider-unavailable"
    assert failure["retryable"] is expected_retryable
    assert failure["retries_remaining"] == expected_retries_remaining


@pytest.mark.parametrize(
    "exhausted_authority",
    (
        "role_call",
        "global_call",
        "campaign_call",
        "role_spend",
        "global_spend",
        "campaign_spend",
        "role_input_tokens",
        "effective_prompt_input",
        "global_input_tokens",
        "role_completion_tokens",
        "global_completion_tokens",
    ),
)
def test_campaign_operations_never_advertises_a_retry_the_ledger_would_refuse(
    migrated_db: Engine,
    exhausted_authority: str,
) -> None:
    suffix = {
        "role_call": "rc",
        "global_call": "gc",
        "campaign_call": "cc",
        "role_spend": "rs",
        "global_spend": "gs",
        "campaign_spend": "cs",
        "role_input_tokens": "rt",
        "effective_prompt_input": "ep",
        "global_input_tokens": "gt",
        "role_completion_tokens": "ro",
        "global_completion_tokens": "go",
    }[exhausted_authority]
    organization_id = f"org_CampaignOperations-exhausted-{suffix}"
    run_id = f"run-campaign-operations-exhausted-{suffix}"
    attempt_failed = f"attempt-failed-{suffix}"
    configuration = _configuration_with_exhausted_retry_authority(exhausted_authority)
    _seed_failed_campaign(
        migrated_db,
        organization_id=organization_id,
        launcher_user_id=f"user_CampaignOperations-{suffix}",
        run_id=run_id,
        request_id=f"request-campaign-operations-{suffix}",
        attempt_complete=f"attempt-complete-{suffix}",
        attempt_failed=attempt_failed,
        hosted_configuration=configuration,
        provider_model_call_limit_override=(
            1
            if exhausted_authority == "campaign_call"
            else (12 if exhausted_authority == "global_call" else None)
        ),
        provider_model_spend_limit_usd_override=(
            "0.04"
            if exhausted_authority == "campaign_spend"
            else ("4" if exhausted_authority == "global_spend" else None)
        ),
    )
    _seed_invalid_output_provider_failure(
        migrated_db,
        organization_id=organization_id,
        run_id=run_id,
        attempt_id=attempt_failed,
        configuration=configuration,
        cost_measurement_state="measured",
        provider_user_content=(
            json.dumps({"payload": "x" * 45_000}, separators=(",", ":"))
            if exhausted_authority == "effective_prompt_input"
            else '{"case_id":"case-failed"}'
        ),
    )
    if exhausted_authority == "global_call":
        usage_index = 0
        for agent_role in ("orchestrator", "red_team", "documentation"):
            for _ in range(3):
                _seed_measured_provider_usage(
                    migrated_db,
                    organization_id=organization_id,
                    run_id=run_id,
                    attempt_id=attempt_failed,
                    configuration=configuration,
                    agent_role=agent_role,
                    usage_index=usage_index,
                    measured_cost=Decimal(0),
                    input_tokens=0,
                    output_tokens=0,
                    reasoning_tokens=0,
                )
                usage_index += 1
    elif exhausted_authority == "global_spend":
        _seed_measured_provider_usage(
            migrated_db,
            organization_id=organization_id,
            run_id=run_id,
            attempt_id=attempt_failed,
            configuration=configuration,
            agent_role="orchestrator",
            usage_index=0,
            measured_cost=Decimal("1"),
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )
    elif exhausted_authority == "global_input_tokens":
        _seed_measured_provider_usage(
            migrated_db,
            organization_id=organization_id,
            run_id=run_id,
            attempt_id=attempt_failed,
            configuration=configuration,
            agent_role="orchestrator",
            usage_index=0,
            measured_cost=Decimal(0),
            input_tokens=70_000,
            output_tokens=0,
            reasoning_tokens=0,
        )
    elif exhausted_authority == "global_completion_tokens":
        _seed_measured_provider_usage(
            migrated_db,
            organization_id=organization_id,
            run_id=run_id,
            attempt_id=attempt_failed,
            configuration=configuration,
            agent_role="orchestrator",
            usage_index=0,
            measured_cost=Decimal(0),
            input_tokens=0,
            output_tokens=19_000,
            reasoning_tokens=19_500,
        )
    if exhausted_authority == "effective_prompt_input":
        judge = next(role for role in configuration.roles if role.role == "judge")
        judge_prompt = next(record for record in load_prompt_registry() if record.role == "judge")
        policy_bound = DEFAULT_HOSTED_GENERATION_POLICY.call_bounds["judge"].input_tokens
        large_user_content = json.dumps({"payload": "x" * 45_000}, separators=(",", ":"))
        conservative_bound = (
            len(b"system")
            + len(judge_prompt.content.encode())
            + len(b"user")
            + len(large_user_content.encode())
            + (64 * 2)
            + 4096
        )
        assert 30 + policy_bound <= judge.limits.max_input_tokens
        assert 30 + conservative_bound > judge.limits.max_input_tokens

    result = PostgresApiBackend(migrated_db, environment="staging").read(
        "campaign_operations",
        _principal(organization_id),
        identifiers={"campaign_id": run_id},
    )

    assert result.state == "ready", result
    failure = result.data["terminal_failure"]
    assert failure["error_code"] == "invalid_structured_output"
    assert failure["retryable"] is False
    assert failure["retries_remaining"] == 0
    judge = next(role for role in configuration.roles if role.role == "judge")
    if exhausted_authority == "global_call":
        assert result.data["executions"]["provider_calls"] == 10
        assert result.data["limits"]["provider_calls_remaining"] == 2
        assert judge.limits.max_calls - 1 == 2
    elif exhausted_authority == "global_spend":
        assert result.data["limits"]["provider_budget_remaining_usd"] == 2.99
        assert judge.limits.max_usd - Decimal("0.01") > Decimal("0.04")
    elif exhausted_authority == "global_input_tokens":
        assert judge.limits.max_input_tokens - 30 > 32_768
    elif exhausted_authority == "global_completion_tokens":
        assert judge.limits.max_output_tokens + judge.limits.max_reasoning_tokens - 10 > 512 + 1_024


@pytest.mark.parametrize(
    ("missing_authority", "suffix"),
    (
        ("configuration_set_sha256", "mc"),
        ("generation_policy_sha256", "mp"),
        ("provider_model_call_limit", "ml"),
        ("provider_model_spend_limit_usd", "ms"),
        ("provider_max_retries", "mr"),
        ("prompt_snapshot", "ps"),
        ("prompt_snapshot_hash", "ph"),
    ),
)
def test_campaign_operations_missing_retry_authority_is_unknown(
    migrated_db: Engine,
    missing_authority: str,
    suffix: str,
) -> None:
    organization_id = f"org_CampaignOperations-missing-{suffix}"
    run_id = f"run-campaign-operations-missing-{suffix}"
    attempt_failed = f"attempt-failed-{suffix}"
    configuration = _operations_hosted_configuration()
    _seed_failed_campaign(
        migrated_db,
        organization_id=organization_id,
        launcher_user_id=f"user_CampaignOperations-{suffix}",
        run_id=run_id,
        request_id=f"request-campaign-operations-{suffix}",
        attempt_complete=f"attempt-complete-{suffix}",
        attempt_failed=attempt_failed,
        hosted_configuration=configuration,
        omitted_hosted_authority=(
            None
            if missing_authority in {"prompt_snapshot", "prompt_snapshot_hash"}
            else missing_authority
        ),
    )
    _seed_invalid_output_provider_failure(
        migrated_db,
        organization_id=organization_id,
        run_id=run_id,
        attempt_id=attempt_failed,
        configuration=configuration,
        cost_measurement_state="measured",
        include_prompt_snapshot=missing_authority != "prompt_snapshot",
        corrupt_prompt_transcript=missing_authority == "prompt_snapshot_hash",
    )

    result = PostgresApiBackend(migrated_db, environment="staging").read(
        "campaign_operations",
        _principal(organization_id),
        identifiers={"campaign_id": run_id},
    )

    assert result.state == "ready", result
    failure = result.data["terminal_failure"]
    assert failure["retryable"] is None
    assert failure["retries_remaining"] is None


def test_campaign_operations_incomplete_campaign_usage_makes_retry_authority_unknown(
    migrated_db: Engine,
) -> None:
    organization_id = "org_CampaignOperations-incomplete"
    run_id = "run-campaign-operations-incomplete"
    attempt_failed = "attempt-failed-incomplete"
    configuration = _operations_hosted_configuration()
    _seed_failed_campaign(
        migrated_db,
        organization_id=organization_id,
        launcher_user_id="user_CampaignOperations-incomplete",
        run_id=run_id,
        request_id="request-campaign-operations-incomplete",
        attempt_complete="attempt-complete-incomplete",
        attempt_failed=attempt_failed,
        hosted_configuration=configuration,
    )
    _seed_invalid_output_provider_failure(
        migrated_db,
        organization_id=organization_id,
        run_id=run_id,
        attempt_id=attempt_failed,
        configuration=configuration,
        cost_measurement_state="not_observed",
    )
    _seed_invalid_output_provider_failure(
        migrated_db,
        organization_id=organization_id,
        run_id=run_id,
        attempt_id=attempt_failed,
        configuration=configuration,
        cost_measurement_state="measured",
    )

    result = PostgresApiBackend(migrated_db, environment="staging").read(
        "campaign_operations",
        _principal(organization_id),
        identifiers={"campaign_id": run_id},
    )

    assert result.state == "ready", result
    failure = result.data["terminal_failure"]
    assert failure["error_code"] == "invalid_structured_output"
    assert failure["retryable"] is None
    assert failure["retries_remaining"] is None


def test_campaign_scoped_costs_include_failed_and_partial_target_accounting(
    operations_db: Engine,
) -> None:
    backend = PostgresApiBackend(operations_db, environment="staging")

    measured = backend.read(
        "costs",
        _principal(_ORGANIZATION_ID),
        identifiers={"campaign_id": _RUN_ID},
    )
    assert measured.state == "ready", measured
    campaign_cost = next(row for row in measured.data if row["record_kind"] == "campaign")
    assert campaign_cost["campaign_id"] == _RUN_ID
    assert campaign_cost["request_count"] == 1
    assert campaign_cost["measured_cost"] == 0.01
    assert campaign_cost["cost_measurement_state"] == "measured"
    assert campaign_cost["accounting_status"] == "measured"
    assert campaign_cost["average_cost_per_request"] == 0.01

    with operations_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO outbound_http_requests "
                "(request_id, organization_id, campaign_run_id, attempt_id, trace_id, "
                "operation, provider, method, destination_host, relative_path, "
                "request_payload, status, request_bytes, measured_cost, currency, "
                "langfuse_status) VALUES "
                "('target-request-partial-cost-fixture', :org, :run_id, :attempt_id, "
                ":trace_id, 'target.http', 'openemr', 'POST', 'target.example.test', "
                "'api/copilot/message', '{}'::jsonb, 'in_flight', 2, 0, 'USD', 'disabled')"
            ),
            {
                "org": _ORGANIZATION_ID,
                "run_id": _RUN_ID,
                "attempt_id": _ATTEMPT_FAILED,
                "trace_id": "3" * 32,
            },
        )
    try:
        partial = backend.read(
            "costs",
            _principal(_ORGANIZATION_ID),
            identifiers={"campaign_id": _RUN_ID},
        )
        assert partial.state == "ready", partial
        campaign_cost = next(row for row in partial.data if row["record_kind"] == "campaign")
        assert campaign_cost["request_count"] == 2
        assert campaign_cost["measured_cost"] == 0.01
        assert campaign_cost["cost_measurement_state"] == "partial"
        assert campaign_cost["accounting_status"] == "partial"
        assert campaign_cost["average_cost_per_request"] is None
        assert campaign_cost["budget_utilization"] is None
    finally:
        with operations_db.begin() as connection:
            connection.execute(
                text(
                    "DELETE FROM outbound_http_requests "
                    "WHERE organization_id = :org AND request_id = "
                    "'target-request-partial-cost-fixture'"
                ),
                {"org": _ORGANIZATION_ID},
            )

    cross_organization = backend.read(
        "costs",
        _principal("org_OtherCampaignOperationsTenant"),
        identifiers={"campaign_id": _RUN_ID},
    )
    assert cross_organization.state == "empty"


def test_campaign_operations_does_not_report_in_flight_target_cost_as_zero(
    operations_db: Engine,
) -> None:
    backend = PostgresApiBackend(operations_db, environment="staging")
    with operations_db.connect() as connection:
        transaction = connection.begin()
        try:
            connection.execute(
                text(
                    "INSERT INTO campaign_run_events "
                    "(organization_id, run_id, state, reason_code) "
                    "VALUES (:org, :run_id, 'running', NULL)"
                ),
                {"org": _ORGANIZATION_ID, "run_id": _RUN_ID},
            )
            connection.execute(
                text(
                    "INSERT INTO outbound_http_requests "
                    "(request_id, organization_id, campaign_run_id, attempt_id, trace_id, "
                    "operation, provider, method, destination_host, relative_path, "
                    "request_payload, status, request_bytes, measured_cost, currency, "
                    "langfuse_status) VALUES "
                    "('target-request-in-flight-operations-fixture', :org, :run_id, "
                    ":attempt_id, :trace_id, 'target.http', 'openemr', 'POST', "
                    "'target.example.test', 'api/copilot/message', '{}'::jsonb, "
                    "'in_flight', 2, 0, 'USD', 'disabled')"
                ),
                {
                    "org": _ORGANIZATION_ID,
                    "run_id": _RUN_ID,
                    "attempt_id": _ATTEMPT_FAILED,
                    "trace_id": "2" * 32,
                },
            )
            projection = backend._campaign_operations_projection(
                connection,
                organization_id=_ORGANIZATION_ID,
                run_id=_RUN_ID,
            )
            assert projection is not None
            validate_ready_data("campaign_operations", projection)
            assert projection["costs"] == {
                "provider_measured_usd": 0.0,
                "provider_measurement_state": "measured",
                "target_measured_usd": 0.01,
                "target_measurement_state": "partial",
                "total_measured_usd": 0.01,
                "measurement_state": "partial",
                "currency": "USD",
            }
            assert projection["limits"]["target_budget_remaining_usd"] is None
            assert projection["current_work"]["stage"] == "target_dispatch"
            assert projection["current_work"]["agent_role"] is None
            assert projection["current_work"]["execution_id"] is None
            assert projection["current_work"]["attempt_id"] == _ATTEMPT_FAILED
        finally:
            transaction.rollback()


def test_campaign_operations_read_model_rejects_fabricated_progress() -> None:
    with pytest.raises(ValidationError):
        validate_ready_data(
            "campaign_operations",
            {
                "campaign_id": "run-invalid",
                "state": "running",
                "created_at": "2026-07-26T12:00:00Z",
                "progress": {
                    "planned": 3,
                    "started": 2,
                    "running": 0,
                    "completed": 1,
                    "failed": 0,
                    "skipped": None,
                    "remaining": 0,
                },
                "executions": {
                    "logical_attempts": 2,
                    "physical_target_requests": 0,
                    "provider_calls": 0,
                },
                "current_work": None,
                "costs": {
                    "provider_measured_usd": 0,
                    "provider_measurement_state": "measured",
                    "target_measured_usd": 0,
                    "target_measurement_state": "measured",
                    "total_measured_usd": 0,
                    "measurement_state": "measured",
                    "currency": "USD",
                },
                "limits": {},
                "verdict_distribution": {"INDETERMINATE": 1},
                "queue": {
                    "queued_jobs": 0,
                    "leased_jobs": 0,
                    "dead_lettered_jobs": 0,
                    "rate_limit_active": None,
                },
                "terminal_failure": None,
                "as_of": "2026-07-26T12:00:01Z",
                "cursor": 0,
            },
        )
