"""Durable, run-bound hosted-agent telemetry and Langfuse projection contracts."""

from __future__ import annotations

import datetime
import hashlib
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.hosted_runtime import HostedCallBounds, HostedExecutionLineage
from agentforge.agents.prompts import load_prompt_registry
from agentforge.agents.red_team.hosted_generation import (
    RedTeamRoleIdentity,
    TracedHostedRedTeamProvider,
    TracedRedTeamGenerationError,
)
from agentforge.api.postgres import PostgresApiBackend
from agentforge.auth.permissions import (
    CAMPAIGN_AUTHORIZE,
    CAMPAIGN_LAUNCH,
    CONFIG_MANAGE,
    TARGETS_MANAGE,
)
from agentforge.auth.principal import Principal
from agentforge.control_plane.errors import (
    AuthorizationDeniedError,
    InvalidControlPlaneInput,
    RecordConflictError,
)
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.providers.lineage import ProviderTerminalEventV1
from agentforge.providers.openrouter import (
    HostedBudgetExceeded,
    HostedProviderError,
    OpenRouterTransport,
)
from agentforge.runner import DispatchUnavailable, DurableCampaignRunner
from agentforge.secrets import Secret
from agentforge.storage.queue import LogicalQueue, PostgresJobQueue
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    HostedRunBinding,
    OwaspMapping,
    RiskLevel,
    SafetyCaps,
    SurfaceKind,
    TargetDefinition,
    TargetEnvironment,
    TargetLifecycle,
)
from agentforge.telemetry import OutboundHttpTelemetry
from agentforge.telemetry.outbound import _LangfuseBridge

_ORGANIZATION_ID = "org_HostedLineage"


def _prompt(role: str):
    return next(record for record in load_prompt_registry() if record.role == role)


_SESSION_GENERATION = "generation-20260724"
_GENERATION_POLICY = "d" * 64
_PROMPTS = {record.role: record for record in load_prompt_registry()}
_MODELS = {
    "orchestrator": "anthropic/claude-opus-4.8",
    "red_team": "qwen/qwen3.5-397b-a17b",
    "judge": "google/gemini-2.5-pro",
    "documentation": "openai/gpt-5.4",
}
_UPSTREAM = {
    "orchestrator": "anthropic",
    "red_team": "together",
    "judge": "google-vertex",
    "documentation": "openai",
}
_SELECTED_PROVIDER = {
    "orchestrator": "Anthropic",
    "red_team": "Unknown until generator endpoint is coordinated",
    "judge": "Google",
    "documentation": "OpenAI",
}


class _LangfuseProjection:
    def __init__(self) -> None:
        self.started: list[dict[str, object]] = []
        self.finished: list[dict[str, object]] = []

    @staticmethod
    def configured() -> bool:
        return True

    def start_agent(self, **values: object) -> tuple[object, object, str, str]:
        self.started.append(dict(values))
        return object(), object(), "provider_pending", "0123456789abcdef"

    def finish_agent(self, _state: object, **values: object) -> None:
        self.finished.append(dict(values))

    def flush(self) -> None:
        return None

    def shutdown(self) -> None:
        return None


class _Observation:
    def __init__(self, observation_id: str) -> None:
        self.id = observation_id
        self.started: list[dict[str, object]] = []
        self.updated: list[dict[str, object]] = []
        self.ended = False

    def start_observation(self, **values: object) -> _Observation:
        self.started.append(dict(values))
        return _Observation("fedcba9876543210")

    def update(self, **values: object) -> _Observation:
        self.updated.append(dict(values))
        return self

    def end(self) -> None:
        self.ended = True


class _LangfuseClient:
    def __init__(self) -> None:
        self.agent = _Observation("0123456789abcdef")
        self.starts: list[dict[str, object]] = []

    def start_observation(self, **values: object) -> _Observation:
        self.starts.append(dict(values))
        return self.agent


def _principal(user_id: str, *permissions: str) -> Principal:
    return Principal(
        user_id=user_id,
        session_id=f"sess_{user_id.removeprefix('user_')}",
        organization_id=_ORGANIZATION_ID,
        organization_role="org:operator",
        organization_permissions=frozenset(permissions),
    )


def _configuration() -> HostedConfigurationSet:
    roles = []
    for role in ("orchestrator", "red_team", "judge", "documentation"):
        roles.append(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=_MODELS[role],
                upstream_provider=_UPSTREAM[role],
                completion_token_parameter="max_completion_tokens",
                credential_reference=(
                    f"secretref://staging/providers/openrouter/{role}/{_SESSION_GENERATION}"
                ),
                prompt_sha256=_PROMPTS[role].sha256,
                policy_sha256=hashlib.sha256(f"{role}:policy:v1".encode()).hexdigest(),
                prices=TokenPrices(
                    input_usd_per_million_tokens=Decimal("1"),
                    output_usd_per_million_tokens=Decimal("2"),
                    reasoning_usd_per_million_tokens=Decimal("3"),
                ),
                limits=HostedLimits(
                    max_calls=8,
                    max_input_tokens=80_000,
                    max_output_tokens=16_000,
                    max_reasoning_tokens=32_768,
                    max_usd=Decimal("0.5"),
                    max_retries=1,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
        )
    return HostedConfigurationSet(
        roles=tuple(roles),
        global_limits=HostedLimits(
            max_calls=32,
            max_input_tokens=320_000,
            max_output_tokens=64_000,
            max_reasoning_tokens=131_072,
            max_usd=Decimal("2"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE agent_executions, agent_configuration_versions, "
                "hosted_configuration_sets, audit_events, command_idempotency, "
                "campaign_attempts, campaign_run_events, campaign_runs, "
                "campaign_authorization_decisions, campaign_authorization_requests, "
                "surface_state_events, attack_surface_definitions, surface_identities, "
                "target_lifecycle_events, target_definitions, target_identities, jobs "
                "RESTART IDENTITY CASCADE"
            )
        )


def _authorized_run(engine: Engine) -> tuple[ControlPlaneStore, str, HostedConfigurationSet]:
    _clean(engine)
    store = ControlPlaneStore(engine, environment="staging")
    launcher = _principal(
        "user_HostedLauncher",
        TARGETS_MANAGE,
        CONFIG_MANAGE,
        CAMPAIGN_LAUNCH,
    )
    approver = _principal("user_HostedApprover", CAMPAIGN_AUTHORIZE)
    target = TargetDefinition(
        target_id="hosted-lineage-target",
        name="Synthetic hosted lineage fixture",
        version="1.0.0",
        adapter_kind="openemr",
        environment=TargetEnvironment.STAGING,
        base_url="https://target.example.test/openemr",
        allowlisted_hosts=("target.example.test",),
        auth_mode=AuthMode.BEARER,
        credential_ref="secretref://staging/targets/hosted-lineage",
        synthetic_data_only=True,
        synthetic_data_attestation_ref="attestation://synthetic/hosted-lineage",
        canary_refs=("oracle://canary/hosted-lineage",),
        oracle_refs=("oracle://judge/hosted-lineage",),
        safety_caps=SafetyCaps(
            budget_usd=2.0,
            max_attempts_per_run=3,
            target_requests_per_second=0.5,
            run_timeout_seconds=60.0,
        ),
    )
    surface = AttackSurfaceDefinition(
        surface_id="hosted-lineage-chat",
        version="1.0.0",
        target_id=target.target_id,
        target_version=target.version,
        kind=SurfaceKind.CHAT,
        protocol="https",
        method="POST",
        relative_path="api/copilot/message",
        trust_boundary="external-target",
        authentication_required=True,
        risk=RiskLevel.HIGH,
        owasp_mappings=(
            OwaspMapping(
                framework="OWASP LLM",
                version="2025",
                identifier="LLM01",
                name="Prompt Injection",
            ),
        ),
        oracle_refs=("oracle://canary/hosted-lineage",),
        enabled=True,
    )
    store.register_target(
        principal=launcher,
        target=target,
        idempotency_key="hosted-lineage-target-register",
    )
    store.register_surface(
        principal=launcher,
        surface=surface,
        idempotency_key="hosted-lineage-surface-register",
    )
    for lifecycle in (TargetLifecycle.VALIDATING, TargetLifecycle.READY):
        store.transition_target(
            principal=launcher,
            target_id=target.target_id,
            version=target.version,
            lifecycle=lifecycle,
            idempotency_key=f"hosted-lineage-target-{lifecycle.value}",
        )

    configuration = _configuration()
    store.stage_hosted_configuration_set(
        principal=launcher,
        configuration=configuration,
        release_sha256="e" * 64,
        rationale="Bind the exact synthetic four-role configuration.",
        idempotency_key="hosted-lineage-config-stage",
    )
    binding = HostedRunBinding(
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY,
        session_generation=_SESSION_GENERATION,
        provider_model_call_limit=configuration.global_limits.max_calls,
        provider_model_spend_limit_usd=format(
            configuration.global_limits.max_usd,
            "f",
        ),
        provider_max_retries=configuration.global_limits.max_retries,
        provider_max_concurrency=configuration.global_limits.max_concurrency,
        provider_timeout_seconds=30.0,
    )
    scope = store.build_scope(
        principal=launcher,
        target_id=target.target_id,
        target_version=target.version,
        surface_id=surface.surface_id,
        surface_version=surface.version,
        corpus_hash="a" * 64,
        caps=SafetyCaps(
            budget_usd=2.0,
            max_attempts_per_run=3,
            target_requests_per_second=0.5,
            run_timeout_seconds=60.0,
        ),
        run_nonce="hosted-lineage-run-nonce",
        hosted_run=binding,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="hosted-lineage-request",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="hosted-lineage-approve",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="hosted-lineage-launch",
    )
    return store, run.run_id, configuration


def _start(
    store: ControlPlaneStore,
    run_id: str,
    configuration: HostedConfigurationSet,
    *,
    role: str,
    judge_calibration_id: str | None = None,
    judge_calibration_state: str | None = None,
) -> str:
    role_configuration = next(item for item in configuration.roles if item.role == role)
    return store.start_hosted_agent_execution(
        run_id=run_id,
        agent_role=role,  # type: ignore[arg-type]
        input_payload={
            "case_ref": "synthetic-case-1",
            "evidence_summary_sha256": "b" * 64,
        },
        provider=role_configuration.provider,
        model=role_configuration.model_id,
        upstream_provider=role_configuration.upstream_provider,
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role_configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY,
        judge_calibration_id=judge_calibration_id,
        judge_calibration_state=judge_calibration_state,
        detail={"input_kind": "sanitized_hash_summary"},
    )


def _record_physical_event(
    store: ControlPlaneStore,
    *,
    execution_id: str,
    role: str,
    sequence: int = 1,
    status: str = "succeeded",
    returned_model: str | None = None,
    upstream_provider: str | None = None,
    provider_request_id: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    reasoning_tokens: int | None = None,
    cost_measurement_state: str = "measured",
    measured_cost_usd: Decimal | None = Decimal("0"),
    error_code: str | None = None,
) -> tuple[object, ProviderTerminalEventV1]:
    prompt = _prompt(role)  # type: ignore[arg-type]
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, sequence)
    if status == "succeeded":
        returned_model = returned_model or logical.requested_model
        upstream_provider = upstream_provider or _SELECTED_PROVIDER[role]
        provider_request_id = provider_request_id or f"provider-request-{role}-{sequence}"
        input_tokens = 0 if input_tokens is None else input_tokens
        output_tokens = 0 if output_tokens is None else output_tokens
        reasoning_tokens = 0 if reasoning_tokens is None else reasoning_tokens
    event = ProviderTerminalEventV1(
        invocation_id=invocation.invocation_id,
        physical_sequence=sequence,
        status=status,
        returned_model=returned_model,
        upstream_provider=upstream_provider,
        provider_request_id=provider_request_id,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        reasoning_tokens=reasoning_tokens,
        cost_measurement_state=cost_measurement_state,
        measured_cost_usd=measured_cost_usd,
        error_code=error_code,
        finished_at=datetime.datetime.now(datetime.UTC),
    )
    return invocation, store.finish_physical_attempt(invocation, event)


class _StoreBackedRedTeamLifecycle:
    def __init__(
        self,
        *,
        store: ControlPlaneStore,
        run_id: str,
    ) -> None:
        self._store = store
        self._run_id = run_id
        self.execution_id: str | None = None

    def start(self, **values: object) -> str:
        execution_id = self._store.start_hosted_agent_execution(
            run_id=self._run_id,
            agent_role="red_team",
            input_payload=values["input_payload"],  # type: ignore[arg-type]
            provider=str(values["provider"]),
            model=str(values["model"]),
            upstream_provider=str(values["upstream_provider"]),
            configuration_set_sha256=str(values["configuration_sha256"]),
            role_configuration_sha256=str(values["role_configuration_sha256"]),
            generation_policy_sha256=str(values["generation_policy_sha256"]),
            parent_execution_id=values["parent_execution_id"],  # type: ignore[arg-type]
            detail={"source": "canonical-q-lineage-test"},
        )
        self.execution_id = execution_id
        return execution_id

    def provider_context(
        self,
        *,
        execution_id: str,
        prompt_version: str,
        prompt_sha256: str,
    ):
        return self._store.provider_logical_context(
            execution_id=execution_id,
            prompt_version=prompt_version,
            prompt_sha256=prompt_sha256,
        )

    def finish(self, **values: object) -> None:
        lineage = values["lineage"]
        if lineage is not None and not isinstance(lineage, HostedExecutionLineage):
            raise TypeError("red_team test lineage is invalid")
        self._store.finish_hosted_agent_execution(
            execution_id=str(values["execution_id"]),
            status=str(values["status"]),
            output_payload=values["output_payload"],  # type: ignore[arg-type]
            returned_model=(lineage.returned_model if lineage is not None else None),
            upstream_provider=(lineage.upstream_provider if lineage is not None else None),
            provider_request_id=(lineage.provider_request_id if lineage is not None else None),
            input_tokens=(lineage.input_tokens if lineage is not None else None),
            output_tokens=(lineage.output_tokens if lineage is not None else None),
            reasoning_tokens=(lineage.reasoning_tokens if lineage is not None else None),
            measured_cost_usd=(lineage.measured_cost_usd if lineage is not None else None),
            configuration_set_sha256=(
                lineage.configuration_sha256 if lineage is not None else None
            ),
            role_configuration_sha256=(
                lineage.role_configuration_sha256 if lineage is not None else None
            ),
            generation_policy_sha256=(
                lineage.generation_policy_sha256 if lineage is not None else None
            ),
            physical_attempts=(lineage.physical_attempts if lineage is not None else None),
            error_code=values["error_code"],  # type: ignore[arg-type]
        )


class _InvalidRedTeamContextLifecycle(_StoreBackedRedTeamLifecycle):
    def provider_context(
        self,
        *,
        execution_id: str,
        prompt_version: str,
        prompt_sha256: str,
    ):
        return None


def _canonical_q_provider(
    *,
    store: ControlPlaneStore,
    run_id: str,
    configuration: HostedConfigurationSet,
    lifecycle: _StoreBackedRedTeamLifecycle,
    handler,
) -> TracedHostedRedTeamProvider:
    role = next(item for item in configuration.roles if item.role == "red_team")
    prompt = _prompt("red_team")
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda _reference: Secret("synthetic-provider-credential"),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        lineage_recorder=store,
        sleeper=lambda _seconds: None,
        monotonic=lambda: 0.0,
    )
    return TracedHostedRedTeamProvider(
        transport=transport,
        lifecycle=lifecycle,
        role_identity=RedTeamRoleIdentity(
            provider=role.provider,
            model=role.model_id,
            upstream_provider=role.upstream_provider,
            prompt_version=prompt.version,
            prompt_sha256=prompt.sha256,
            role_configuration_sha256=role.configuration_sha256,
        ),
        configuration_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY,
        call_bounds=HostedCallBounds(
            # This fixture exercises successful physical lineage. Keep its explicit authority
            # above the conservative encoded-message bound rather than relying on transport
            # widening.
            input_tokens=10_000,
            output_tokens=1_024,
            reasoning_tokens=512,
            timeout_seconds=30,
        ),
    )


def test_canonical_q_generator_records_physical_lineage_before_returning_variants(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    lifecycle = _StoreBackedRedTeamLifecycle(store=store, run_id=run_id)
    seen: list[httpx.Request] = []
    qwen_model = _MODELS["red_team"]

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={
                "id": "openrouter-q-lineage-success",
                "model": qwen_model,
                "openrouter_metadata": {
                    "requested": qwen_model,
                    "endpoints": {
                        "available": [
                            {
                                "provider": "Together",
                                "model": qwen_model,
                                "selected": True,
                            }
                        ]
                    },
                },
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"variants":["synthetic continuation one",'
                                '"synthetic continuation two"]}'
                            )
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 120,
                    "completion_tokens": 30,
                    "completion_tokens_details": {"reasoning_tokens": 5},
                    "cost": 0.000195,
                },
            },
        )

    provider = _canonical_q_provider(
        store=store,
        run_id=run_id,
        configuration=configuration,
        lifecycle=lifecycle,
        handler=respond,
    )
    variants = provider.generate(
        {
            "case_ref": "synthetic-case-1",
            "input_sequence": ["synthetic seed"],
        },
        count=2,
        category="prompt_injection",
    )

    assert variants == [
        {"input_sequence": ["synthetic seed", "synthetic continuation one"]},
        {"input_sequence": ["synthetic seed", "synthetic continuation two"]},
    ]
    assert len(seen) == 1
    with migrated_db.connect() as connection:
        execution = (
            connection.execute(
                text(
                    "SELECT status, returned_model, upstream_provider, physical_attempts, "
                    "provider_event_ids FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": lifecycle.execution_id},
            )
            .mappings()
            .one()
        )
        invocation_count = connection.execute(
            text(
                "SELECT count(*) FROM provider_call_invocations "
                "WHERE logical_execution_id = :execution"
            ),
            {"execution": lifecycle.execution_id},
        ).scalar_one()
        event = (
            connection.execute(
                text(
                    "SELECT status, returned_model, upstream_provider, provider_request_id "
                    "FROM provider_call_events WHERE logical_execution_id = :execution"
                ),
                {"execution": lifecycle.execution_id},
            )
            .mappings()
            .one()
        )
    assert execution["status"] == "succeeded"
    assert execution["returned_model"] == qwen_model
    assert execution["upstream_provider"] == "Together"
    assert execution["physical_attempts"] == 1
    assert len(execution["provider_event_ids"]) == 1
    assert invocation_count == 1
    assert dict(event) == {
        "status": "succeeded",
        "returned_model": qwen_model,
        "upstream_provider": "Together",
        "provider_request_id": "openrouter-q-lineage-success",
    }


def test_canonical_q_generator_fails_before_send_when_context_resolution_is_invalid(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    lifecycle = _InvalidRedTeamContextLifecycle(store=store, run_id=run_id)
    seen: list[httpx.Request] = []
    provider = _canonical_q_provider(
        store=store,
        run_id=run_id,
        configuration=configuration,
        lifecycle=lifecycle,
        handler=lambda request: (
            seen.append(request) or httpx.Response(500, json={"error": "must not send"})
        ),
    )

    with pytest.raises(TracedRedTeamGenerationError, match="context is invalid"):
        provider.generate(
            {
                "case_ref": "synthetic-case-1",
                "input_sequence": ["synthetic seed"],
            },
            count=1,
            category="prompt_injection",
        )

    assert seen == []
    with migrated_db.connect() as connection:
        execution = (
            connection.execute(
                text(
                    "SELECT status, error_code, physical_attempts, provider_event_ids "
                    "FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": lifecycle.execution_id},
            )
            .mappings()
            .one()
        )
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM provider_call_invocations "
                    "WHERE logical_execution_id = :execution"
                ),
                {"execution": lifecycle.execution_id},
            ).scalar_one()
            == 0
        )
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM provider_call_events "
                    "WHERE logical_execution_id = :execution"
                ),
                {"execution": lifecycle.execution_id},
            ).scalar_one()
            == 0
        )
    assert dict(execution) == {
        "status": "failed",
        "error_code": "red-team-generation-failed",
        "physical_attempts": None,
        "provider_event_ids": [],
    }


def test_canonical_q_generator_records_each_failed_physical_retry(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    lifecycle = _StoreBackedRedTeamLifecycle(store=store, run_id=run_id)
    seen: list[httpx.Request] = []
    provider = _canonical_q_provider(
        store=store,
        run_id=run_id,
        configuration=configuration,
        lifecycle=lifecycle,
        handler=lambda request: (
            seen.append(request) or httpx.Response(503, headers={"Retry-After": "0"})
        ),
    )

    with pytest.raises(HostedProviderError, match="authorized retry"):
        provider.generate(
            {
                "case_ref": "synthetic-case-1",
                "input_sequence": ["synthetic seed"],
            },
            count=1,
            category="prompt_injection",
        )

    assert len(seen) == 2
    with migrated_db.connect() as connection:
        execution = (
            connection.execute(
                text(
                    "SELECT status, error_code, cost_measurement_state, physical_attempts, "
                    "provider_event_ids FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": lifecycle.execution_id},
            )
            .mappings()
            .one()
        )
        events = (
            connection.execute(
                text(
                    "SELECT physical_sequence, status, cost_measurement_state "
                    "FROM provider_call_events WHERE logical_execution_id = :execution "
                    "ORDER BY physical_sequence"
                ),
                {"execution": lifecycle.execution_id},
            )
            .mappings()
            .all()
        )
    assert execution["status"] == "failed"
    assert execution["error_code"] == "hosted-provider-unavailable"
    assert execution["cost_measurement_state"] == "not_observed"
    assert execution["physical_attempts"] == 2
    assert len(execution["provider_event_ids"]) == 2
    assert [dict(event) for event in events] == [
        {
            "physical_sequence": 1,
            "status": "retryable_failure",
            "cost_measurement_state": "not_observed",
        },
        {
            "physical_sequence": 2,
            "status": "retryable_failure",
            "cost_measurement_state": "not_observed",
        },
    ]


def test_hosted_execution_persists_exact_lineage_and_projects_it_to_langfuse(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    resolved = store.load_hosted_role_for_execution(
        run_id=run_id,
        agent_role="orchestrator",
    )
    role = resolved.role_configuration
    assert resolved.configuration.configuration_sha256 == configuration.configuration_sha256
    assert role.model_id == _MODELS["orchestrator"]

    execution_id = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    projection = _LangfuseProjection()
    telemetry.langfuse = projection  # type: ignore[assignment]
    telemetry.begin_agent(
        execution_id=execution_id,
        input_payload={"must_not_be_projected": "raw-input"},
    )
    _, event = _record_physical_event(
        store,
        execution_id=execution_id,
        role="orchestrator",
        provider_request_id="openrouter-request-synthetic-1",
        input_tokens=123,
        output_tokens=45,
        reasoning_tokens=7,
        measured_cost_usd=Decimal("0.000001234567"),
    )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"selected_case_ref": "synthetic-case-1"},
    )
    telemetry.finish_agent(
        execution_id=execution_id,
        output_payload={"selected_case_ref": "synthetic-case-1"},
    )

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text("SELECT * FROM agent_executions WHERE execution_id = :execution_id"),
                {"execution_id": execution_id},
            )
            .mappings()
            .one()
        )
    assert row["model"] == role.model_id
    assert row["returned_model"] == role.model_id
    assert row["upstream_provider"] == _SELECTED_PROVIDER["orchestrator"]
    assert row["provider_request_id"] == "openrouter-request-synthetic-1"
    assert row["reasoning_tokens"] == 7
    assert Decimal(str(row["measured_cost"])) == Decimal("0.000001234567")
    assert row["configuration_set_sha256"] == configuration.configuration_sha256
    assert row["role_configuration_sha256"] == role.configuration_sha256
    assert row["generation_policy_sha256"] == _GENERATION_POLICY
    assert row["physical_attempts"] == 1
    assert row["provider_event_ids"] == [event.event_id]
    assert row["cost_measurement_state"] == "measured"
    assert row["trace_id"] == projection.started[0]["trace_id"]
    assert "must_not_be_projected" not in str(projection.started[0]["input_payload"])
    assert projection.finished[0]["returned_model"] == role.model_id
    assert projection.finished[0]["reasoning_tokens"] == 7
    assert projection.finished[0]["cost_measurement_state"] == "measured"
    assert projection.finished[0]["provider_event_ids"] == [event.event_id]
    finished_metadata = projection.finished[0]["metadata"]
    assert isinstance(finished_metadata, dict)
    assert finished_metadata["agent.provider_request_id"] == ("openrouter-request-synthetic-1")


def test_hosted_start_rejects_identity_drift_and_unbound_runs(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    role = configuration.roles[0]
    with pytest.raises(AuthorizationDeniedError, match="approved run binding"):
        store.start_hosted_agent_execution(
            run_id=run_id,
            agent_role=role.role,
            input_payload={"case_ref": "synthetic-case-1"},
            provider=role.provider,
            model="anthropic/different-model",
            upstream_provider=role.upstream_provider,
            configuration_set_sha256=configuration.configuration_sha256,
            role_configuration_sha256=role.configuration_sha256,
            generation_policy_sha256=_GENERATION_POLICY,
        )

    launcher = _principal("user_HostedLauncher", CAMPAIGN_LAUNCH)
    deterministic_scope = store.build_scope(
        principal=launcher,
        target_id="hosted-lineage-target",
        target_version="1.0.0",
        surface_id="hosted-lineage-chat",
        surface_version="1.0.0",
        corpus_hash="a" * 64,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=1,
            target_requests_per_second=0.5,
            run_timeout_seconds=30.0,
        ),
        run_nonce="deterministic-lineage-run",
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=deterministic_scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="deterministic-lineage-request",
    )
    store.decide_campaign_authorization(
        principal=_principal("user_HostedApprover", CAMPAIGN_AUTHORIZE),
        request_id=request.request_id,
        decision="approved",
        idempotency_key="deterministic-lineage-approve",
    )
    deterministic_run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="deterministic-lineage-launch",
    )
    with pytest.raises(AuthorizationDeniedError):
        store.load_hosted_role_for_execution(
            run_id=deterministic_run.run_id,
            agent_role="orchestrator",
        )


def test_judge_reconciliation_keeps_failed_calibration_oracle_decisive(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    calibration_id = f"JC-{'c' * 64}"
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="judge",
        judge_calibration_id=calibration_id,
        judge_calibration_state="failed",
    )
    _record_physical_event(
        store,
        execution_id=execution_id,
        role="judge",
        provider_request_id="openrouter-request-judge-1",
        input_tokens=100,
        output_tokens=20,
        reasoning_tokens=5,
        measured_cost_usd=Decimal("0.01"),
    )
    values = {
        "execution_id": execution_id,
        "status": "succeeded",
        "output_payload": {"state": "NO_EXPLOIT_OBSERVED"},
        "oracle_agreement": False,
    }
    with pytest.raises(AuthorizationDeniedError, match="enabled Judge calibration"):
        store.finish_hosted_agent_execution(
            **values,
            decision_authority="model",
        )
    store.finish_hosted_agent_execution(
        **values,
        decision_authority="oracle",
    )

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT judge_calibration_id, judge_calibration_state, "
                    "oracle_agreement, decision_authority FROM agent_executions "
                    "WHERE execution_id = :execution_id"
                ),
                {"execution_id": execution_id},
            )
            .mappings()
            .one()
        )
    assert dict(row) == {
        "judge_calibration_id": calibration_id,
        "judge_calibration_state": "failed",
        "oracle_agreement": False,
        "decision_authority": "oracle",
    }


def test_non_judge_cannot_claim_calibration_or_reconciliation(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    with pytest.raises(InvalidControlPlaneInput, match="non-Judge"):
        _start(
            store,
            run_id,
            configuration,
            role="documentation",
            judge_calibration_id=f"JC-{'a' * 64}",
            judge_calibration_state="passed",
        )


def test_failed_hosted_call_closes_without_fabricated_provider_accounting(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    with pytest.raises(InvalidControlPlaneInput, match="hosted terminalization"):
        store.finish_agent_execution(
            execution_id=execution_id,
            status="failed",
            output_payload={"status": "failed"},
            error_code="hosted-agent-failed",
        )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        error_code="hosted-agent-failed",
    )

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT status, returned_model, provider_request_id, "
                    "input_tokens, output_tokens, reasoning_tokens, "
                    "physical_attempts, measured_cost, cost_measurement_state, error_code "
                    "FROM agent_executions WHERE execution_id = :execution_id"
                ),
                {"execution_id": execution_id},
            )
            .mappings()
            .one()
        )
    assert row["status"] == "failed"
    assert all(
        row[field] is None
        for field in (
            "returned_model",
            "provider_request_id",
            "input_tokens",
            "output_tokens",
            "reasoning_tokens",
            "physical_attempts",
        )
    )
    assert row["measured_cost"] is None
    assert row["cost_measurement_state"] == "not_observed"
    assert row["error_code"] == "hosted-agent-failed"


def test_unobserved_hosted_cost_stays_null_through_langfuse_projection(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    projection = _LangfuseProjection()
    telemetry.langfuse = projection  # type: ignore[assignment]
    telemetry.begin_agent(
        execution_id=execution_id,
        input_payload={"sanitized": True},
    )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        error_code="hosted-agent-failed",
    )
    telemetry.finish_agent(
        execution_id=execution_id,
        output_payload={"status": "failed"},
        error_code="hosted-agent-failed",
    )

    finished = projection.finished[0]
    assert finished["measured_cost"] is None
    assert finished["cost_measurement_state"] == "not_observed"
    assert finished["provider_event_ids"] == []
    metadata = finished["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["cost.usd"] is None
    assert metadata["cost.measurement_state"] == "not_observed"
    assert metadata["agent.provider_event_ids"] == []


def test_database_rejects_partial_hosted_provider_measurements(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )

    with pytest.raises(IntegrityError), migrated_db.begin() as connection:
        connection.execute(
            text("UPDATE agent_executions SET input_tokens = 1 WHERE execution_id = :execution_id"),
            {"execution_id": execution_id},
        )


def test_failed_provider_attempts_survive_restart_and_still_consume_the_role_cap(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    for sequence in (1, 2):
        _record_physical_event(
            store,
            execution_id=execution_id,
            role="documentation",
            sequence=sequence,
            status="retryable_failure",
            cost_measurement_state="not_observed",
            measured_cost_usd=None,
            error_code="provider_retryable",
        )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        error_code="hosted-provider-unavailable",
    )

    runner = object.__new__(DurableCampaignRunner)
    runner.engine = migrated_db
    ledger = runner._hosted_usage_ledger(
        organization_id=_ORGANIZATION_ID,
        run_id=run_id,
        configuration=configuration,
        generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
    )

    assert ledger.snapshot.physical_calls == 2
    assert ledger.snapshot.measured_usd == 0
    assert ledger.snapshot.unresolved_exposure_usd > 0
    for _ in range(6):
        reservation = ledger.reserve(
            "documentation",
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )
        ledger.settle(
            reservation,
            measured_cost=Decimal(0),
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )
    with pytest.raises(
        HostedBudgetExceeded,
        match="role physical model-call cap is exhausted",
    ):
        ledger.reserve(
            "documentation",
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT status, physical_attempts, input_tokens, output_tokens, "
                    "reasoning_tokens, measured_cost, cost_measurement_state "
                    "FROM agent_executions "
                    "WHERE execution_id = :execution_id"
                ),
                {"execution_id": execution_id},
            )
            .mappings()
            .one()
        )
    assert dict(row) == {
        "status": "failed",
        "physical_attempts": 2,
        "input_tokens": None,
        "output_tokens": None,
        "reasoning_tokens": None,
        "measured_cost": None,
        "cost_measurement_state": "not_observed",
    }


def test_running_hosted_row_recovers_maximum_attempt_exposure_after_crash(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )

    restarted = object.__new__(DurableCampaignRunner)
    restarted.engine = migrated_db
    ledger = restarted._hosted_usage_ledger(
        organization_id=_ORGANIZATION_ID,
        run_id=run_id,
        configuration=configuration,
        generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
    )

    # One in-flight logical call could have consumed both its initial attempt
    # and its one authorized retry before the worker died.
    assert ledger.snapshot.physical_calls == 2
    assert ledger.snapshot.measured_usd == 0
    assert ledger.snapshot.unresolved_exposure_usd > 0
    for _ in range(6):
        reservation = ledger.reserve(
            "documentation",
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )
        ledger.settle(
            reservation,
            measured_cost=Decimal(0),
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )
    with pytest.raises(HostedBudgetExceeded, match="role physical model-call cap"):
        ledger.reserve(
            "documentation",
            input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
        )


def test_charged_invalid_output_persists_exact_usage_across_restart(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    role = next(item for item in configuration.roles if item.role == "documentation")
    _record_physical_event(
        store,
        execution_id=execution_id,
        role="documentation",
        status="invalid_output",
        returned_model=role.model_id,
        upstream_provider=_SELECTED_PROVIDER["documentation"],
        provider_request_id="openrouter-request-charged-invalid-output",
        input_tokens=321,
        output_tokens=40,
        reasoning_tokens=9,
        cost_measurement_state="measured",
        measured_cost_usd=Decimal("0.125"),
        error_code="invalid_structured_output",
    )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        error_code="hosted-provider-unavailable",
    )

    runner = object.__new__(DurableCampaignRunner)
    runner.engine = migrated_db
    ledger = runner._hosted_usage_ledger(
        organization_id=_ORGANIZATION_ID,
        run_id=run_id,
        configuration=configuration,
        generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
    )

    assert ledger.snapshot.physical_calls == 1
    assert ledger.snapshot.measured_usd == Decimal("0.125")
    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT status, returned_model, upstream_provider, provider_request_id, "
                    "input_tokens, output_tokens, reasoning_tokens, physical_attempts, "
                    "measured_cost FROM agent_executions WHERE execution_id = :execution_id"
                ),
                {"execution_id": execution_id},
            )
            .mappings()
            .one()
        )
    assert dict(row) == {
        "status": "failed",
        "returned_model": role.model_id,
        "upstream_provider": _SELECTED_PROVIDER["documentation"],
        "provider_request_id": "openrouter-request-charged-invalid-output",
        "input_tokens": 321,
        "output_tokens": 40,
        "reasoning_tokens": 9,
        "physical_attempts": 1,
        "measured_cost": Decimal("0.125"),
    }


def test_physical_retry_ledger_is_authoritative_but_does_not_terminalize_role_work(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    prompt = _prompt("orchestrator")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    assert logical.campaign_attempt_id is None

    first = store.begin_physical_attempt(logical, 1)
    first_event = ProviderTerminalEventV1(
        invocation_id=first.invocation_id,
        physical_sequence=1,
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
        finished_at=datetime.datetime.now(datetime.UTC),
    )
    store.finish_physical_attempt(first, first_event)

    second = store.begin_physical_attempt(logical, 2)
    running_activity = PostgresApiBackend(
        migrated_db,
        environment="staging",
    ).read(
        "agent_activity",
        _principal("user_HostedViewer", "org:console:read"),
    )
    projected_running = next(
        row for row in running_activity.data if row["execution_id"] == execution_id
    )
    assert projected_running["status"] == "running"
    assert projected_running["physical_attempts"] == 2
    assert projected_running["provider_event_ids"] == [first_event.event_id]

    second_event = ProviderTerminalEventV1(
        invocation_id=second.invocation_id,
        physical_sequence=2,
        status="succeeded",
        returned_model=logical.requested_model,
        upstream_provider="Anthropic",
        provider_request_id="provider-request-after-retry",
        input_tokens=30,
        output_tokens=5,
        reasoning_tokens=5,
        cost_measurement_state="measured",
        measured_cost_usd=Decimal("0.000065"),
        error_code=None,
        finished_at=datetime.datetime.now(datetime.UTC),
    )
    store.finish_physical_attempt(second, second_event)

    with migrated_db.connect() as connection:
        running = (
            connection.execute(
                text(
                    "SELECT status, cost_measurement_state, measured_cost, "
                    "physical_attempts, provider_event_ids, decision_authority "
                    "FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .one()
        )
    assert running["status"] == "running"
    assert running["decision_authority"] is None
    assert running["cost_measurement_state"] == "partial"
    assert running["measured_cost"] == Decimal("0.000065000000")
    assert running["physical_attempts"] == 2
    assert running["provider_event_ids"] == [
        first_event.event_id,
        second_event.event_id,
    ]

    role = next(item for item in configuration.roles if item.role == "orchestrator")
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"next_category": "prompt_injection"},
        returned_model=role.model_id,
        upstream_provider="Anthropic",
        provider_request_id="provider-request-after-retry",
        input_tokens=30,
        output_tokens=5,
        reasoning_tokens=5,
        measured_cost_usd="0.000065",
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY,
        physical_attempts=2,
    )

    with migrated_db.connect() as connection:
        terminal = (
            connection.execute(
                text(
                    "SELECT status, cost_measurement_state, measured_cost "
                    "FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .one()
        )
    assert terminal["status"] == "succeeded"
    assert terminal["cost_measurement_state"] == "partial"
    assert terminal["measured_cost"] == Decimal("0.000065000000")


def test_cost_projection_includes_running_reserved_calls_in_incomplete_budgets(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    completed_execution = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    _, completed_event = _record_physical_event(
        store,
        execution_id=completed_execution,
        role="orchestrator",
        input_tokens=100,
        output_tokens=20,
        reasoning_tokens=5,
        measured_cost_usd=Decimal("0.1"),
    )
    store.finish_hosted_agent_execution(
        execution_id=completed_execution,
        status="succeeded",
        output_payload={"selected_case_ref": "synthetic-case-1"},
    )

    running_execution = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    prompt = _prompt("orchestrator")
    running_logical = store.provider_logical_context(
        execution_id=running_execution,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    store.begin_physical_attempt(running_logical, 1)

    backend = PostgresApiBackend(migrated_db, environment="staging")
    viewer = _principal("user_HostedBudgetViewer", "org:console:read")
    costs = backend.read("costs", viewer)
    role_cost = next(
        row
        for row in costs.data
        if row["record_kind"] == "agent" and row["agent_role"] == "orchestrator"
    )

    assert role_cost["accounting_status"] == "partial"
    assert role_cost["cost_measurement_state"] == "partial"
    assert role_cost["measured_cost"] == 0.1
    assert role_cost["average_cost_per_request"] is None
    assert role_cost["physical_call_count"] == 2
    assert role_cost["provider_event_ids"] == [completed_event.event_id]
    budget = role_cost["provider_budget"]
    assert budget["role_cost_measurement_state"] == "partial"
    assert budget["role_physical_calls"] == 2
    assert budget["role_usd_remaining"] is None
    assert budget["role_usd_remaining_upper_bound"] == pytest.approx(0.4)
    assert budget["global_cost_measurement_state"] == "partial"
    assert budget["global_physical_calls"] == 2
    assert budget["global_usd_remaining"] is None
    assert budget["global_usd_remaining_upper_bound"] == pytest.approx(1.9)


def test_physical_judge_success_cannot_bypass_reconciliation(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="judge",
        judge_calibration_id=f"JC-{'a' * 64}",
        judge_calibration_state="enabled",
    )
    prompt = _prompt("judge")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    store.finish_physical_attempt(
        invocation,
        ProviderTerminalEventV1(
            invocation_id=invocation.invocation_id,
            physical_sequence=1,
            status="succeeded",
            returned_model=logical.requested_model,
            upstream_provider="Google",
            provider_request_id="provider-request-judge",
            input_tokens=20,
            output_tokens=6,
            reasoning_tokens=4,
            cost_measurement_state="measured",
            measured_cost_usd=Decimal("0.001"),
            error_code=None,
            finished_at=datetime.datetime.now(datetime.UTC),
        ),
    )
    role = next(item for item in configuration.roles if item.role == "judge")

    with pytest.raises(
        InvalidControlPlaneInput,
        match="explicit decision authority",
    ):
        store.finish_hosted_agent_execution(
            execution_id=execution_id,
            status="succeeded",
            output_payload={"state": "NO_EXPLOIT_OBSERVED"},
            returned_model=role.model_id,
            upstream_provider="Google",
            provider_request_id="provider-request-judge",
            input_tokens=20,
            output_tokens=6,
            reasoning_tokens=4,
            measured_cost_usd="0.001",
            configuration_set_sha256=configuration.configuration_sha256,
            role_configuration_sha256=role.configuration_sha256,
            generation_policy_sha256=_GENERATION_POLICY,
            physical_attempts=1,
        )

    with migrated_db.connect() as connection:
        status = connection.execute(
            text("SELECT status FROM agent_executions WHERE execution_id = :execution"),
            {"execution": execution_id},
        ).scalar_one()
    assert status == "running"


def test_logical_terminalization_requires_closed_provider_events(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    prompt = _prompt("documentation")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    store.begin_physical_attempt(logical, 1)

    with pytest.raises(RecordConflictError, match="unfinished physical invocation"):
        store.finish_hosted_agent_execution(
            execution_id=execution_id,
            status="failed",
            output_payload={"status": "failed"},
            error_code="hosted-provider-unavailable",
        )


def test_eventless_hosted_completion_cannot_claim_provider_facts(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    successful_execution = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    with pytest.raises(RecordConflictError, match="durable provider event"):
        store.finish_hosted_agent_execution(
            execution_id=successful_execution,
            status="succeeded",
            output_payload={"next_category": "prompt_injection"},
        )

    failed_execution = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    with pytest.raises(AuthorizationDeniedError, match="cannot claim provider lineage"):
        store.finish_hosted_agent_execution(
            execution_id=failed_execution,
            status="failed",
            output_payload={"status": "failed"},
            physical_attempts=1,
            error_code="hosted-provider-unavailable",
        )


def test_failed_logical_attempt_count_must_equal_durable_events(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    _record_physical_event(
        store,
        execution_id=execution_id,
        role="documentation",
        status="terminal_failure",
        cost_measurement_state="not_observed",
        measured_cost_usd=None,
        error_code="provider_terminal",
    )
    with pytest.raises(AuthorizationDeniedError, match="attempt count differs"):
        store.finish_hosted_agent_execution(
            execution_id=execution_id,
            status="failed",
            output_payload={"status": "failed"},
            physical_attempts=2,
            error_code="hosted-provider-unavailable",
        )

    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        error_code="hosted-provider-unavailable",
    )


def test_runner_recovers_open_provider_reservation_without_resending(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    prompt = _prompt("documentation")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    runner = object.__new__(DurableCampaignRunner)
    runner.store = store

    assert runner.recover_interrupted_provider_calls(limit=8, stale_after_seconds=0) == 1
    assert runner.recover_interrupted_provider_calls(limit=8, stale_after_seconds=0) == 0
    with pytest.raises(RecordConflictError, match="physical provider context"):
        store.begin_physical_attempt(logical, 2)

    with migrated_db.connect() as connection:
        logical_row = (
            connection.execute(
                text(
                    "SELECT status, error_code, physical_attempts, cost_measurement_state, "
                    "provider_event_ids FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .one()
        )
        physical_rows = (
            connection.execute(
                text(
                    "SELECT invocation_id, status, error_code FROM provider_call_events "
                    "WHERE logical_execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .all()
        )
    assert logical_row["status"] == "failed"
    assert logical_row["error_code"] == "provider_outcome_unknown"
    assert logical_row["physical_attempts"] == 1
    assert logical_row["cost_measurement_state"] == "not_observed"
    assert len(logical_row["provider_event_ids"]) == 1
    assert [dict(row) for row in physical_rows] == [
        {
            "invocation_id": invocation.invocation_id,
            "status": "outcome_unknown",
            "error_code": "provider_outcome_unknown",
        }
    ]


def test_runner_recovers_stale_pre_provider_crash_without_fabricating_facts(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE agent_executions SET "
                "started_at = clock_timestamp() - interval '10 minutes', "
                "langfuse_status = 'queued' WHERE execution_id = :execution"
            ),
            {"execution": execution_id},
        )
    runner = object.__new__(DurableCampaignRunner)
    runner.store = store

    assert (
        runner.recover_interrupted_provider_calls(
            limit=8,
            stale_after_seconds=60,
        )
        == 1
    )
    assert (
        runner.recover_interrupted_provider_calls(
            limit=8,
            stale_after_seconds=60,
        )
        == 0
    )

    with migrated_db.connect() as connection:
        logical = (
            connection.execute(
                text(
                    "SELECT status, error_code, returned_model, upstream_provider, "
                    "provider_request_id, physical_attempts, measured_cost, "
                    "cost_measurement_state, provider_event_ids, langfuse_status "
                    "FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .one()
        )
        invocation_count = connection.execute(
            text(
                "SELECT count(*) FROM provider_call_invocations "
                "WHERE logical_execution_id = :execution"
            ),
            {"execution": execution_id},
        ).scalar_one()
        event_count = connection.execute(
            text(
                "SELECT count(*) FROM provider_call_events WHERE logical_execution_id = :execution"
            ),
            {"execution": execution_id},
        ).scalar_one()
        job_status = connection.execute(
            text(
                "SELECT status FROM jobs WHERE campaign_run_id = :run_id "
                "AND queue = 'agent_work'::job_queue"
            ),
            {"run_id": run_id},
        ).scalar_one()
        campaign_state = connection.execute(
            text(
                "SELECT state FROM campaign_run_events WHERE run_id = :run_id "
                "ORDER BY id DESC LIMIT 1"
            ),
            {"run_id": run_id},
        ).scalar_one()
    assert dict(logical) == {
        "status": "failed",
        "error_code": "provider_invocation_not_started",
        "returned_model": None,
        "upstream_provider": None,
        "provider_request_id": None,
        "physical_attempts": None,
        "measured_cost": None,
        "cost_measurement_state": "not_observed",
        "provider_event_ids": [],
        "langfuse_status": "error",
    }
    assert invocation_count == event_count == 0
    assert job_status == "dead_letter"
    assert campaign_state == "aborted"
    queue = PostgresJobQueue(migrated_db, supported_payload_versions={})
    assert queue.reap_expired().requeued_job_ids == ()
    assert queue.claim(LogicalQueue.AGENT_WORK, worker_id="runner-no-replay") is None


def test_pre_provider_recovery_preserves_recent_and_live_leased_work(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    runner = object.__new__(DurableCampaignRunner)
    runner.store = store

    assert (
        runner.recover_interrupted_provider_calls(
            limit=8,
            stale_after_seconds=600,
        )
        == 0
    )
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE agent_executions SET "
                "started_at = clock_timestamp() - interval '20 minutes' "
                "WHERE execution_id = :execution"
            ),
            {"execution": execution_id},
        )
        connection.execute(
            text(
                "UPDATE jobs SET status = 'leased'::job_status, attempts = attempts + 1, "
                "worker_id = 'runner-live-owner', lease_token = 'lease-pre-provider', "
                "leased_at = clock_timestamp(), last_heartbeat_at = clock_timestamp(), "
                "lease_expires_at = clock_timestamp() + interval '10 minutes' "
                "WHERE campaign_run_id = :run_id"
            ),
            {"run_id": run_id},
        )

    assert (
        runner.recover_interrupted_provider_calls(
            limit=8,
            stale_after_seconds=600,
        )
        == 0
    )
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM agent_executions WHERE execution_id = :execution"),
                {"execution": execution_id},
            ).scalar_one()
            == "running"
        )


def test_pre_provider_recovery_wins_before_late_reservation(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    prompt = _prompt("documentation")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE agent_executions SET "
                "started_at = clock_timestamp() - interval '10 minutes' "
                "WHERE execution_id = :execution"
            ),
            {"execution": execution_id},
        )

    assert store.recover_interrupted_hosted_executions(
        limit=8,
        stale_after_seconds=60,
    ) == ((execution_id, "provider_invocation_not_started"),)
    with pytest.raises(RecordConflictError, match="physical provider context"):
        store.begin_physical_attempt(logical, 1)


def test_recent_provider_reservation_wins_before_stale_recovery(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE agent_executions SET "
                "started_at = clock_timestamp() - interval '10 minutes' "
                "WHERE execution_id = :execution"
            ),
            {"execution": execution_id},
        )
    prompt = _prompt("documentation")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    store.begin_physical_attempt(logical, 1)

    assert (
        store.recover_interrupted_hosted_executions(
            limit=8,
            stale_after_seconds=60,
        )
        == ()
    )
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text("SELECT status FROM agent_executions WHERE execution_id = :execution"),
                {"execution": execution_id},
            ).scalar_one()
            == "running"
        )


def test_reap_and_reclaim_cannot_replay_unresolved_hosted_execution(
    migrated_db: Engine,
    tmp_path,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)

    class NoIoTelemetry:
        def flush(self) -> None:
            return None

        def release_campaign(self, _run_id: str) -> None:
            return None

    first_runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        manifest_root=tmp_path,
        telemetry=NoIoTelemetry(),  # type: ignore[arg-type]
    )
    original_job = first_runner.queue.claim(
        LogicalQueue.AGENT_WORK,
        worker_id="runner-original",
    )
    assert original_job is not None
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    prompt = _prompt("documentation")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE jobs SET leased_at = clock_timestamp() - interval '2 minutes', "
                "last_heartbeat_at = clock_timestamp() - interval '2 minutes', "
                "lease_expires_at = clock_timestamp() - interval '1 minute' "
                "WHERE job_id = :job_id"
            ),
            {"job_id": original_job.job_id},
        )

    reaped = first_runner.queue.reap_expired()
    assert reaped.requeued_job_ids == (original_job.job_id,)
    replacement_runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        manifest_root=tmp_path,
        telemetry=NoIoTelemetry(),  # type: ignore[arg-type]
    )
    replacement_job = replacement_runner.queue.claim(
        LogicalQueue.AGENT_WORK,
        worker_id="runner-replacement",
    )
    assert replacement_job is not None
    assert (
        store.recover_interrupted_hosted_executions(
            limit=8,
            stale_after_seconds=60,
        )
        == ()
    )
    replacement_runner.queue.claim = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: replacement_job
    )

    with pytest.raises(DispatchUnavailable, match="preflight_blocked"):
        replacement_runner.run_once(worker_id="runner-replacement")

    with migrated_db.connect() as connection:
        physical = (
            connection.execute(
                text(
                    "SELECT "
                    "(SELECT count(*) FROM provider_call_invocations "
                    "WHERE logical_execution_id = :execution) AS invocations, "
                    "(SELECT count(*) FROM provider_call_events "
                    "WHERE logical_execution_id = :execution) AS events, "
                    "(SELECT count(*) FROM outbound_http_requests "
                    "WHERE campaign_run_id = :run_id) AS target_requests"
                ),
                {
                    "execution": execution_id,
                    "run_id": run_id,
                },
            )
            .mappings()
            .one()
        )
        job_status = connection.execute(
            text("SELECT status FROM jobs WHERE job_id = :job_id"),
            {"job_id": original_job.job_id},
        ).scalar_one()
        campaign_state = connection.execute(
            text(
                "SELECT state FROM campaign_run_events WHERE run_id = :run_id "
                "ORDER BY id DESC LIMIT 1"
            ),
            {"run_id": run_id},
        ).scalar_one()
    assert dict(physical) == {
        "invocations": 1,
        "events": 0,
        "target_requests": 0,
    }
    assert invocation.logical_execution_id == execution_id
    assert job_status == "dead_letter"
    assert campaign_state == "aborted"
    assert replacement_runner.queue.reap_expired().requeued_job_ids == ()
    assert (
        first_runner.queue.claim(
            LogicalQueue.AGENT_WORK,
            worker_id="runner-third",
        )
        is None
    )


def test_live_campaign_job_lease_blocks_cross_runner_provider_recovery(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    prompt = _prompt("documentation")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    with migrated_db.begin() as connection:
        assert (
            connection.execute(
                text(
                    "UPDATE jobs SET status = 'leased'::job_status, attempts = attempts + 1, "
                    "worker_id = 'runner-live-owner', lease_token = 'lease-test-owner', "
                    "leased_at = clock_timestamp(), last_heartbeat_at = clock_timestamp(), "
                    "lease_expires_at = clock_timestamp() + interval '10 minutes' "
                    "WHERE campaign_run_id = :run_id RETURNING job_id"
                ),
                {"run_id": run_id},
            ).scalar_one()
            is not None
        )
    runner = object.__new__(DurableCampaignRunner)
    runner.store = store

    assert runner.recover_interrupted_provider_calls(limit=8, stale_after_seconds=0) == 0
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM provider_call_events WHERE invocation_id = :invocation"),
                {"invocation": invocation.invocation_id},
            ).scalar_one()
            == 0
        )
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE jobs SET status = 'queued'::job_status, worker_id = NULL, "
                "lease_token = NULL, leased_at = NULL, last_heartbeat_at = NULL, "
                "lease_expires_at = NULL WHERE campaign_run_id = :run_id"
            ),
            {"run_id": run_id},
        )
    assert runner.recover_interrupted_provider_calls(limit=8, stale_after_seconds=0) == 1


def test_runner_recovers_terminal_provider_event_to_failed_logical_lifecycle(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    invocation, event = _record_physical_event(
        store,
        execution_id=execution_id,
        role="documentation",
        measured_cost_usd=Decimal("0.000000000123"),
    )
    assert len(event.event_id) == 64
    runner = object.__new__(DurableCampaignRunner)
    runner.store = store

    assert runner.recover_interrupted_provider_calls(limit=8, stale_after_seconds=0) == 1
    assert runner.recover_interrupted_provider_calls(limit=8, stale_after_seconds=0) == 0
    with migrated_db.connect() as connection:
        logical = (
            connection.execute(
                text(
                    "SELECT status, error_code, returned_model, upstream_provider, "
                    "provider_request_id, measured_cost, cost_measurement_state, "
                    "provider_event_ids FROM agent_executions WHERE execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .one()
        )
        physical = (
            connection.execute(
                text(
                    "SELECT event_id, invocation_id, status FROM provider_call_events "
                    "WHERE logical_execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .all()
        )
    assert logical["status"] == "failed"
    assert logical["error_code"] == "provider_lifecycle_interrupted"
    assert logical["returned_model"] == _MODELS["documentation"]
    assert logical["upstream_provider"] == _SELECTED_PROVIDER["documentation"]
    assert logical["provider_request_id"] == "provider-request-documentation-1"
    assert Decimal(str(logical["measured_cost"])) == Decimal("0.000000000123")
    assert logical["cost_measurement_state"] == "measured"
    assert logical["provider_event_ids"] == [event.event_id]
    assert [dict(row) for row in physical] == [
        {
            "event_id": event.event_id,
            "invocation_id": invocation.invocation_id,
            "status": "succeeded",
        }
    ]


def test_runner_provider_recovery_limit_bounds_each_pass(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_ids = [
        _start(
            store,
            run_id,
            configuration,
            role="documentation",
        )
        for _ in range(2)
    ]
    prompt = _prompt("documentation")
    for execution_id in execution_ids:
        logical = store.provider_logical_context(
            execution_id=execution_id,
            prompt_version=prompt.version,
            prompt_sha256=prompt.sha256,
        )
        store.begin_physical_attempt(logical, 1)
    runner = object.__new__(DurableCampaignRunner)
    runner.store = store

    assert runner.recover_interrupted_provider_calls(limit=1, stale_after_seconds=0) == 1
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM agent_executions "
                    "WHERE execution_id IN (:first_execution, :second_execution) "
                    "AND status = 'failed'"
                ),
                {
                    "first_execution": execution_ids[0],
                    "second_execution": execution_ids[1],
                },
            ).scalar_one()
            == 1
        )
    assert runner.recover_interrupted_provider_calls(limit=1, stale_after_seconds=0) == 1
    assert runner.recover_interrupted_provider_calls(limit=1, stale_after_seconds=0) == 0


def test_concurrent_crash_recovery_records_exactly_one_terminal_fact(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    prompt = _prompt("documentation")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)

    def recover() -> tuple[tuple[str, str], ...]:
        return ControlPlaneStore(
            migrated_db,
            environment="staging",
        ).recover_interrupted_hosted_executions(
            limit=8,
            stale_after_seconds=0,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        recovered = list(pool.map(lambda _: recover(), range(2)))

    assert sorted(len(batch) for batch in recovered) == [0, 1]
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text(
                    "SELECT count(*) FROM provider_call_events "
                    "WHERE organization_id = :org AND invocation_id = :invocation"
                ),
                {"org": _ORGANIZATION_ID, "invocation": invocation.invocation_id},
            ).scalar_one()
            == 1
        )
        recovered_row = (
            connection.execute(
                text(
                    "SELECT status, error_code FROM agent_executions "
                    "WHERE execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .one()
        )
        event_count = connection.execute(
            text(
                "SELECT count(*) FROM provider_call_events "
                "WHERE organization_id = :org AND invocation_id = :invocation"
            ),
            {"org": _ORGANIZATION_ID, "invocation": invocation.invocation_id},
        ).scalar_one()
        audit_count = connection.execute(
            text(
                "SELECT count(*) FROM audit_events WHERE aggregate_type = 'agent_execution' "
                "AND aggregate_id = :execution AND event_type = 'agent.failed'"
            ),
            {"execution": execution_id},
        ).scalar_one()
    assert dict(recovered_row) == {
        "status": "failed",
        "error_code": "provider_outcome_unknown",
    }
    assert event_count == 1
    assert audit_count == 1


def test_provider_attempt_sequences_are_contiguous_in_app_and_database(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    prompt = _prompt("orchestrator")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    with pytest.raises(RecordConflictError, match="contiguous"):
        store.begin_physical_attempt(logical, 2)

    def raw_insert(connection, *, sequence: int) -> None:  # type: ignore[no-untyped-def]
        invocation_id = hashlib.sha256(f"raw-sequence:{sequence}".encode()).hexdigest()
        connection.execute(
            text(
                "INSERT INTO provider_call_invocations "
                "(invocation_id, organization_id, campaign_run_id, "
                "campaign_attempt_id, logical_execution_id, parent_execution_id, "
                "agent_role, physical_sequence, idempotency_key, requested_model, "
                "configured_upstream, prompt_version, prompt_sha256, "
                "configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, started_at) VALUES "
                "(:invocation, :org, :run, :attempt, :execution, :parent, :role, "
                ":sequence, :idempotency, :model, :upstream, :prompt_version, "
                ":prompt_hash, :configuration_hash, :role_hash, :policy_hash, "
                "clock_timestamp())"
            ),
            {
                "invocation": invocation_id,
                "org": logical.organization_id,
                "run": logical.campaign_run_id,
                "attempt": logical.campaign_attempt_id,
                "execution": logical.logical_execution_id,
                "parent": logical.parent_execution_id,
                "role": logical.agent_role,
                "sequence": sequence,
                "idempotency": f"provider-call:{invocation_id}",
                "model": logical.requested_model,
                "upstream": logical.configured_upstream,
                "prompt_version": logical.prompt_version,
                "prompt_hash": logical.prompt_sha256,
                "configuration_hash": logical.configuration_set_sha256,
                "role_hash": logical.role_configuration_sha256,
                "policy_hash": logical.generation_policy_sha256,
            },
        )

    with (
        pytest.raises(IntegrityError, match="sequence is not contiguous"),
        migrated_db.begin() as connection,
    ):
        raw_insert(connection, sequence=2)
    with migrated_db.begin() as connection:
        raw_insert(connection, sequence=1)
    with (
        pytest.raises(IntegrityError, match="sequence is not contiguous"),
        migrated_db.begin() as connection,
    ):
        raw_insert(connection, sequence=3)


def test_attempt_identity_cannot_change_after_provider_reservation(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="red_team",
    )
    prompt = _prompt("red_team")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    store.begin_physical_attempt(logical, 1)
    attempt = store.ensure_campaign_attempt(
        run_id=run_id,
        ordinal=0,
        case_id="case-after-provider-reservation",
    )

    with pytest.raises(RecordConflictError, match="after provider invocation"):
        store.bind_agent_execution_attempt(
            execution_id=execution_id,
            run_id=run_id,
            attempt_id=attempt.attempt_id,
        )
    with (
        pytest.raises(DBAPIError, match="attempt binding follows provider invocation"),
        migrated_db.begin() as connection,
    ):
        connection.execute(
            text(
                "UPDATE agent_executions SET attempt_id = :attempt WHERE execution_id = :execution"
            ),
            {
                "attempt": attempt.attempt_id,
                "execution": execution_id,
            },
        )


@pytest.mark.parametrize(
    ("field", "replacement", "error"),
    [
        ("campaign_run_id", "run-reattributed", "logical identity mismatch"),
        ("campaign_attempt_id", "attempt-reattributed", "logical identity mismatch"),
        ("parent_execution_id", "__self__", "logical identity mismatch"),
        ("agent_role", "documentation", "logical identity mismatch"),
        ("requested_model", _MODELS["documentation"], "logical identity mismatch"),
        ("configuration_set_sha256", "e" * 64, "logical identity mismatch"),
        ("role_configuration_sha256", "e" * 64, "logical identity mismatch"),
        ("generation_policy_sha256", "e" * 64, "logical identity mismatch"),
        ("configured_upstream", "openai", "hosted role authority"),
        ("prompt_sha256", "e" * 64, "hosted role authority"),
    ],
)
def test_database_rejects_direct_provider_invocation_reattribution(
    migrated_db: Engine,
    field: str,
    replacement: str,
    error: str,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    prompt = _prompt("orchestrator")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    raw_invocation = hashlib.sha256(f"raw:{field}".encode()).hexdigest()
    values: dict[str, object] = {
        "invocation": raw_invocation,
        "org": logical.organization_id,
        "run": logical.campaign_run_id,
        "attempt": logical.campaign_attempt_id,
        "execution": logical.logical_execution_id,
        "parent": logical.parent_execution_id,
        "role": logical.agent_role,
        "sequence": 1,
        "idempotency": f"provider-call:{raw_invocation}",
        "model": logical.requested_model,
        "upstream": logical.configured_upstream,
        "prompt_version": logical.prompt_version,
        "prompt_hash": logical.prompt_sha256,
        "configuration_hash": logical.configuration_set_sha256,
        "role_hash": logical.role_configuration_sha256,
        "policy_hash": logical.generation_policy_sha256,
        "started": datetime.datetime.now(datetime.UTC),
    }
    parameter = {
        "campaign_run_id": "run",
        "campaign_attempt_id": "attempt",
        "parent_execution_id": "parent",
        "agent_role": "role",
        "requested_model": "model",
        "configured_upstream": "upstream",
        "prompt_sha256": "prompt_hash",
        "configuration_set_sha256": "configuration_hash",
        "role_configuration_sha256": "role_hash",
        "generation_policy_sha256": "policy_hash",
    }[field]
    values[parameter] = execution_id if replacement == "__self__" else replacement

    with (
        pytest.raises(IntegrityError, match=error),
        migrated_db.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO provider_call_invocations "
                "(invocation_id, organization_id, campaign_run_id, "
                "campaign_attempt_id, logical_execution_id, parent_execution_id, "
                "agent_role, physical_sequence, idempotency_key, requested_model, "
                "configured_upstream, prompt_version, prompt_sha256, "
                "configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, started_at) VALUES "
                "(:invocation, :org, :run, :attempt, :execution, :parent, :role, "
                ":sequence, :idempotency, :model, :upstream, :prompt_version, "
                ":prompt_hash, :configuration_hash, :role_hash, :policy_hash, :started)"
            ),
            values,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("returned_model", "openai/gpt-5.4"),
        ("upstream_provider", "OpenAI"),
        ("finished_at", "before"),
        ("duration_ms", Decimal("999")),
    ),
)
def test_database_rejects_false_success_and_timing_facts(
    migrated_db: Engine,
    field: str,
    replacement: object,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    prompt = _prompt("orchestrator")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    finished_at = invocation.started_at + datetime.timedelta(seconds=1)
    values: dict[str, object] = {
        "event": hashlib.sha256(f"raw-event:{field}".encode()).hexdigest(),
        "invocation": invocation.invocation_id,
        "org": invocation.organization_id,
        "run": invocation.campaign_run_id,
        "attempt": invocation.campaign_attempt_id,
        "execution": invocation.logical_execution_id,
        "role": invocation.agent_role,
        "sequence": invocation.physical_sequence,
        "model": invocation.requested_model,
        "upstream": "Anthropic",
        "request": "raw-provider-request",
        "finished": finished_at,
        "duration": Decimal("1000"),
    }
    parameter = {
        "returned_model": "model",
        "upstream_provider": "upstream",
        "finished_at": "finished",
        "duration_ms": "duration",
    }[field]
    values[parameter] = (
        invocation.started_at - datetime.timedelta(seconds=1)
        if replacement == "before"
        else replacement
    )

    with (
        pytest.raises(IntegrityError, match="provider event attempt identity mismatch"),
        migrated_db.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO provider_call_events "
                "(event_id, invocation_id, organization_id, campaign_run_id, "
                "campaign_attempt_id, logical_execution_id, agent_role, physical_sequence, "
                "status, returned_model, upstream_provider, provider_request_id, "
                "input_tokens, output_tokens, reasoning_tokens, cost_measurement_state, "
                "measured_cost_usd, error_code, finished_at, duration_ms) VALUES "
                "(:event, :invocation, :org, :run, :attempt, :execution, :role, :sequence, "
                "'succeeded', :model, :upstream, :request, 10, 2, 1, 'measured', "
                "0.000001, NULL, :finished, :duration)"
            ),
            values,
        )


def test_provider_lineage_tables_are_selectively_granted_and_append_only(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="orchestrator",
    )
    invocation, event = _record_physical_event(
        store,
        execution_id=execution_id,
        role="orchestrator",
    )

    with migrated_db.connect() as connection:
        for table in ("provider_call_invocations", "provider_call_events"):
            privileges = (
                connection.execute(
                    text(
                        "SELECT "
                        "has_table_privilege('headshot_web', :table, 'SELECT') AS web_select, "
                        "has_table_privilege('headshot_web', :table, 'INSERT') AS web_insert, "
                        "has_table_privilege('headshot_runner', :table, 'SELECT') runner_select, "
                        "has_table_privilege('headshot_runner', :table, 'INSERT') runner_insert, "
                        "has_table_privilege('headshot_runner', :table, 'UPDATE') runner_update, "
                        "has_table_privilege('headshot_runner', :table, 'DELETE') runner_delete, "
                        "has_table_privilege('headshot_runner', :table, 'TRUNCATE') "
                        "AS runner_truncate"
                    ),
                    {"table": table},
                )
                .mappings()
                .one()
            )
            assert dict(privileges) == {
                "web_select": False,
                "web_insert": False,
                "runner_select": True,
                "runner_insert": True,
                "runner_update": False,
                "runner_delete": False,
                "runner_truncate": False,
            }

    for statement, values in (
        (
            "UPDATE provider_call_invocations SET started_at = started_at "
            "WHERE invocation_id = :identity",
            {"identity": invocation.invocation_id},
        ),
        (
            "DELETE FROM provider_call_events WHERE event_id = :identity",
            {"identity": event.event_id},
        ),
    ):
        with (
            pytest.raises(DBAPIError, match="append-only"),
            migrated_db.begin() as connection,
        ):
            connection.execute(text(statement), values)


def test_provider_terminal_returned_model_matches_storage_envelope() -> None:
    now = datetime.datetime.now(datetime.UTC)
    values = {
        "invocation_id": "a" * 64,
        "physical_sequence": 1,
        "status": "succeeded",
        "upstream_provider": "OpenAI",
        "provider_request_id": "provider-request-envelope",
        "input_tokens": 1,
        "output_tokens": 1,
        "reasoning_tokens": 0,
        "cost_measurement_state": "measured",
        "measured_cost_usd": Decimal("0"),
        "error_code": None,
        "finished_at": now,
    }
    assert ProviderTerminalEventV1(returned_model="m" * 192, **values).returned_model == "m" * 192
    with pytest.raises(ValueError, match="returned_model"):
        ProviderTerminalEventV1(returned_model="m" * 193, **values)


def test_failed_logical_projection_preserves_192_character_returned_model(
    migrated_db: Engine,
) -> None:
    store, run_id, configuration = _authorized_run(migrated_db)
    execution_id = _start(
        store,
        run_id,
        configuration,
        role="documentation",
    )
    _record_physical_event(
        store,
        execution_id=execution_id,
        role="documentation",
        status="invalid_output",
        returned_model="m" * 192,
        upstream_provider="OpenAI",
        provider_request_id="provider-request-long-returned-model",
        input_tokens=1,
        output_tokens=1,
        reasoning_tokens=0,
        cost_measurement_state="measured",
        measured_cost_usd=Decimal("0"),
        error_code="invalid_structured_output",
    )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        error_code="invalid_structured_output",
    )

    with migrated_db.connect() as connection:
        returned_model = connection.execute(
            text("SELECT returned_model FROM agent_executions WHERE execution_id = :execution"),
            {"execution": execution_id},
        ).scalar_one()
    assert returned_model == "m" * 192


def test_hosted_logical_langfuse_generation_is_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = _LangfuseBridge()
    client = _LangfuseClient()
    bridge.client = client
    monkeypatch.setattr(bridge, "configured", lambda: True)
    state = bridge.start_agent(
        trace_id="a" * 32,
        role="judge",
        provider="openrouter",
        model=_MODELS["judge"],
        execution_mode="hosted_advisory",
        version="1",
        input_payload={"sha256": "b" * 64},
        metadata={"agent.execution_id": "execution-1"},
    )
    assert state is not None
    generation = state[1]
    bridge.finish_agent(
        state,
        output={"sha256": "c" * 64},
        metadata={"agent.returned_model": _MODELS["judge"]},
        error_code=None,
        status="succeeded",
        input_tokens=100,
        output_tokens=30,
        reasoning_tokens=9,
        measured_cost=0.0125,
        cost_measurement_state="measured",
        provider_event_ids=["d" * 64],
        returned_model=_MODELS["judge"],
    )

    assert "model" not in generation.updated[0]
    assert "usage_details" not in generation.updated[0]
    assert "cost_details" not in generation.updated[0]
    assert generation.updated[0]["metadata"]["cost.source"] == "provider_attempt_generations"
    assert generation.ended is True
    assert client.agent.ended is True


def test_langfuse_physical_generation_carries_native_usage_and_cost_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = _LangfuseBridge()
    client = _LangfuseClient()
    bridge.client = client
    monkeypatch.setattr(bridge, "configured", lambda: True)
    agent_state = bridge.start_agent(
        trace_id="a" * 32,
        role="judge",
        provider="openrouter",
        model=_MODELS["judge"],
        execution_mode="hosted_advisory",
        version="1",
        input_payload={"sha256": "b" * 64},
        metadata={"agent.execution_id": "execution-physical"},
    )
    assert agent_state is not None
    physical = bridge.start_provider_attempt(
        agent_state,
        model=_MODELS["judge"],
        version="judge-v1",
        input_payload={
            "prompt_sha256": "c" * 64,
            "configuration_set_sha256": "d" * 64,
        },
        metadata={
            "agent.execution_id": "execution-physical",
            "provider.invocation_id": "e" * 64,
        },
    )
    bridge.finish_provider_attempt(
        physical,
        output={"provider_event_id": "f" * 64},
        metadata={
            "provider.status": "succeeded",
            "cost.measurement_state": "measured",
        },
        error_code=None,
        status="succeeded",
        returned_model=_MODELS["judge"],
        input_tokens=100,
        output_tokens=30,
        reasoning_tokens=9,
        measured_cost=0.0125,
        cost_measurement_state="measured",
    )

    physical_start = client.agent.started[1]
    assert physical_start["name"] == "provider.openrouter.attempt"
    assert physical_start["as_type"] == "generation"
    assert physical_start["input"] == {
        "prompt_sha256": "c" * 64,
        "configuration_set_sha256": "d" * 64,
    }
    assert physical.updated[0]["model"] == _MODELS["judge"]
    assert physical.updated[0]["usage_details"] == {
        "input": 100,
        "output": 30,
        "reasoning": 9,
        "total": 139,
    }
    assert physical.updated[0]["cost_details"] == {"total": 0.0125}
    assert physical.ended is True


def test_langfuse_generation_does_not_invent_unobserved_zero_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = _LangfuseBridge()
    client = _LangfuseClient()
    bridge.client = client
    monkeypatch.setattr(bridge, "configured", lambda: True)
    state = bridge.start_agent(
        trace_id="a" * 32,
        role="documentation",
        provider="openrouter",
        model=_MODELS["documentation"],
        execution_mode="hosted_advisory",
        version="1",
        input_payload={"sha256": "b" * 64},
        metadata={"agent.execution_id": "execution-unobserved"},
    )
    assert state is not None
    generation = state[1]
    bridge.finish_agent(
        state,
        output={"sha256": "c" * 64},
        metadata={"cost.usd": None},
        error_code="provider_outcome_unknown",
        status="failed",
        input_tokens=None,
        output_tokens=None,
        reasoning_tokens=None,
        measured_cost=None,
        cost_measurement_state="not_observed",
        provider_event_ids=["d" * 64],
        returned_model=None,
    )

    assert "cost_details" not in generation.updated[0]
    metadata = generation.updated[0]["metadata"]
    assert metadata["cost.source"] == "provider_attempt_generations"
    assert metadata["cost.measurement_state"] == "not_observed"
    assert metadata["agent.provider_event_ids"] == ["d" * 64]
