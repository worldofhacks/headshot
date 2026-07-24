"""Durable, run-bound hosted-agent telemetry and Langfuse projection contracts."""

from __future__ import annotations

import datetime
import hashlib
from decimal import Decimal

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.hosted_prompts import hosted_prompt
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
)
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.providers.openrouter import HostedBudgetExceeded
from agentforge.runner import DurableCampaignRunner
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
_SESSION_GENERATION = "generation-20260724"
_GENERATION_POLICY = "d" * 64
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
                credential_reference=(
                    f"secretref://staging/providers/openrouter/{role}/{_SESSION_GENERATION}"
                ),
                prompt_sha256=hosted_prompt(role).prompt_sha256,  # type: ignore[arg-type]
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
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"selected_case_ref": "synthetic-case-1"},
        returned_model=role.model_id,
        upstream_provider=_SELECTED_PROVIDER["orchestrator"],
        provider_request_id="openrouter-request-synthetic-1",
        input_tokens=123,
        output_tokens=45,
        reasoning_tokens=7,
        measured_cost_usd="0.000001234567",
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY,
        physical_attempts=1,
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
    assert row["trace_id"] == projection.started[0]["trace_id"]
    assert "must_not_be_projected" not in str(projection.started[0]["input_payload"])
    assert projection.finished[0]["returned_model"] == role.model_id
    assert projection.finished[0]["reasoning_tokens"] == 7
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
    role = next(item for item in configuration.roles if item.role == "judge")
    values = {
        "execution_id": execution_id,
        "status": "succeeded",
        "output_payload": {"state": "NO_EXPLOIT_OBSERVED"},
        "returned_model": role.model_id,
        "upstream_provider": _SELECTED_PROVIDER["judge"],
        "provider_request_id": "openrouter-request-judge-1",
        "input_tokens": 100,
        "output_tokens": 20,
        "reasoning_tokens": 5,
        "measured_cost_usd": "0.01",
        "configuration_set_sha256": configuration.configuration_sha256,
        "role_configuration_sha256": role.configuration_sha256,
        "generation_policy_sha256": _GENERATION_POLICY,
        "physical_attempts": 1,
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
                    "physical_attempts, measured_cost, error_code "
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
    # No provider accounting was observed, so the cost stays NULL. Recording a zero here would
    # be the fabricated measurement this test exists to forbid.
    assert row["measured_cost"] is None
    assert row["error_code"] == "hosted-agent-failed"


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
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        physical_attempts=2,
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
                    "reasoning_tokens, measured_cost FROM agent_executions "
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
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="failed",
        output_payload={"status": "failed"},
        returned_model=role.model_id,
        upstream_provider=_SELECTED_PROVIDER["documentation"],
        provider_request_id="openrouter-request-charged-invalid-output",
        input_tokens=321,
        output_tokens=40,
        reasoning_tokens=9,
        measured_cost_usd="0.125",
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY,
        physical_attempts=1,
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


def test_langfuse_generation_uses_returned_model_and_reasoning_usage(
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
        returned_model=_MODELS["judge"],
    )

    assert generation.updated[0]["model"] == _MODELS["judge"]
    assert generation.updated[0]["usage_details"] == {
        "input": 100,
        "output": 30,
        "reasoning": 9,
        "total": 139,
    }
    assert generation.updated[0]["cost_details"] == {"total": 0.0125}
    assert generation.ended is True
    assert client.agent.ended is True
