"""Store authority for the bounded, target-free hosted-agent acceptance run."""

from __future__ import annotations

import datetime
import hashlib
from decimal import Decimal

import pytest
from sqlalchemy import Engine, text

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.prompts import load_prompt_registry
from agentforge.auth.principal import Principal
from agentforge.control_plane.errors import AuthorizationDeniedError, RecordConflictError
from agentforge.control_plane.store import (
    AgentAcceptanceRunIdentity,
    ControlPlaneStore,
    canonical_agent_acceptance_limits,
)
from agentforge.providers.lineage import ProviderTerminalEventV1

_ORGANIZATION_ID = "org_AgentAcceptance"
_GENERATION_POLICY_SHA256 = "d" * 64
_RELEASE_SHA256 = hashlib.sha256(b"reviewed-combined-release").hexdigest()
_JUDGE_CALIBRATION_ID = f"JC-{'c' * 64}"
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
_SERVED_UPSTREAM = {
    "orchestrator": "Anthropic",
    "red_team": "Together",
    "judge": "Google",
    "documentation": "OpenAI",
}
_USD_CAPS = {
    "orchestrator": Decimal("1.5"),
    "red_team": Decimal("1"),
    "judge": Decimal("4"),
    "documentation": Decimal("1"),
}


def _prompt(role: str):
    return next(record for record in load_prompt_registry() if record.role == role)


def _configuration() -> HostedConfigurationSet:
    return HostedConfigurationSet(
        roles=tuple(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=_MODELS[role],
                upstream_provider=_UPSTREAM[role],
                credential_reference=f"secretref://local/openrouter/{role}/acceptance-1",
                prompt_sha256=_prompt(role).sha256,
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
                    max_usd=_USD_CAPS[role],
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


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE campaign_runs, hosted_configuration_sets, "
                "command_idempotency, audit_events RESTART IDENTITY CASCADE"
            )
        )


def _stage(store: ControlPlaneStore, configuration: HostedConfigurationSet) -> None:
    store.stage_hosted_configuration_set(
        principal=Principal(
            user_id="user_acceptance_operator",
            session_id="sess_acceptance_operator",
            organization_id=_ORGANIZATION_ID,
            organization_role="org:operator",
            organization_permissions=frozenset({"org:config:manage"}),
        ),
        configuration=configuration,
        release_sha256=_RELEASE_SHA256,
        rationale=(
            "Stage the bounded, target-free four-role hosted acceptance configuration through "
            "CONFIG_MANAGE; this does not authorize campaign or target traffic."
        ),
        idempotency_key="agent-acceptance-stage-config-0001",
    )


def _create(
    engine: Engine,
) -> tuple[ControlPlaneStore, AgentAcceptanceRunIdentity, HostedConfigurationSet]:
    _clean(engine)
    store = ControlPlaneStore(engine, environment="local")
    configuration = _configuration()
    _stage(store, configuration)
    identity = store.create_agent_acceptance_run(
        organization_id=_ORGANIZATION_ID,
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY_SHA256,
        acceptance_context={
            "fixture": "synthetic-agent-acceptance-v1",
            "synthetic_data_only": True,
            "target_traffic": "forbidden",
        },
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        limits=canonical_agent_acceptance_limits(configuration),
    )
    return store, identity, configuration


def _start(
    store: ControlPlaneStore,
    identity: AgentAcceptanceRunIdentity,
    configuration: HostedConfigurationSet,
    role: str,
    *,
    parent_execution_id: str | None = None,
) -> str:
    role_configuration = next(item for item in configuration.roles if item.role == role)
    return store.start_acceptance_agent_execution(
        run_id=identity.run_id,
        agent_role=role,  # type: ignore[arg-type]
        input_payload={"fixture": "synthetic-agent-acceptance-v1", "role": role},
        provider=role_configuration.provider,
        model=role_configuration.model_id,
        upstream_provider=role_configuration.upstream_provider,
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role_configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY_SHA256,
        judge_calibration_id=_JUDGE_CALIBRATION_ID if role == "judge" else None,
        judge_calibration_state="failed" if role == "judge" else None,
        parent_execution_id=parent_execution_id,
        detail={"input_kind": "synthetic_acceptance"},
    )


def _succeed(
    store: ControlPlaneStore,
    execution_id: str,
    configuration: HostedConfigurationSet,
    role: str,
) -> None:
    role_configuration = next(item for item in configuration.roles if item.role == role)
    prompt = _prompt(role)
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    cost = Decimal("0.010000000000")
    store.finish_physical_attempt(
        invocation,
        ProviderTerminalEventV1(
            invocation_id=invocation.invocation_id,
            physical_sequence=1,
            status="succeeded",
            returned_model=logical.requested_model,
            upstream_provider=_SERVED_UPSTREAM[role],
            provider_request_id=f"acceptance-provider-request-{role}",
            input_tokens=10,
            output_tokens=5,
            reasoning_tokens=2,
            cost_measurement_state="measured",
            measured_cost_usd=cost,
            error_code=None,
            finished_at=datetime.datetime.now(datetime.UTC),
        ),
    )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"fixture": "synthetic-agent-acceptance-v1", "role": role},
        returned_model=logical.requested_model,
        upstream_provider=_SERVED_UPSTREAM[role],
        provider_request_id=f"acceptance-provider-request-{role}",
        input_tokens=10,
        output_tokens=5,
        reasoning_tokens=2,
        measured_cost_usd=format(cost, "f"),
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role_configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY_SHA256,
        physical_attempts=1,
        oracle_agreement=True if role == "judge" else None,
        decision_authority="oracle" if role == "judge" else None,
    )


def test_acceptance_atomically_creates_one_canonical_attempt(
    migrated_db: Engine,
) -> None:
    _, identity, configuration = _create(migrated_db)
    expected_attempt = hashlib.sha256(
        f"m1d-attempt:v1\0{identity.run_id}\0{0}\0agentforge-hosted-acceptance-v1".encode()
    ).hexdigest()

    with migrated_db.connect() as connection:
        run = (
            connection.execute(
                text(
                    "SELECT run_kind, acceptance_attempt_id, "
                    "acceptance_configuration_sha256 FROM campaign_runs WHERE run_id = :run"
                ),
                {"run": identity.run_id},
            )
            .mappings()
            .one()
        )
        attempts = (
            connection.execute(
                text(
                    "SELECT attempt_id, ordinal, case_id, fixture_provenance "
                    "FROM campaign_attempts WHERE run_id = :run"
                ),
                {"run": identity.run_id},
            )
            .mappings()
            .all()
        )

    assert identity.attempt_id == expected_attempt
    assert run["run_kind"] == "agent_acceptance"
    assert run["acceptance_attempt_id"] == identity.attempt_id
    assert run["acceptance_configuration_sha256"] == configuration.configuration_sha256
    assert len(attempts) == 1
    assert attempts[0]["attempt_id"] == identity.attempt_id
    assert attempts[0]["ordinal"] == 0
    assert attempts[0]["case_id"] == "agentforge-hosted-acceptance-v1"
    assert attempts[0]["fixture_provenance"]["contains_real_phi"] is False


def test_acceptance_configuration_load_is_bound_to_the_reviewed_release(
    migrated_db: Engine,
) -> None:
    store, _, configuration = _create(migrated_db)

    assert (
        store.load_hosted_configuration_set(
            organization_id=_ORGANIZATION_ID,
            configuration_set_sha256=configuration.configuration_sha256,
            release_sha256=_RELEASE_SHA256,
        )
        == configuration
    )
    with pytest.raises(AuthorizationDeniedError, match="different reviewed release"):
        store.load_hosted_configuration_set(
            organization_id=_ORGANIZATION_ID,
            configuration_set_sha256=configuration.configuration_sha256,
            release_sha256="f" * 64,
        )


def test_acceptance_binds_all_owned_roles_to_the_same_non_null_attempt(
    migrated_db: Engine,
) -> None:
    store, identity, configuration = _create(migrated_db)
    planner = _start(store, identity, configuration, "orchestrator")
    evaluator = _start(
        store,
        identity,
        configuration,
        "judge",
        parent_execution_id=planner,
    )
    report_writer = _start(
        store,
        identity,
        configuration,
        "documentation",
        parent_execution_id=evaluator,
    )

    with migrated_db.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT execution_id, attempt_id, parent_execution_id, agent_role "
                    "FROM agent_executions WHERE campaign_run_id = :run ORDER BY id"
                ),
                {"run": identity.run_id},
            )
            .mappings()
            .all()
        )
    assert [row["agent_role"] for row in rows] == [
        "orchestrator",
        "judge",
        "documentation",
    ]
    assert {row["attempt_id"] for row in rows} == {identity.attempt_id}
    assert rows[0]["parent_execution_id"] is None
    assert rows[1]["parent_execution_id"] == planner
    assert rows[2]["parent_execution_id"] == evaluator
    assert report_writer == rows[2]["execution_id"]

    with pytest.raises(AuthorizationDeniedError, match="outside.*allowlist"):
        store.load_acceptance_role_for_execution(
            run_id=identity.run_id,
            agent_role="red_team",
        )


def test_acceptance_completes_after_three_final_provider_events_and_oracle_reconciliation(
    migrated_db: Engine,
) -> None:
    store, identity, configuration = _create(migrated_db)
    planner = _start(store, identity, configuration, "orchestrator")
    _succeed(store, planner, configuration, "orchestrator")
    evaluator = _start(
        store,
        identity,
        configuration,
        "judge",
        parent_execution_id=planner,
    )
    _succeed(store, evaluator, configuration, "judge")
    report_writer = _start(
        store,
        identity,
        configuration,
        "documentation",
        parent_execution_id=evaluator,
    )
    _succeed(store, report_writer, configuration, "documentation")

    assert store.complete_agent_acceptance_run(run_id=identity.run_id) == identity.run_id
    assert store.complete_agent_acceptance_run(run_id=identity.run_id) == identity.run_id
    with migrated_db.connect() as connection:
        executions = (
            connection.execute(
                text(
                    "SELECT agent_role, attempt_id, provider_event_ids, decision_authority "
                    "FROM agent_executions WHERE campaign_run_id = :run ORDER BY id"
                ),
                {"run": identity.run_id},
            )
            .mappings()
            .all()
        )
        states = list(
            connection.execute(
                text("SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id"),
                {"run": identity.run_id},
            ).scalars()
        )
    assert {row["attempt_id"] for row in executions} == {identity.attempt_id}
    assert all(len(row["provider_event_ids"]) == 1 for row in executions)
    assert (
        next(row for row in executions if row["agent_role"] == "judge")["decision_authority"]
        == "oracle"
    )
    assert states == ["running", "complete"]


def test_acceptance_completion_rejects_cross_projected_provider_event(
    migrated_db: Engine,
) -> None:
    store, identity, configuration = _create(migrated_db)
    planner = _start(store, identity, configuration, "orchestrator")
    _succeed(store, planner, configuration, "orchestrator")
    evaluator = _start(
        store,
        identity,
        configuration,
        "judge",
        parent_execution_id=planner,
    )
    _succeed(store, evaluator, configuration, "judge")
    report_writer = _start(
        store,
        identity,
        configuration,
        "documentation",
        parent_execution_id=evaluator,
    )
    _succeed(store, report_writer, configuration, "documentation")

    with migrated_db.begin() as connection:
        event_ids = list(
            connection.execute(
                text(
                    "SELECT execution_id, provider_event_ids->>0 AS event_id "
                    "FROM agent_executions WHERE campaign_run_id = :run ORDER BY id"
                ),
                {"run": identity.run_id},
            ).mappings()
        )
        connection.execute(
            text(
                "UPDATE agent_executions SET provider_event_ids = "
                "jsonb_build_array(CAST(:event AS text)) "
                "WHERE execution_id = :execution"
            ),
            {
                "execution": event_ids[0]["execution_id"],
                "event": event_ids[1]["event_id"],
            },
        )

    with pytest.raises(RecordConflictError, match="do not reconcile"):
        store.complete_agent_acceptance_run(run_id=identity.run_id)


def test_acceptance_final_provider_event_is_idempotent_before_logical_reconciliation(
    migrated_db: Engine,
) -> None:
    store, identity, configuration = _create(migrated_db)
    execution_id = _start(store, identity, configuration, "orchestrator")
    prompt = _prompt("orchestrator")
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    event = ProviderTerminalEventV1(
        invocation_id=invocation.invocation_id,
        physical_sequence=1,
        status="succeeded",
        returned_model=logical.requested_model,
        upstream_provider=_SERVED_UPSTREAM["orchestrator"],
        provider_request_id="acceptance-provider-request-idempotent",
        input_tokens=10,
        output_tokens=5,
        reasoning_tokens=2,
        cost_measurement_state="measured",
        measured_cost_usd=Decimal("0.010000000000"),
        error_code=None,
        finished_at=datetime.datetime.now(datetime.UTC),
    )

    assert store.finish_physical_attempt(invocation, event) == event
    assert store.finish_physical_attempt(invocation, event) == event
    with migrated_db.connect() as connection:
        logical_status = connection.execute(
            text(
                "SELECT status FROM agent_executions "
                "WHERE organization_id = :org AND execution_id = :execution"
            ),
            {"org": _ORGANIZATION_ID, "execution": execution_id},
        ).scalar_one()
        event_count = connection.execute(
            text(
                "SELECT count(*) FROM provider_call_events "
                "WHERE organization_id = :org AND invocation_id = :invocation"
            ),
            {"org": _ORGANIZATION_ID, "invocation": invocation.invocation_id},
        ).scalar_one()
    assert logical_status == "running"
    assert event_count == 1


def test_acceptance_pre_send_rechecks_concurrency_call_caps_and_kill_switch(
    migrated_db: Engine,
) -> None:
    store, identity, configuration = _create(migrated_db)
    planner = _start(store, identity, configuration, "orchestrator")
    evaluator = _start(
        store,
        identity,
        configuration,
        "judge",
        parent_execution_id=planner,
    )
    planner_prompt = _prompt("orchestrator")
    planner_logical = store.provider_logical_context(
        execution_id=planner,
        prompt_version=planner_prompt.version,
        prompt_sha256=planner_prompt.sha256,
    )
    evaluator_prompt = _prompt("judge")
    evaluator_logical = store.provider_logical_context(
        execution_id=evaluator,
        prompt_version=evaluator_prompt.version,
        prompt_sha256=evaluator_prompt.sha256,
    )
    invocation = store.begin_physical_attempt(planner_logical, 1)
    with pytest.raises(AuthorizationDeniedError, match="concurrency cap is exhausted"):
        store.begin_physical_attempt(evaluator_logical, 1)
    store.finish_physical_attempt(
        invocation,
        ProviderTerminalEventV1(
            invocation_id=invocation.invocation_id,
            physical_sequence=1,
            status="succeeded",
            returned_model=planner_logical.requested_model,
            upstream_provider=_SERVED_UPSTREAM["orchestrator"],
            provider_request_id="acceptance-provider-request-orchestrator",
            input_tokens=10,
            output_tokens=5,
            reasoning_tokens=2,
            cost_measurement_state="measured",
            measured_cost_usd=Decimal("0.010000000000"),
            error_code=None,
            finished_at=datetime.datetime.now(datetime.UTC),
        ),
    )
    with pytest.raises(AuthorizationDeniedError, match="call cap is exhausted"):
        store.begin_physical_attempt(planner_logical, 2)

    store.abort_agent_acceptance_run(
        run_id=identity.run_id,
        reason_code="operator_kill_switch",
    )
    with pytest.raises(AuthorizationDeniedError, match="not executable"):
        store.begin_physical_attempt(evaluator_logical, 1)


def test_acceptance_refuses_missing_staged_configuration_and_nonfailed_judge(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="local")
    configuration = _configuration()
    with pytest.raises(AuthorizationDeniedError, match="human-staged configuration"):
        store.create_agent_acceptance_run(
            organization_id=_ORGANIZATION_ID,
            configuration_set_sha256=configuration.configuration_sha256,
            generation_policy_sha256=_GENERATION_POLICY_SHA256,
            acceptance_context={"fixture": "synthetic-agent-acceptance-v1"},
            expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
            limits=canonical_agent_acceptance_limits(configuration),
        )

    _stage(store, configuration)
    identity = store.create_agent_acceptance_run(
        organization_id=_ORGANIZATION_ID,
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY_SHA256,
        acceptance_context={"fixture": "synthetic-agent-acceptance-v1"},
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        limits=canonical_agent_acceptance_limits(configuration),
    )
    planner = _start(store, identity, configuration, "orchestrator")
    judge = next(item for item in configuration.roles if item.role == "judge")
    with pytest.raises(
        AuthorizationDeniedError,
        match="must start with failed calibration",
    ):
        store.start_acceptance_agent_execution(
            run_id=identity.run_id,
            agent_role="judge",
            input_payload={"fixture": "synthetic-agent-acceptance-v1"},
            provider=judge.provider,
            model=judge.model_id,
            upstream_provider=judge.upstream_provider,
            configuration_set_sha256=configuration.configuration_sha256,
            role_configuration_sha256=judge.configuration_sha256,
            generation_policy_sha256=_GENERATION_POLICY_SHA256,
            judge_calibration_id=_JUDGE_CALIBRATION_ID,
            judge_calibration_state="passed",
            parent_execution_id=planner,
        )
    with pytest.raises(RecordConflictError, match="already has a logical execution"):
        _start(store, identity, configuration, "orchestrator")
