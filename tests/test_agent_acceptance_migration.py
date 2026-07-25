"""Database authority for a bounded, no-target hosted-agent acceptance run."""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from copy import deepcopy

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import DBAPIError

import _db
from agentforge.storage.models import CampaignRunRecord

_ORGANIZATION_ID = "org_AgentAcceptance"
_CONFIGURATION_SHA256 = "a" * 64
_GENERATION_POLICY_SHA256 = "b" * 64
_CONTEXT_SHA256 = "c" * 64
_ACCEPTANCE_CASE_ID = "agentforge-hosted-acceptance-v1"
_PROVENANCE = {
    "actor_type": "system",
    "schema_version": "1",
    "source": "agentforge.live_acceptance",
}
_FIXTURE_PROVENANCE = {
    "classification": "synthetic",
    "contains_real_phi": False,
    "schema_version": "1",
    "source": "agentforge.live_acceptance",
}
_LIMITS = {
    "schema_version": "1",
    "network_scope": "openrouter_langfuse_only",
    "target_call_limit": 0,
    "allowed_roles": ["orchestrator", "judge", "documentation"],
    "role_call_caps": {
        "orchestrator": 1,
        "judge": 1,
        "documentation": 1,
    },
    "role_usd_caps": {
        "orchestrator": "1.5",
        "judge": "4",
        "documentation": "1",
    },
    "global_call_cap": 3,
    "global_usd_cap": "10",
}


def _acceptance_attempt_id(run_id: str) -> str:
    identity = f"m1d-attempt:v1\0{run_id}\0{0}\0{_ACCEPTANCE_CASE_ID}"
    return hashlib.sha256(identity.encode()).hexdigest()


def _seed_hosted_configuration(
    engine: Engine,
    *,
    organization_id: str = _ORGANIZATION_ID,
    configuration_sha256: str = _CONFIGURATION_SHA256,
) -> None:
    release_sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO hosted_configuration_sets "
                "(organization_id, configuration_sha256, schema_version, release_sha256, "
                "payload, rationale, actor_user_id, actor_session_id) VALUES "
                "(:org, :configuration, '1', :release, '{}'::jsonb, "
                "'bounded acceptance fixture', 'user_AcceptanceOwner', "
                "'sess_AcceptanceOwner')"
            ),
            {
                "org": organization_id,
                "configuration": configuration_sha256,
                "release": release_sha256,
            },
        )


def _insert_acceptance(
    engine: Engine,
    *,
    run_id: str | None = None,
    organization_id: str = _ORGANIZATION_ID,
    configuration_sha256: str = _CONFIGURATION_SHA256,
    limits: dict[str, object] | None = None,
    expires_at: datetime.datetime | None = None,
    authorization_request_id: str | None = None,
    scope_hash: str | None = None,
    launcher_user_id: str | None = None,
    launcher_session_id: str | None = None,
    insert_attempt: bool = True,
    attempt_case_id: str = _ACCEPTANCE_CASE_ID,
) -> str:
    resolved_run_id = run_id or f"AR-{uuid.uuid4().hex}"
    acceptance_attempt_id = _acceptance_attempt_id(resolved_run_id)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, run_kind, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id, acceptance_configuration_sha256, "
                "acceptance_generation_policy_sha256, acceptance_context_sha256, "
                "acceptance_attempt_id, "
                "acceptance_limits, acceptance_expires_at, acceptance_actor_id, "
                "acceptance_provenance) VALUES "
                "(:run_id, :org, 'agent_acceptance', :authorization_request_id, :scope_hash, "
                ":launcher_user_id, :launcher_session_id, :configuration, :generation_policy, "
                ":context, :attempt_id, CAST(:limits AS jsonb), :expires_at, "
                "'system:live-acceptance', CAST(:provenance AS jsonb))"
            ),
            {
                "run_id": resolved_run_id,
                "org": organization_id,
                "authorization_request_id": authorization_request_id,
                "scope_hash": scope_hash,
                "launcher_user_id": launcher_user_id,
                "launcher_session_id": launcher_session_id,
                "configuration": configuration_sha256,
                "generation_policy": _GENERATION_POLICY_SHA256,
                "context": _CONTEXT_SHA256,
                "attempt_id": acceptance_attempt_id,
                "limits": json.dumps(limits or _LIMITS),
                "expires_at": expires_at
                or datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
                "provenance": json.dumps(_PROVENANCE),
            },
        )
        if insert_attempt:
            connection.execute(
                text(
                    "INSERT INTO campaign_attempts "
                    "(organization_id, run_id, attempt_id, ordinal, case_id, "
                    "case_content_hash, fixture_provenance) VALUES "
                    "(:org, :run_id, :attempt_id, 0, :case_id, :context, "
                    "CAST(:fixture AS jsonb))"
                ),
                {
                    "org": organization_id,
                    "run_id": resolved_run_id,
                    "attempt_id": acceptance_attempt_id,
                    "case_id": attempt_case_id,
                    "context": _CONTEXT_SHA256,
                    "fixture": json.dumps(_FIXTURE_PROVENANCE),
                },
            )
    return resolved_run_id


def _insert_agent_execution(
    engine: Engine,
    *,
    run_id: str,
    configuration_sha256: str,
    role: str,
    parent_execution_id: str | None,
    attempt_id: str | None,
) -> str:
    execution_id = uuid.uuid4().hex
    models = {
        "orchestrator": "anthropic/claude-opus-4.8",
        "red_team": "qwen/qwen3-235b-a22b",
        "judge": "google/gemini-2.5-pro",
        "documentation": "openai/gpt-5.4",
    }
    judge_calibration_id = f"JC-{'3' * 64}" if role == "judge" else None
    judge_calibration_state = "failed" if role == "judge" else None
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, attempt_id, "
                "parent_execution_id, agent_role, provider, model, execution_mode, "
                "configuration_version, input_sha256, trace_id, detail, "
                "configuration_set_sha256, "
                "role_configuration_sha256, generation_policy_sha256, "
                "judge_calibration_id, judge_calibration_state) VALUES "
                "(:execution, :org, :run, :attempt, :parent, :role, 'openrouter', "
                ":model, 'hosted_advisory', 1, :input_hash, :trace_id, "
                '\'{"provider_lineage_state":"canonical_physical"}\'::jsonb, '
                ":configuration, :role_configuration, :generation_policy, "
                ":calibration, :calibration_state)"
            ),
            {
                "execution": execution_id,
                "org": _ORGANIZATION_ID,
                "run": run_id,
                "attempt": attempt_id,
                "parent": parent_execution_id,
                "role": role,
                "model": models[role],
                "input_hash": "1" * 64,
                "trace_id": uuid.uuid4().hex,
                "configuration": configuration_sha256,
                "role_configuration": "2" * 64,
                "generation_policy": _GENERATION_POLICY_SHA256,
                "calibration": judge_calibration_id,
                "calibration_state": judge_calibration_state,
            },
        )
    return execution_id


def _seed_authorized_campaign(engine: Engine, suffix: str) -> str:
    run_id = f"campaign-{suffix}"
    request_id = f"request-{suffix}"
    scope_hash = "d" * 64
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:request, :org, :scope, '{}'::jsonb, 'user_CampaignLauncher', "
                "'sess_CampaignLauncher', clock_timestamp() + interval '15 minutes')"
            ),
            {"request": request_id, "org": _ORGANIZATION_ID, "scope": scope_hash},
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) VALUES "
                "(:decision, :org, :request, :scope, 'approved', "
                "'user_CampaignApprover', 'sess_CampaignApprover')"
            ),
            {
                "decision": f"decision-{suffix}",
                "org": _ORGANIZATION_ID,
                "request": request_id,
                "scope": scope_hash,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run, :org, :request, :scope, "
                "'user_CampaignLauncher', 'sess_CampaignLauncher')"
            ),
            {
                "run": run_id,
                "org": _ORGANIZATION_ID,
                "request": request_id,
                "scope": scope_hash,
            },
        )
    return run_id


def test_agent_acceptance_migration_is_the_only_head() -> None:
    script = ScriptDirectory.from_config(_db.alembic_config(_db.admin_url()))
    assert script.get_heads() == ["0020"]
    assert script.get_revision("0020").down_revision == "0019"
    assert script.get_revision("0019").down_revision == "0018"


def test_campaign_run_model_matches_discriminated_acceptance_authority() -> None:
    columns = CampaignRunRecord.__table__.c
    assert columns.run_kind.nullable is False
    assert columns.authorization_request_id.nullable is True
    assert columns.scope_hash.nullable is True
    assert columns.launcher_user_id.nullable is True
    assert columns.launcher_session_id.nullable is True
    for name in (
        "acceptance_configuration_sha256",
        "acceptance_generation_policy_sha256",
        "acceptance_context_sha256",
        "acceptance_attempt_id",
        "acceptance_limits",
        "acceptance_expires_at",
        "acceptance_actor_id",
        "acceptance_provenance",
    ):
        assert columns[name].nullable is True


def test_0020_backfills_campaign_and_round_trips_without_weakening_campaign_gate(
    admin_url: str,
) -> None:
    database_name = f"agentforge_agent_acceptance_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(database_url, "0018")
        engine = _db.build_engine(database_url)
        campaign_run_id = _seed_authorized_campaign(engine, uuid.uuid4().hex[:10])

        _db.alembic_upgrade(database_url, "0020")
        with engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT run_kind, acceptance_configuration_sha256 "
                        "FROM campaign_runs WHERE run_id = :run"
                    ),
                    {"run": campaign_run_id},
                )
                .mappings()
                .one()
            )
            assert dict(row) == {
                "run_kind": "campaign",
                "acceptance_configuration_sha256": None,
            }
            nullable = {
                item["name"]: item["nullable"]
                for item in inspect(connection).get_columns("campaign_runs")
            }
            assert nullable["authorization_request_id"] is True
            assert nullable["launcher_user_id"] is True

        with (
            pytest.raises(DBAPIError, match="one live exact-scope approval"),
            engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "INSERT INTO campaign_runs "
                    "(run_id, organization_id, authorization_request_id, scope_hash, "
                    "launcher_user_id, launcher_session_id) VALUES "
                    "('campaign-no-approval', :org, 'missing-request', :scope, "
                    "'user_CampaignLauncher', 'sess_CampaignLauncher')"
                ),
                {"org": _ORGANIZATION_ID, "scope": "e" * 64},
            )

        _db.alembic_downgrade(database_url, "0018")
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT count(*) FROM campaign_runs WHERE run_id = :run"),
                    {"run": campaign_run_id},
                ).scalar_one()
                == 1
            )
            columns = {
                item["name"]: item["nullable"]
                for item in inspect(connection).get_columns("campaign_runs")
            }
            assert "run_kind" not in columns
            assert columns["authorization_request_id"] is False
            assert columns["launcher_session_id"] is False
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_valid_agent_acceptance_is_no_target_and_append_only(migrated_db: Engine) -> None:
    configuration_sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    _seed_hosted_configuration(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    run_id = _insert_acceptance(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )

    with migrated_db.connect() as connection:
        row = (
            connection.execute(
                text(
                    "SELECT run_kind, authorization_request_id, launcher_user_id, "
                    "acceptance_attempt_id, "
                    "acceptance_limits->>'network_scope' AS network_scope, "
                    "acceptance_limits->>'target_call_limit' AS target_call_limit "
                    "FROM campaign_runs WHERE run_id = :run"
                ),
                {"run": run_id},
            )
            .mappings()
            .one()
        )
    assert dict(row) == {
        "run_kind": "agent_acceptance",
        "authorization_request_id": None,
        "launcher_user_id": None,
        "acceptance_attempt_id": _acceptance_attempt_id(run_id),
        "network_scope": "openrouter_langfuse_only",
        "target_call_limit": "0",
    }

    with pytest.raises(DBAPIError, match="append-only"), migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE campaign_runs SET acceptance_context_sha256 = :changed WHERE run_id = :run"
            ),
            {"changed": "f" * 64, "run": run_id},
        )


def test_agent_acceptance_requires_one_exact_synthetic_attempt(
    migrated_db: Engine,
) -> None:
    configuration_sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    _seed_hosted_configuration(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )

    with pytest.raises(DBAPIError, match="fk_campaign_run_acceptance_attempt"):
        _insert_acceptance(
            migrated_db,
            configuration_sha256=configuration_sha256,
            insert_attempt=False,
        )

    with pytest.raises(DBAPIError, match="exact synthetic singleton"):
        _insert_acceptance(
            migrated_db,
            configuration_sha256=configuration_sha256,
            attempt_case_id="not-the-authorized-acceptance-case",
        )

    run_id = _insert_acceptance(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    with migrated_db.connect() as connection:
        attempt = (
            connection.execute(
                text(
                    "SELECT attempt_id, ordinal, case_id, case_content_hash, "
                    "fixture_provenance FROM campaign_attempts "
                    "WHERE organization_id = :org AND run_id = :run"
                ),
                {"org": _ORGANIZATION_ID, "run": run_id},
            )
            .mappings()
            .one()
        )
        assert attempt["ordinal"] == 0
        assert attempt["case_id"] == _ACCEPTANCE_CASE_ID
        assert attempt["case_content_hash"] == _CONTEXT_SHA256
        assert attempt["fixture_provenance"] == _FIXTURE_PROVENANCE

    with (
        pytest.raises(DBAPIError, match="exact synthetic singleton"),
        migrated_db.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO campaign_attempts "
                "(organization_id, run_id, attempt_id, ordinal, case_id) "
                "VALUES (:org, :run, :attempt, 1, 'extra-acceptance-attempt')"
            ),
            {
                "org": _ORGANIZATION_ID,
                "run": run_id,
                "attempt": "f" * 64,
            },
        )


def test_database_guards_acceptance_execution_attempt_parentage_and_judge(
    migrated_db: Engine,
) -> None:
    configuration_sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    _seed_hosted_configuration(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    run_id = _insert_acceptance(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    attempt_id = _acceptance_attempt_id(run_id)

    with pytest.raises(DBAPIError, match="outside its role or attempt authority"):
        _insert_agent_execution(
            migrated_db,
            run_id=run_id,
            configuration_sha256=configuration_sha256,
            role="orchestrator",
            parent_execution_id=None,
            attempt_id=None,
        )
    with pytest.raises(DBAPIError, match="outside its role or attempt authority"):
        _insert_agent_execution(
            migrated_db,
            run_id=run_id,
            configuration_sha256=configuration_sha256,
            role="red_team",
            parent_execution_id=None,
            attempt_id=attempt_id,
        )

    orchestrator_id = _insert_agent_execution(
        migrated_db,
        run_id=run_id,
        configuration_sha256=configuration_sha256,
        role="orchestrator",
        parent_execution_id=None,
        attempt_id=attempt_id,
    )
    with pytest.raises(DBAPIError, match="requires its exact parent"):
        _insert_agent_execution(
            migrated_db,
            run_id=run_id,
            configuration_sha256=configuration_sha256,
            role="judge",
            parent_execution_id=None,
            attempt_id=attempt_id,
        )
    judge_id = _insert_agent_execution(
        migrated_db,
        run_id=run_id,
        configuration_sha256=configuration_sha256,
        role="judge",
        parent_execution_id=orchestrator_id,
        attempt_id=attempt_id,
    )
    with pytest.raises(DBAPIError, match="requires its exact parent"):
        _insert_agent_execution(
            migrated_db,
            run_id=run_id,
            configuration_sha256=configuration_sha256,
            role="documentation",
            parent_execution_id=orchestrator_id,
            attempt_id=attempt_id,
        )
    _insert_agent_execution(
        migrated_db,
        run_id=run_id,
        configuration_sha256=configuration_sha256,
        role="documentation",
        parent_execution_id=judge_id,
        attempt_id=attempt_id,
    )

    with (
        pytest.raises(DBAPIError, match="must remain failed-calibration advisory"),
        migrated_db.begin() as connection,
    ):
        connection.execute(
            text(
                "UPDATE agent_executions SET judge_calibration_state = 'passed' "
                "WHERE organization_id = :org AND execution_id = :execution"
            ),
            {
                "org": _ORGANIZATION_ID,
                "execution": judge_id,
            },
        )

    with (
        pytest.raises(DBAPIError, match="requires explicit oracle reconciliation"),
        migrated_db.begin() as connection,
    ):
        connection.execute(
            text(
                "UPDATE agent_executions SET status = 'succeeded', "
                "output_sha256 = :output_hash, returned_model = model, "
                "upstream_provider = 'Google', provider_request_id = 'provider-request', "
                "input_tokens = 1, output_tokens = 1, reasoning_tokens = 0, "
                "physical_attempts = 1, finished_at = clock_timestamp(), duration_ms = 1, "
                "decision_authority = 'none', oracle_agreement = TRUE "
                "WHERE organization_id = :org AND execution_id = :execution"
            ),
            {
                "org": _ORGANIZATION_ID,
                "execution": judge_id,
                "output_hash": "4" * 64,
            },
        )


def test_database_binds_acceptance_provider_invocation_to_its_logical_execution(
    migrated_db: Engine,
) -> None:
    configuration_sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    _seed_hosted_configuration(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    first_run_id = _insert_acceptance(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    second_run_id = _insert_acceptance(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    execution_id = _insert_agent_execution(
        migrated_db,
        run_id=first_run_id,
        configuration_sha256=configuration_sha256,
        role="orchestrator",
        parent_execution_id=None,
        attempt_id=_acceptance_attempt_id(first_run_id),
    )

    with (
        pytest.raises(DBAPIError, match="differs from its logical execution"),
        migrated_db.begin() as connection,
    ):
        connection.execute(
            text(
                "INSERT INTO provider_call_invocations "
                "(invocation_id, organization_id, campaign_run_id, campaign_attempt_id, "
                "logical_execution_id, parent_execution_id, agent_role, physical_sequence, "
                "idempotency_key, requested_model, configured_upstream, prompt_version, "
                "prompt_sha256, configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256) VALUES "
                "(:invocation, :org, :run, :attempt, :execution, NULL, 'orchestrator', 1, "
                ":idempotency, 'anthropic/claude-opus-4.8', 'anthropic', '1', "
                ":prompt, :configuration, :role_configuration, :generation_policy)"
            ),
            {
                "invocation": uuid.uuid4().hex,
                "org": _ORGANIZATION_ID,
                "run": second_run_id,
                "attempt": _acceptance_attempt_id(second_run_id),
                "execution": execution_id,
                "idempotency": f"provider-call:{uuid.uuid4().hex}",
                "prompt": "4" * 64,
                "configuration": configuration_sha256,
                "role_configuration": "2" * 64,
                "generation_policy": _GENERATION_POLICY_SHA256,
            },
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda limits: limits["allowed_roles"].append("red_team"),
        lambda limits: limits["role_call_caps"].update({"red_team": 1}),
        lambda limits: limits["role_call_caps"].update({"judge": 2}),
        lambda limits: limits["role_usd_caps"].update({"orchestrator": "1.5000001"}),
        lambda limits: limits["role_usd_caps"].update({"judge": "4.01"}),
        lambda limits: limits["role_usd_caps"].update({"documentation": "1.01"}),
        lambda limits: limits.update({"global_call_cap": 4}),
        lambda limits: limits.update({"global_usd_cap": "10.01"}),
        lambda limits: limits.update({"target_call_limit": 1}),
        lambda limits: limits.update({"network_scope": "target_and_provider"}),
    ],
)
def test_agent_acceptance_rejects_unbounded_or_generator_limits(
    migrated_db: Engine,
    mutate,
) -> None:
    configuration_sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    _seed_hosted_configuration(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    limits = deepcopy(_LIMITS)
    mutate(limits)

    with pytest.raises(DBAPIError):
        _insert_acceptance(
            migrated_db,
            configuration_sha256=configuration_sha256,
            limits=limits,
        )


def test_agent_acceptance_rejects_missing_config_expiry_and_mixed_authority(
    migrated_db: Engine,
) -> None:
    with pytest.raises(DBAPIError, match="configuration is unavailable"):
        _insert_acceptance(
            migrated_db,
            configuration_sha256="9" * 64,
        )

    configuration_sha256 = uuid.uuid4().hex + uuid.uuid4().hex
    _seed_hosted_configuration(
        migrated_db,
        configuration_sha256=configuration_sha256,
    )
    with pytest.raises(DBAPIError, match="authority expired"):
        _insert_acceptance(
            migrated_db,
            configuration_sha256=configuration_sha256,
            expires_at=datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1),
        )
    with pytest.raises(DBAPIError):
        _insert_acceptance(
            migrated_db,
            configuration_sha256=configuration_sha256,
            authorization_request_id="request-mixed",
            scope_hash="8" * 64,
            launcher_user_id="user_Mixed",
            launcher_session_id="sess_Mixed",
        )
    with pytest.raises(DBAPIError):
        _insert_acceptance(
            migrated_db,
            run_id=f"campaign-{uuid.uuid4().hex}",
            configuration_sha256=configuration_sha256,
        )
