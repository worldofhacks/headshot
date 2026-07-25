"""The Langfuse delivery migration preserves requests across a rollback round trip."""

from __future__ import annotations

import json
import uuid
from decimal import Decimal

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

import _db
from agentforge.api.postgres import PostgresApiBackend
from agentforge.auth.principal import Principal

_SYNTHETIC_SECRET_PROVIDER = "Bear" + "er " + "abcdefghijklmnop"
_SYNTHETIC_SECRET_MODEL = "github_" + "pat_" + ("A" * 24)
_SYNTHETIC_SECRET_UPSTREAM = "postgresql:" + "//user:" + "pass@" + "db"
_SYNTHETIC_SECRET_REQUEST_ID = "AI" + "za" + ("B" * 24)


def _seed_0017_agent_rows(
    engine: Engine,
    *,
    organization_id: str,
    include_running: bool = False,
) -> None:
    scope_hash = "9" * 64
    run_id = "run-populated-0017"
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, "
                "launcher_user_id, launcher_session_id, expires_at) VALUES "
                "('request-populated-0017', :org, :scope_hash, CAST(:scope AS jsonb), "
                "'user_migration', 'sess_migration', clock_timestamp() + interval '1 day')"
            ),
            {
                "org": organization_id,
                "scope_hash": scope_hash,
                "scope": json.dumps(
                    {
                        "execution_profile": "live",
                        "caps": {"budget_usd": 5},
                    }
                ),
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run_id, :org, 'request-populated-0017', :scope_hash, "
                "'user_migration', 'sess_migration')"
            ),
            {
                "run_id": run_id,
                "org": organization_id,
                "scope_hash": scope_hash,
            },
        )
        terminal_rows = (
            {
                "execution_id": "deterministic-0017",
                "agent_role": "documentation",
                "status": "succeeded",
                "provider": "internal",
                "model": "deterministic-template-v1",
                "execution_mode": "deterministic",
                "returned_model": None,
                "upstream_provider": None,
                "provider_request_id": None,
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": None,
                "measured_cost": "0",
                "configuration_set_sha256": None,
                "role_configuration_sha256": None,
                "generation_policy_sha256": None,
                "physical_attempts": None,
                "error_code": None,
            },
            {
                "execution_id": "hosted-one-0017",
                "agent_role": "orchestrator",
                "status": "succeeded",
                "provider": "openrouter",
                "model": "anthropic/claude-opus-4.8",
                "execution_mode": "hosted_advisory",
                "returned_model": "anthropic/claude-opus-4.8",
                "upstream_provider": "Anthropic",
                "provider_request_id": "provider-one-0017",
                "input_tokens": 10,
                "output_tokens": 4,
                "reasoning_tokens": 2,
                "measured_cost": "0.100000000000",
                "configuration_set_sha256": "a" * 64,
                "role_configuration_sha256": "b" * 64,
                "generation_policy_sha256": "c" * 64,
                "physical_attempts": 1,
                "error_code": None,
            },
            {
                "execution_id": "hosted-multi-0017",
                "agent_role": "red_team",
                "status": "succeeded",
                "provider": "openrouter",
                "model": "qwen/qwen3.5-397b-a17b",
                "execution_mode": "hosted_advisory",
                "returned_model": "qwen/qwen3.5-397b-a17b",
                "upstream_provider": "Together",
                "provider_request_id": "provider-multi-0017",
                "input_tokens": 20,
                "output_tokens": 8,
                "reasoning_tokens": 4,
                "measured_cost": "0.200000000000",
                "configuration_set_sha256": "d" * 64,
                "role_configuration_sha256": "e" * 64,
                "generation_policy_sha256": "f" * 64,
                "physical_attempts": 2,
                "error_code": None,
            },
            {
                "execution_id": "hosted-unobserved-0017",
                "agent_role": "documentation",
                "status": "failed",
                "provider": "openrouter",
                "model": "openai/gpt-5.4",
                "execution_mode": "hosted_advisory",
                "returned_model": None,
                "upstream_provider": None,
                "provider_request_id": None,
                "input_tokens": None,
                "output_tokens": None,
                "reasoning_tokens": None,
                "measured_cost": "0",
                "configuration_set_sha256": "1" * 64,
                "role_configuration_sha256": "2" * 64,
                "generation_policy_sha256": "3" * 64,
                "physical_attempts": 1,
                "error_code": "provider_timeout",
            },
            {
                "execution_id": "hosted-cost-only-0017",
                "agent_role": "documentation",
                "status": "failed",
                "provider": "openrouter",
                "model": "openai/gpt-5.4",
                "execution_mode": "hosted_advisory",
                "returned_model": None,
                "upstream_provider": None,
                "provider_request_id": None,
                "input_tokens": None,
                "output_tokens": None,
                "reasoning_tokens": None,
                "measured_cost": "0.300000000000",
                "configuration_set_sha256": "1" * 64,
                "role_configuration_sha256": "2" * 64,
                "generation_policy_sha256": "3" * 64,
                "physical_attempts": 1,
                "error_code": "hosted-provider-unavailable",
            },
            {
                "execution_id": "hosted-cost-only-no-count-0017",
                "agent_role": "documentation",
                "status": "failed",
                "provider": "openrouter",
                "model": "openai/gpt-5.4",
                "execution_mode": "hosted_advisory",
                "returned_model": None,
                "upstream_provider": None,
                "provider_request_id": None,
                "input_tokens": None,
                "output_tokens": None,
                "reasoning_tokens": None,
                "measured_cost": "0.400000000000",
                "configuration_set_sha256": "1" * 64,
                "role_configuration_sha256": "2" * 64,
                "generation_policy_sha256": "3" * 64,
                "physical_attempts": None,
                "error_code": "hosted-provider-unavailable",
            },
            {
                "execution_id": "hosted-max-identity-0017",
                "agent_role": "red_team",
                "status": "failed",
                "provider": "openrouter",
                "model": "m" * 160,
                "execution_mode": "hosted_advisory",
                "returned_model": "m" * 160,
                "upstream_provider": "U" * 64,
                "provider_request_id": "r" * 256,
                "input_tokens": 1,
                "output_tokens": 2,
                "reasoning_tokens": 3,
                "measured_cost": "0.500000000000",
                "configuration_set_sha256": "d" * 64,
                "role_configuration_sha256": "e" * 64,
                "generation_policy_sha256": "f" * 64,
                "physical_attempts": 1,
                "error_code": "hosted-provider-unavailable",
            },
            {
                "execution_id": "hosted-secret-identity-0017",
                "agent_role": "red_team",
                "status": "failed",
                "provider": _SYNTHETIC_SECRET_PROVIDER,
                "model": _SYNTHETIC_SECRET_MODEL,
                "execution_mode": "hosted_advisory",
                "returned_model": _SYNTHETIC_SECRET_MODEL,
                "upstream_provider": _SYNTHETIC_SECRET_UPSTREAM,
                "provider_request_id": _SYNTHETIC_SECRET_REQUEST_ID,
                "input_tokens": 9,
                "output_tokens": 4,
                "reasoning_tokens": 1,
                "measured_cost": "0.600000000000",
                "configuration_set_sha256": "4" * 64,
                "role_configuration_sha256": "5" * 64,
                "generation_policy_sha256": "6" * 64,
                "physical_attempts": 1,
                "error_code": "hosted-provider-unavailable",
            },
        )
        insert_terminal = text(
            "INSERT INTO agent_executions "
            "(execution_id, organization_id, campaign_run_id, agent_role, status, "
            "provider, model, execution_mode, configuration_version, input_sha256, "
            "output_sha256, returned_model, upstream_provider, provider_request_id, "
            "input_tokens, output_tokens, reasoning_tokens, measured_cost, trace_id, "
            "configuration_set_sha256, role_configuration_sha256, "
            "generation_policy_sha256, physical_attempts, detail, error_code, "
            "finished_at, duration_ms) VALUES "
            "(:execution_id, :org, :run_id, :agent_role, :status, :provider, :model, "
            ":execution_mode, 1, :input_sha256, :output_sha256, :returned_model, "
            ":upstream_provider, :provider_request_id, :input_tokens, :output_tokens, "
            ":reasoning_tokens, :measured_cost, :trace_id, :configuration_set_sha256, "
            ":role_configuration_sha256, :generation_policy_sha256, :physical_attempts, "
            '\'{"fixture":"populated-0017"}\'::jsonb, :error_code, '
            "clock_timestamp(), 5)"
        )
        for index, row in enumerate(terminal_rows, start=1):
            connection.execute(
                insert_terminal,
                {
                    **row,
                    "org": organization_id,
                    "run_id": run_id,
                    "input_sha256": f"{index:x}" * 64,
                    "output_sha256": f"{index + 4:x}" * 64,
                    "trace_id": f"{index:x}" * 32,
                },
            )
        if include_running:
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, agent_role, "
                    "provider, model, execution_mode, configuration_version, input_sha256, "
                    "trace_id, configuration_set_sha256, role_configuration_sha256, "
                    "generation_policy_sha256) VALUES "
                    "('hosted-running-0017', :org, :run_id, 'orchestrator', "
                    "'openrouter', 'anthropic/claude-opus-4.8', 'hosted_advisory', 1, "
                    ":input_sha256, :trace_id, :configuration, :role_configuration, "
                    ":generation_policy)"
                ),
                {
                    "org": organization_id,
                    "run_id": run_id,
                    "input_sha256": "8" * 64,
                    "trace_id": "8" * 32,
                    "configuration": "a" * 64,
                    "role_configuration": "b" * 64,
                    "generation_policy": "c" * 64,
                },
            )


def test_shared_campaign_traces_survive_0016_downgrade_and_reupgrade(
    admin_url: str,
) -> None:
    database_name = f"agentforge_langfuse_migration_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(database_url, "0016")
        engine = _db.build_engine(database_url)
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            for request_id in ("request-shared-trace-a", "request-shared-trace-b"):
                connection.execute(
                    text(
                        "INSERT INTO outbound_http_requests "
                        "(request_id, organization_id, campaign_run_id, attempt_id, trace_id, "
                        "operation, provider, method, destination_host, relative_path, "
                        "request_payload, request_bytes, measured_cost) VALUES "
                        "(:request_id, 'org-migration', 'run-migration', :request_id, "
                        "'11111111111111111111111111111111', 'target.http', 'target', 'POST', "
                        "'target.example.test', 'chat', '{}'::jsonb, 2, 0)"
                    ),
                    {"request_id": request_id},
                )

        _db.alembic_downgrade(database_url, "0015")
        with engine.begin() as connection:
            # Revision 0015 used this value for a non-raising SDK flush, which is not remote
            # delivery proof. Re-upgrade must conservatively return it to the verification queue.
            connection.execute(
                text(
                    "UPDATE outbound_http_requests SET langfuse_status = 'exported' "
                    "WHERE request_id = 'request-shared-trace-a'"
                )
            )
        with engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT request_id, trace_id FROM outbound_http_requests "
                        "ORDER BY request_id"
                    )
                )
                .mappings()
                .all()
            )
            assert len(rows) == 2
            assert len({row["trace_id"] for row in rows}) == 2
            assert all(len(row["trace_id"]) == 32 for row in rows)
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE (table_name = 'agent_executions' "
                        "AND column_name IN ('langfuse_status','langfuse_verified_at')) "
                        "OR (table_name = 'outbound_http_requests' "
                        "AND column_name = 'langfuse_verified_at')"
                    )
                ).scalar_one()
                == 0
            )

        _db.alembic_upgrade(database_url, "0016")
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT count(*) FROM outbound_http_requests")).scalar_one()
                == 2
            )
            assert (
                connection.execute(
                    text(
                        "SELECT langfuse_status FROM outbound_http_requests "
                        "WHERE request_id = 'request-shared-trace-a'"
                    )
                ).scalar_one()
                == "queued"
            )
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_hosted_agent_lineage_columns_survive_0017_round_trip(admin_url: str) -> None:
    database_name = f"agentforge_hosted_lineage_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    lineage_columns = (
        "returned_model",
        "upstream_provider",
        "provider_request_id",
        "reasoning_tokens",
        "configuration_set_sha256",
        "role_configuration_sha256",
        "generation_policy_sha256",
        "physical_attempts",
        "judge_calibration_id",
        "judge_calibration_state",
        "oracle_agreement",
        "decision_authority",
    )
    try:
        _db.alembic_upgrade(database_url, "0017")
        engine = _db.build_engine(database_url)
        with engine.connect() as connection:
            columns = set(
                connection.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'agent_executions' "
                        "AND column_name = ANY(:columns)"
                    ),
                    {"columns": list(lineage_columns)},
                ).scalars()
            )
            cost_shape = connection.execute(
                text(
                    "SELECT numeric_precision, numeric_scale "
                    "FROM information_schema.columns "
                    "WHERE table_name = 'agent_executions' "
                    "AND column_name = 'measured_cost'"
                )
            ).one()
        assert columns == set(lineage_columns)
        assert cost_shape == (20, 12)

        _db.alembic_downgrade(database_url, "0016")
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_name = 'agent_executions' "
                        "AND column_name = ANY(:columns)"
                    ),
                    {"columns": list(lineage_columns)},
                ).scalar_one()
                == 0
            )
            assert connection.execute(
                text(
                    "SELECT numeric_precision, numeric_scale "
                    "FROM information_schema.columns "
                    "WHERE table_name = 'agent_executions' "
                    "AND column_name = 'measured_cost'"
                )
            ).one() == (14, 6)

        _db.alembic_upgrade(database_url, "0017")
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_populated_0017_upgrade_exposes_truthful_historical_provider_lineage(
    admin_url: str,
) -> None:
    database_name = f"agentforge_provider_backfill_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    organization_id = "org_populated_0017"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(database_url, "0017")
        engine = _db.build_engine(database_url)
        _seed_0017_agent_rows(engine, organization_id=organization_id)

        _db.alembic_upgrade(database_url, "0019")
        with engine.connect() as connection:
            rows = {
                row["execution_id"]: row
                for row in connection.execute(
                    text(
                        "SELECT execution_id, measured_cost, cost_measurement_state, "
                        "physical_attempts, provider_event_ids, provider_event_status, "
                        "provider, model, returned_model, upstream_provider, "
                        "provider_request_id, input_tokens, output_tokens, "
                        "reasoning_tokens, detail "
                        "FROM agent_executions WHERE organization_id = :org"
                    ),
                    {"org": organization_id},
                )
                .mappings()
                .all()
            }
        assert rows["deterministic-0017"]["cost_measurement_state"] == "measured"
        assert rows["deterministic-0017"]["measured_cost"] == 0
        assert "provider_lineage_state" not in rows["deterministic-0017"]["detail"]
        for execution_id, amount, attempts in (
            ("hosted-one-0017", "0.100000000000", 1),
            ("hosted-multi-0017", "0.200000000000", 2),
        ):
            row = rows[execution_id]
            assert format(row["measured_cost"], "f") == amount
            assert row["cost_measurement_state"] == "partial"
            assert row["physical_attempts"] == attempts
            assert row["provider_event_ids"] == []
            assert row["detail"]["provider_lineage_state"] == "historical_not_instrumented"
            assert row["provider_event_status"] is None
        unobserved = rows["hosted-unobserved-0017"]
        assert unobserved["measured_cost"] is None
        assert unobserved["cost_measurement_state"] == "not_observed"
        assert unobserved["physical_attempts"] == 1
        assert unobserved["provider_event_ids"] == []
        assert unobserved["provider_event_status"] is None
        for execution_id, amount, attempts in (
            ("hosted-cost-only-0017", "0.300000000000", 1),
            ("hosted-cost-only-no-count-0017", "0.400000000000", None),
        ):
            row = rows[execution_id]
            assert format(row["measured_cost"], "f") == amount
            assert row["cost_measurement_state"] == "partial"
            assert row["physical_attempts"] == attempts
            assert row["provider_event_ids"] == []
            assert row["detail"]["provider_lineage_state"] == "historical_not_instrumented"
            assert row["provider_event_status"] is None

        secret_identity = rows["hosted-secret-identity-0017"]
        assert secret_identity["provider"] == "redacted"
        assert secret_identity["model"] == "unsafe-provider-text-redacted"
        assert secret_identity["returned_model"] is None
        assert secret_identity["upstream_provider"] is None
        assert secret_identity["provider_request_id"] is None
        assert secret_identity["input_tokens"] == 9
        assert secret_identity["output_tokens"] == 4
        assert secret_identity["reasoning_tokens"] == 1
        assert secret_identity["measured_cost"] == Decimal("0.600000000000")
        assert secret_identity["cost_measurement_state"] == "partial"
        assert secret_identity["physical_attempts"] == 1
        assert secret_identity["provider_event_ids"] == []
        assert secret_identity["provider_event_status"] is None
        assert secret_identity["detail"]["provider_identity_redacted"] is True

        # Exercise the complete populated deployment path before current-head
        # read models query columns introduced by 0020.
        _db.alembic_upgrade(database_url, "0020")
        principal = Principal(
            user_id="user_migration",
            session_id="sess_migration",
            organization_id=organization_id,
            organization_role="org:operator",
            organization_permissions=frozenset(),
        )
        backend = PostgresApiBackend(engine, environment="staging")
        activity = backend.read("agent_activity", principal)
        traces = backend.read("traces", principal)
        costs = backend.read("costs", principal)
        assert activity.state == traces.state == costs.state == "ready"
        activity_by_id = {row["execution_id"]: row for row in activity.data}
        trace_by_id = {
            row["execution_id"]: row for row in traces.data if row["execution_id"] is not None
        }
        assert (
            activity_by_id["hosted-multi-0017"]["provider_lineage_state"]
            == "historical_not_instrumented"
        )
        assert (
            trace_by_id["hosted-multi-0017"]["provider_lineage_state"]
            == "historical_not_instrumented"
        )
        assert activity_by_id["hosted-multi-0017"]["provider_event_ids"] == []
        assert trace_by_id["hosted-multi-0017"]["provider_event_ids"] == []
        rendered_read_models = json.dumps(
            {
                "activity": activity.data,
                "traces": traces.data,
                "costs": costs.data,
            },
            default=str,
        )
        for synthetic_secret in (
            _SYNTHETIC_SECRET_PROVIDER,
            _SYNTHETIC_SECRET_MODEL,
            _SYNTHETIC_SECRET_UPSTREAM,
            _SYNTHETIC_SECRET_REQUEST_ID,
        ):
            assert synthetic_secret not in rendered_read_models
        for execution_id in (
            "hosted-cost-only-0017",
            "hosted-cost-only-no-count-0017",
        ):
            assert activity_by_id[execution_id]["accounting_status"] == "partial"
            assert trace_by_id[execution_id]["accounting_status"] == "partial"
        assert activity_by_id["deterministic-0017"]["provider_lineage_state"] == "not_applicable"
        red_team_cost = next(
            row
            for row in costs.data
            if row["agent_role"] == "red_team"
            and row["provider"].endswith("qwen/qwen3.5-397b-a17b")
        )
        assert red_team_cost["cost_measurement_state"] == "partial"
        assert red_team_cost["accounting_status"] == "partial"
        assert red_team_cost["measured_cost"] == 0.2
        assert red_team_cost["physical_call_count"] == 2
        assert red_team_cost["provider_event_ids"] == []

        _db.alembic_downgrade(database_url, "0017")
        with engine.connect() as connection:
            downgraded = connection.execute(
                text(
                    "SELECT returned_model, upstream_provider, provider_request_id, "
                    "measured_cost FROM agent_executions "
                    "WHERE execution_id = 'hosted-max-identity-0017'"
                )
            ).one()
            preserved_costs = dict(
                connection.execute(
                    text(
                        "SELECT execution_id, measured_cost FROM agent_executions "
                        "WHERE execution_id IN "
                        "('hosted-cost-only-0017','hosted-cost-only-no-count-0017')"
                    )
                ).all()
            )
        assert downgraded == ("m" * 160, "U" * 64, "r" * 256, Decimal("0.500000000000"))
        assert preserved_costs == {
            "hosted-cost-only-0017": Decimal("0.300000000000"),
            "hosted-cost-only-no-count-0017": Decimal("0.400000000000"),
        }

        _db.alembic_upgrade(database_url, "0019")
        with engine.connect() as connection:
            reupgraded = connection.execute(
                text(
                    "SELECT returned_model, upstream_provider, provider_request_id, "
                    "measured_cost, cost_measurement_state "
                    "FROM agent_executions "
                    "WHERE execution_id = 'hosted-max-identity-0017'"
                )
            ).one()
        assert reupgraded == (
            "m" * 160,
            "U" * 64,
            "r" * 256,
            Decimal("0.500000000000"),
            "partial",
        )
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_0018_refuses_to_upgrade_while_a_hosted_execution_is_running(
    admin_url: str,
) -> None:
    database_name = f"agentforge_provider_quiescence_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(database_url, "0017")
        engine = _db.build_engine(database_url)
        _seed_0017_agent_rows(
            engine,
            organization_id="org_running_0017",
            include_running=True,
        )
        with pytest.raises(Exception, match="zero running hosted agent executions"):
            _db.alembic_upgrade(database_url, "0018")
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0017"
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM agent_executions "
                        "WHERE execution_id = 'hosted-running-0017' AND status = 'running'"
                    )
                ).scalar_one()
                == 1
            )
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_0019_records_failed_substitution_and_preserves_physical_truth_on_rollback(
    admin_url: str,
) -> None:
    database_name = f"agentforge_provider_identity_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    event_id = "1" * 64
    invocation_id = "2" * 64
    requested_model = "google/gemini-2.5-pro"
    returned_model = "google/gemini-flash"
    try:
        _db.alembic_upgrade(database_url, "0018")
        engine = _db.build_engine(database_url)
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(
                text(
                    "INSERT INTO campaign_authorization_requests "
                    "(request_id, organization_id, scope_hash, scope_payload, "
                    "launcher_user_id, launcher_session_id, expires_at) VALUES "
                    "('request-identity', 'org-identity', :scope_hash, '{}'::jsonb, "
                    "'user_identity', 'sess_identity', clock_timestamp() + interval '1 day')"
                ),
                {"scope_hash": "9" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_runs "
                    "(run_id, organization_id, authorization_request_id, scope_hash, "
                    "launcher_user_id, launcher_session_id) VALUES "
                    "('run-identity', 'org-identity', 'request-identity', :scope_hash, "
                    "'user_identity', 'sess_identity')"
                ),
                {"scope_hash": "9" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, agent_role, status, "
                    "provider, model, execution_mode, configuration_version, input_sha256, "
                    "output_sha256, returned_model, upstream_provider, provider_request_id, "
                    "input_tokens, output_tokens, reasoning_tokens, physical_attempts, "
                    "measured_cost, cost_measurement_state, provider_event_ids, "
                    "provider_event_status, trace_id, "
                    "configuration_set_sha256, role_configuration_sha256, "
                    "generation_policy_sha256, detail, error_code, finished_at, duration_ms) "
                    "VALUES ('execution-identity', 'org-identity', 'run-identity', "
                    "'documentation', 'failed', 'openrouter', :requested_model, "
                    "'hosted_advisory', 1, :input_sha, :output_sha, :requested_model, "
                    "'Google', 'provider-identity', 30, 5, 5, 1, "
                    "0.000065, 'measured', CAST(:event_ids AS jsonb), 'model_mismatch', :trace_id, "
                    ":configuration, :role_configuration, :generation_policy, "
                    '\'{"provider_lineage_state":"canonical_physical"}\'::jsonb, '
                    "'provider-model-substituted', clock_timestamp(), 5)"
                ),
                {
                    "requested_model": requested_model,
                    "input_sha": "3" * 64,
                    "output_sha": "4" * 64,
                    "event_ids": json.dumps([event_id]),
                    "trace_id": "5" * 32,
                    "configuration": "6" * 64,
                    "role_configuration": "7" * 64,
                    "generation_policy": "8" * 64,
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
                    "(:invocation, 'org-identity', 'run-identity', NULL, "
                    "'execution-identity', NULL, 'documentation', 1, :idempotency, "
                    ":requested_model, 'google-vertex', 'v1', :prompt_sha, "
                    ":configuration, :role_configuration, :generation_policy, "
                    "clock_timestamp() - interval '5 milliseconds')"
                ),
                {
                    "invocation": invocation_id,
                    "idempotency": f"provider-call:{invocation_id}",
                    "requested_model": requested_model,
                    "prompt_sha": "a" * 64,
                    "configuration": "6" * 64,
                    "role_configuration": "7" * 64,
                    "generation_policy": "8" * 64,
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
                    "(:event, :invocation, 'org-identity', 'run-identity', NULL, "
                    "'execution-identity', 'documentation', 1, 'model_mismatch', "
                    ":returned_model, 'Google', 'provider-identity', 30, 5, 5, "
                    "'measured', 0.000065, 'returned_model_mismatch', "
                    "clock_timestamp(), 5)"
                ),
                {
                    "event": event_id,
                    "invocation": invocation_id,
                    "returned_model": returned_model,
                },
            )

        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE agent_executions SET returned_model = :returned "
                    "WHERE execution_id = 'execution-identity'"
                ),
                {"returned": returned_model},
            )

        _db.alembic_upgrade(database_url, "0019")
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE agent_executions SET returned_model = :returned "
                    "WHERE execution_id = 'execution-identity'"
                ),
                {"returned": returned_model},
            )
        with pytest.raises(IntegrityError), engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE agent_executions SET status = 'succeeded' "
                    "WHERE execution_id = 'execution-identity'"
                )
            )

        _db.alembic_downgrade(database_url, "0018")
        with engine.connect() as connection:
            logical = connection.execute(
                text(
                    "SELECT returned_model, upstream_provider, provider_request_id, "
                    "input_tokens, output_tokens, reasoning_tokens, physical_attempts, "
                    "provider_event_ids, provider_event_status, measured_cost, "
                    "cost_measurement_state "
                    "FROM agent_executions WHERE execution_id = 'execution-identity'"
                )
            ).one()
            physical = connection.execute(
                text(
                    "SELECT status, returned_model, measured_cost_usd "
                    "FROM provider_call_events WHERE event_id = :event"
                ),
                {"event": event_id},
            ).one()
        assert logical == (
            None,
            None,
            None,
            None,
            None,
            None,
            1,
            [event_id],
            "model_mismatch",
            Decimal("0.000065000000"),
            "measured",
        )
        assert physical == (
            "model_mismatch",
            returned_model,
            Decimal("0.000065000000"),
        )

        _db.alembic_upgrade(database_url, "0019")
        with engine.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT physical_attempts, provider_event_ids, measured_cost, "
                    "provider_event_status, cost_measurement_state FROM agent_executions "
                    "WHERE execution_id = 'execution-identity'"
                )
            ).one() == (
                1,
                [event_id],
                Decimal("0.000065000000"),
                "model_mismatch",
                "measured",
            )

        _db.alembic_downgrade(database_url, "0017")
        _db.alembic_upgrade(database_url, "0019")
        with engine.connect() as connection:
            reupgraded = connection.execute(
                text(
                    "SELECT detail->>'provider_lineage_state', physical_attempts, "
                    "provider_event_ids, provider_event_status, measured_cost, "
                    "cost_measurement_state "
                    "FROM agent_executions WHERE execution_id = 'execution-identity'"
                )
            ).one()
        assert reupgraded == (
            "historical_not_instrumented",
            1,
            [],
            None,
            Decimal("0.000065000000"),
            "partial",
        )
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_physical_provider_lineage_survives_0018_round_trip(
    admin_url: str,
) -> None:
    database_name = f"agentforge_provider_lineage_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(database_url, "0018")
        engine = _db.build_engine(database_url)
        with engine.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(
                text(
                    "INSERT INTO campaign_authorization_requests "
                    "(request_id, organization_id, scope_hash, scope_payload, "
                    "launcher_user_id, launcher_session_id, expires_at) VALUES "
                    "('request-roundtrip', 'org-roundtrip', :scope_hash, '{}'::jsonb, "
                    "'user_roundtrip', 'sess_roundtrip', "
                    "clock_timestamp() + interval '1 day')"
                ),
                {"scope_hash": "9" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO campaign_runs "
                    "(run_id, organization_id, authorization_request_id, scope_hash, "
                    "launcher_user_id, launcher_session_id) VALUES "
                    "('run-roundtrip', 'org-roundtrip', 'request-roundtrip', :scope_hash, "
                    "'user_roundtrip', 'sess_roundtrip')"
                ),
                {"scope_hash": "9" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, agent_role, status, "
                    "provider, model, execution_mode, configuration_version, input_sha256, "
                    "output_sha256, measured_cost, cost_measurement_state, "
                    "provider_event_ids, trace_id, configuration_set_sha256, "
                    "role_configuration_sha256, generation_policy_sha256, detail, "
                    "error_code, finished_at, duration_ms) VALUES "
                    "('canonical-roundtrip', 'org-roundtrip', 'run-roundtrip', "
                    "'orchestrator', 'failed', 'openrouter', "
                    "'anthropic/claude-opus-4.8', 'hosted_advisory', 1, :input_sha256, "
                    ":output_sha256, NULL, 'not_observed', '[]'::jsonb, :trace_id, "
                    ":configuration, :role_configuration, :generation_policy, "
                    '\'{"provider_lineage_state":"canonical_physical"}\'::jsonb, '
                    "'provider_invocation_not_started', clock_timestamp(), 1)"
                ),
                {
                    "input_sha256": "a" * 64,
                    "output_sha256": "b" * 64,
                    "trace_id": "c" * 32,
                    "configuration": "d" * 64,
                    "role_configuration": "e" * 64,
                    "generation_policy": "f" * 64,
                },
            )
        with engine.connect() as connection:
            tables = set(
                connection.execute(
                    text(
                        "SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema = 'public' "
                        "AND table_name = ANY(:tables)"
                    ),
                    {
                        "tables": [
                            "provider_call_invocations",
                            "provider_call_events",
                        ]
                    },
                ).scalars()
            )
            attempt_nullable = connection.execute(
                text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_name = 'provider_call_invocations' "
                    "AND column_name = 'campaign_attempt_id'"
                )
            ).scalar_one()
            event_cost_shape = connection.execute(
                text(
                    "SELECT numeric_precision, numeric_scale "
                    "FROM information_schema.columns "
                    "WHERE table_name = 'provider_call_events' "
                    "AND column_name = 'measured_cost_usd'"
                )
            ).one()
            logical_identity_lengths = dict(
                connection.execute(
                    text(
                        "SELECT column_name, character_maximum_length "
                        "FROM information_schema.columns "
                        "WHERE table_name = 'agent_executions' "
                        "AND column_name = ANY(:columns)"
                    ),
                    {"columns": ["returned_model", "upstream_provider"]},
                ).all()
            )
        assert tables == {
            "provider_call_invocations",
            "provider_call_events",
        }
        assert attempt_nullable == "YES"
        assert event_cost_shape == (20, 12)
        assert logical_identity_lengths == {
            "returned_model": 192,
            "upstream_provider": 128,
        }

        _db.alembic_downgrade(database_url, "0017")
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM information_schema.tables "
                        "WHERE table_schema = 'public' "
                        "AND table_name = ANY(:tables)"
                    ),
                    {
                        "tables": [
                            "provider_call_invocations",
                            "provider_call_events",
                        ]
                    },
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM information_schema.columns "
                        "WHERE table_name = 'agent_executions' "
                        "AND column_name = ANY(:columns)"
                    ),
                    {
                        "columns": [
                            "cost_measurement_state",
                            "provider_event_ids",
                            "provider_event_status",
                        ]
                    },
                ).scalar_one()
                == 0
            )
            assert (
                connection.execute(
                    text(
                        "SELECT detail ? 'provider_lineage_state' FROM agent_executions "
                        "WHERE execution_id = 'canonical-roundtrip'"
                    )
                ).scalar_one()
                is False
            )
        _db.alembic_upgrade(database_url, "0018")
        with engine.connect() as connection:
            roundtrip = connection.execute(
                text(
                    "SELECT detail->>'provider_lineage_state', cost_measurement_state, "
                    "provider_event_ids FROM agent_executions "
                    "WHERE execution_id = 'canonical-roundtrip'"
                )
            ).one()
        assert roundtrip == ("historical_not_instrumented", "not_observed", [])
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)
