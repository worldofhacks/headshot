"""The Langfuse delivery migration preserves requests across a rollback round trip."""

from __future__ import annotations

import uuid

from sqlalchemy import Engine, text

import _db


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
                        ]
                    },
                ).scalar_one()
                == 0
            )
        _db.alembic_upgrade(database_url, "0018")
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)
