"""Runner-before-Web rollout gate stays inert until the packaged Alembic head exists."""

from __future__ import annotations

import uuid

from sqlalchemy import Engine, text

import _db
from agentforge.runner import DurableCampaignRunner, check_runtime


class _NoIoTelemetry:
    def __init__(self) -> None:
        self.heartbeat_calls = 0

    def heartbeat(self, **_values: object) -> None:
        self.heartbeat_calls += 1


def test_runner_on_0017_never_claims_or_mutates_queued_work(
    admin_url: str,
    monkeypatch,
    tmp_path,
) -> None:
    database_name = f"agentforge_runner_schema_gate_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(database_url, "0017")
        engine = _db.build_engine(database_url)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO jobs "
                    "(job_id, queue, campaign_run_id, attempt_id, payload_schema, "
                    "payload_version, payload, enqueue_fingerprint, max_attempts) VALUES "
                    "('schema-gate-job', 'agent_work', 'schema-gate-run', "
                    "'schema-gate-attempt', 'agent-work-v1', 1, "
                    '\'{"fixture":"synthetic"}\'::jsonb, :fingerprint, 3)'
                ),
                {"fingerprint": "f" * 64},
            )
        with engine.connect() as connection:
            before = dict(
                connection.execute(text("SELECT * FROM jobs WHERE job_id = 'schema-gate-job'"))
                .mappings()
                .one()
            )

        telemetry = _NoIoTelemetry()
        runner = DurableCampaignRunner(
            engine=engine,
            environment="staging",
            manifest_root=tmp_path,
            telemetry=telemetry,  # type: ignore[arg-type]
        )
        runner.queue.claim = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
            AssertionError("schema-skewed Runner must not claim")
        )
        runner.recover_interrupted_provider_calls = (  # type: ignore[method-assign]
            lambda **_kwargs: (_ for _ in ()).throw(
                AssertionError("schema-skewed Runner must not recover provider work")
            )
        )

        assert runner.run_once(worker_id="runner-schema-gate") is False
        runner.heartbeat_runtime(force_connection_check=True)
        monkeypatch.setenv("AGENTFORGE_ENVIRONMENT", "staging")
        assert check_runtime(database_url) is False
        assert telemetry.heartbeat_calls == 0

        with engine.connect() as connection:
            after = dict(
                connection.execute(text("SELECT * FROM jobs WHERE job_id = 'schema-gate-job'"))
                .mappings()
                .one()
            )
            assert (
                connection.execute(
                    text(
                        "SELECT count(*) FROM campaign_run_events WHERE run_id = 'schema-gate-run'"
                    )
                ).scalar_one()
                == 0
            )
        assert after == before
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)
