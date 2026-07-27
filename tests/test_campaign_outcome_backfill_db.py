"""Migration 0026 recovers historical outcome counts instead of asserting zero.

A completed campaign summary written before 0026 has no decisive/indeterminate/operational-error
counts. Defaulting them to 0 would be worse than leaving them empty: it asserts that the run
adjudicated nothing decisively, and a reader cannot distinguish that claim from "these counts were
never computed". Both readings look identical, and one of them is false.

So the migration backfills from the durable ``verdict`` rows where they still exist, and leaves
NULL — meaning "not available for this historical run" — where they do not.

These tests seed a real pre-0026 database, upgrade across the boundary, and assert both halves.
"""

from __future__ import annotations

import datetime
import uuid

import pytest
from sqlalchemy import text

import _db  # type: ignore[import-not-found]

_ORG = "org_BackfillProof"


def _seed_pre_0026(engine, *, run_id: str, attempts: int, verdicts: list[str]) -> None:
    """Write a completed summary plus its verdicts using only pre-0026 columns.

    ``session_replication_role = replica`` suspends the two-person-control and append-only
    triggers for this seed. That is legitimate here and nowhere else: these rows stand in for
    history that WAS written through the governed path on an earlier release, and the subject of
    the test is what the migration does to such rows — not whether they could be created today.
    Reconstructing a full authorization handshake would exercise the control plane, not the
    backfill. The triggers are restored as soon as the transaction ends.
    """

    now = datetime.datetime.now(datetime.UTC)
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_runs (organization_id, run_id, created_at, run_kind, "
                "authorization_request_id, scope_hash, launcher_user_id, launcher_session_id) "
                "VALUES (:org, :run, :now, 'campaign', :req, :scope, :user, :sess) "
                "ON CONFLICT DO NOTHING"
            ),
            {
                "org": _ORG,
                "run": run_id,
                "now": now,
                "req": f"req-{run_id}",
                "scope": "a" * 64,
                "user": "user_HistoricalLauncher",
                "sess": "sess_HistoricalLauncher",
            },
        )
        for index, state in enumerate(verdicts):
            connection.execute(
                text(
                    "INSERT INTO verdict (organization_id, campaign_run_id, attempt_id, state, "
                    "confidence, reason_codes, created_at) "
                    "VALUES (:org, :run, :attempt, :state, 0.0, "
                    ":reasons ::jsonb, :now)"
                ),
                {
                    "org": _ORG,
                    "run": run_id,
                    "attempt": f"{run_id}-attempt-{index}",
                    "state": state,
                    "reasons": '["non_oracle_uncalibrated_indeterminate"]',
                    "now": now,
                },
            )
        connection.execute(
            text(
                "INSERT INTO campaign_run_summaries "
                "(organization_id, run_id, execution_profile, provenance, attempt_count, "
                "request_count, confirmed_finding_count, measured_cost, started_at, ended_at) "
                "VALUES (:org, :run, 'live', 'live_target', :attempts, :attempts, 0, 0, "
                ":now, :now)"
            ),
            {"org": _ORG, "run": run_id, "attempts": attempts, "now": now},
        )


@pytest.fixture
def upgraded_across_0026():
    """A throwaway database migrated to 0025, seeded, then upgraded to 0026."""

    dbname = f"backfill_{uuid.uuid4().hex[:12]}"
    admin = _db.admin_url()
    url = _db.throwaway_db_url().rsplit("/", 1)[0] + "/" + dbname
    _db.create_fresh_database(admin, dbname)
    engine = None
    try:
        _db.alembic_upgrade(url, "0025")
        engine = _db.build_engine(url)
        yield engine, url
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin, dbname)


def _summary(engine, run_id: str) -> dict:
    with engine.connect() as connection:
        return dict(
            connection.execute(
                text(
                    "SELECT attempt_count, decisive_verdict_count, "
                    "indeterminate_verdict_count, operational_error_count "
                    "FROM campaign_run_summaries WHERE run_id = :run"
                ),
                {"run": run_id},
            )
            .mappings()
            .one()
        )


def test_a_historical_summary_recovers_its_true_counts(upgraded_across_0026) -> None:
    engine, url = upgraded_across_0026
    run_id = "run-with-verdicts-0001"
    _seed_pre_0026(
        engine,
        run_id=run_id,
        attempts=5,
        verdicts=[
            "NO_EXPLOIT_OBSERVED",
            "EXPLOIT_CONFIRMED",
            "INDETERMINATE",
            "INDETERMINATE",
            "ERROR",
        ],
    )

    _db.alembic_upgrade(url, "0026")

    summary = _summary(engine, run_id)
    assert summary["decisive_verdict_count"] == 2, "confirmed + no-exploit-observed"
    assert summary["indeterminate_verdict_count"] == 2
    assert summary["operational_error_count"] == 1
    total = sum(
        summary[key]
        for key in (
            "decisive_verdict_count",
            "indeterminate_verdict_count",
            "operational_error_count",
        )
    )
    assert total == summary["attempt_count"] == 5


def test_a_historical_summary_without_verdicts_stays_unavailable_not_zero(
    upgraded_across_0026,
) -> None:
    """NULL says 'not computed'. Zero would falsely say 'adjudicated nothing'."""

    engine, url = upgraded_across_0026
    run_id = "run-without-verdicts-0002"
    _seed_pre_0026(engine, run_id=run_id, attempts=3, verdicts=[])

    _db.alembic_upgrade(url, "0026")

    summary = _summary(engine, run_id)
    assert summary["decisive_verdict_count"] is None
    assert summary["indeterminate_verdict_count"] is None
    assert summary["operational_error_count"] is None
    assert summary["attempt_count"] == 3


def test_a_new_summary_must_account_for_every_attempt(upgraded_across_0026) -> None:
    """The constraint that stops a run claiming more — or less — evaluation than it performed."""

    engine, url = upgraded_across_0026
    _db.alembic_upgrade(url, "0026")

    now = datetime.datetime.now(datetime.UTC)
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_runs (organization_id, run_id, created_at, run_kind, "
                "authorization_request_id, scope_hash, launcher_user_id, launcher_session_id) "
                "VALUES (:org, 'run-new-0003', :now, 'campaign', 'req-run-new-0003', :scope, "
                "'user_HistoricalLauncher', 'sess_HistoricalLauncher')"
            ),
            {"org": _ORG, "now": now, "scope": "a" * 64},
        )

    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_run_summaries "
                "(organization_id, run_id, execution_profile, provenance, attempt_count, "
                "request_count, confirmed_finding_count, measured_cost, started_at, ended_at, "
                "decisive_verdict_count, indeterminate_verdict_count, operational_error_count) "
                "VALUES (:org, 'run-new-0003', 'live', 'live_target', 10, 10, 0, 0, :now, :now, "
                "1, 1, 1)"
            ),
            {"org": _ORG, "now": now},
        )


def test_counts_may_not_be_negative(upgraded_across_0026) -> None:
    engine, url = upgraded_across_0026
    _db.alembic_upgrade(url, "0026")

    now = datetime.datetime.now(datetime.UTC)
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_runs (organization_id, run_id, created_at, run_kind, "
                "authorization_request_id, scope_hash, launcher_user_id, launcher_session_id) "
                "VALUES (:org, 'run-negative-0004', :now, 'campaign', "
                "'req-run-negative-0004', :scope, "
                "'user_HistoricalLauncher', 'sess_HistoricalLauncher')"
            ),
            {"org": _ORG, "now": now, "scope": "a" * 64},
        )

    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_run_summaries "
                "(organization_id, run_id, execution_profile, provenance, attempt_count, "
                "request_count, confirmed_finding_count, measured_cost, started_at, ended_at, "
                "decisive_verdict_count, indeterminate_verdict_count, operational_error_count) "
                "VALUES (:org, 'run-negative-0004', 'live', 'live_target', 0, 0, 0, 0, "
                ":now, :now, -1, 1, 0)"
            ),
            {"org": _ORG, "now": now},
        )
