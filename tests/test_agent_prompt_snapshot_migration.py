"""Expand/contract and privilege contract for immutable prompt snapshots."""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text

import _db


@pytest.fixture
def prompt_snapshot_revision_db() -> Iterator[tuple[str, Engine]]:
    admin = _db.admin_url()
    database = f"agentforge_prompt_snapshot_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin)
    url = f"{base}/{database}"
    _db.create_fresh_database(admin, database)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(url, "0025")
        engine = _db.build_engine(url)
        yield url, engine
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin, database)


def _table_exists(engine: Engine) -> bool:
    with engine.connect() as connection:
        return bool(
            connection.execute(
                text("SELECT to_regclass('public.agent_prompt_snapshots') IS NOT NULL")
            ).scalar_one()
        )


def test_0027_is_expand_only_protected_and_round_trips(
    prompt_snapshot_revision_db: tuple[str, Engine],
) -> None:
    url, engine = prompt_snapshot_revision_db
    with engine.connect() as connection:
        tables_before = {
            str(row[0])
            for row in connection.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                )
            )
        }
    assert "agent_prompt_snapshots" not in tables_before

    engine.dispose()
    _db.alembic_upgrade(url, "0027")
    engine = _db.build_engine(url)
    assert _table_exists(engine)
    with engine.connect() as connection:
        revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        grants = {
            (str(row[0]), str(row[1]))
            for row in connection.execute(
                text(
                    "SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'public' AND table_name = 'agent_prompt_snapshots' "
                    "AND grantee LIKE 'headshot_%'"
                )
            )
        }
        tables_after = {
            str(row[0])
            for row in connection.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                )
            )
        }
    assert revision == "0027"
    assert tables_after == tables_before | {"agent_prompt_snapshots"}
    assert grants == {
        ("headshot_runner", "INSERT"),
        ("headshot_runner", "SELECT"),
        ("headshot_web", "SELECT"),
    }

    engine.dispose()
    _db.alembic_downgrade(url, "0026")
    engine = _db.build_engine(url)
    assert not _table_exists(engine)
    with engine.connect() as connection:
        tables_after_downgrade = {
            str(row[0])
            for row in connection.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                )
            )
        }
    assert tables_after_downgrade == tables_before
