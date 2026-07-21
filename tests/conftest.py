"""Shared pytest fixtures for the M2 storage suites.

Test-Agent-owned. Provides the session-scoped ``migrated_db`` fixture: a fresh throwaway
Postgres database (per-PID name), migrated to ``head`` via Alembic, yielded as a SQLAlchemy
Engine and dropped at teardown. See ``tests/_db.py`` for the mechanics and the loud
"start Postgres" failure when the cluster is unreachable (no silent skip — S1/S2 must run).

The M2 storage code + migrations do not exist yet, so ``alembic upgrade head`` here raises
at first use and every DB-backed test in the three M2 suites goes RED for the right reason.
Non-M2 suites do not request ``migrated_db`` and are untouched.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine

import _db


@pytest.fixture(scope="session")
def admin_url() -> str:
    """The admin/superuser SQLAlchemy URL (env DATABASE_URL translated, else the local DSN)."""
    return _db.admin_url()


@pytest.fixture(scope="session")
def migrated_db(admin_url: str) -> Iterator[Engine]:
    """A fresh, Alembic-migrated throwaway Postgres DB; yields an Engine, drops it after.

    Steps: create fresh DB (autocommit superuser) → ``alembic upgrade head`` (creates all
    tables/enums/indexes/constraints AND the per-agent roles + grants) → yield Engine.
    Teardown disposes the Engine and drops the DB. A dead cluster fails loudly upstream.
    """
    dbname = _db.throwaway_db_name()
    url = _db.throwaway_db_url()

    _db.create_fresh_database(admin_url, dbname)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(url, "head")
        engine = _db.build_engine(url)
        yield engine
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, dbname)
