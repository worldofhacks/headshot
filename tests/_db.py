"""M2 DB fixture helpers — a REAL Postgres, per-session throwaway test database.

Test-Agent-owned. These helpers back the ``migrated_db`` fixture in ``tests/conftest.py``
that the three M2 suites (``test_models.py``, ``test_db_roles.py``, ``test_migrations.py``)
share. The S1/S2 storage-layer invariants (ARCHITECTURE.md §5, §6, §18; PRESEARCH.md §5.3)
are DB-enforced — they MUST run against a genuine Postgres, never a stub. So the fixture:

  1. resolves an ADMIN/superuser DSN (the ``agentforge`` cluster superuser — it can
     ``CREATE ROLE`` / ``GRANT`` and ``SET ROLE`` into the per-agent roles, whose GRANT
     checks then apply because the tables are OWNED by ``agentforge``, a non-member);
  2. via an AUTOCOMMIT connection on the maintenance ``postgres`` database, ``DROP``s any
     stale test DB and ``CREATE``s a fresh throwaway one whose name is derived from
     ``os.getpid()`` (so parallel/rerun sessions never collide);
  3. runs ``alembic upgrade head`` against that fresh DB (the SINGLE apply path — it also
     creates the per-agent roles + grants from ``roles.sql``, §6); and
  4. yields an :class:`sqlalchemy.engine.Engine`, then drops the DB at teardown.

**No silent skip.** If Postgres is unreachable the fixture raises with a clear
"start Postgres (docker compose up -d postgres)" message rather than skipping — a skip
would let CI go green without ever exercising the S1/S2 append-only-by-DB-permission
invariant, which is the whole point of M2. Per-agent roles are cluster-global, so they are
created idempotently by the migration (``DO $$ ... $$`` + ``pg_roles`` guard).

None of this imports ``agentforge.storage`` at module import time; the model + migration
code does not exist yet, so the fixture's ``alembic upgrade head`` (and the suites' model
imports) are what go RED — for the right reason.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
import pytest
from sqlalchemy import Engine, create_engine

# ---------------------------------------------------------------------------
# DSN resolution — bare postgresql:// (CI's DATABASE_URL) MUST be translated to the
# postgresql+psycopg:// dialect for SQLAlchemy 2.x + psycopg3 (per the M2 brief).
# ---------------------------------------------------------------------------

# The admin/superuser fallback DSN (local dev). 'local_dev_only' is a throwaway local-dev
# password already committed in compose.yaml — not a secret.
_ADMIN_DSN_FALLBACK = "postgresql+psycopg://agentforge:local_dev_only@localhost:5432/agentforge"


def _to_psycopg_dialect(url: str) -> str:
    """Normalize a DSN to the ``postgresql+psycopg://`` SQLAlchemy dialect.

    CI hands us a bare ``postgresql://`` (or ``postgres://``) scheme; SQLAlchemy 2.x would
    otherwise pick the default (psycopg2) driver. Rewriting to ``postgresql+psycopg://``
    binds the psycopg3 driver the stack actually installs. An explicit ``+psycopg`` dialect
    is left untouched.
    """
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://") :]
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    return url


def admin_url() -> str:
    """The admin/superuser SQLAlchemy URL: env ``DATABASE_URL`` (translated) or the fallback."""
    return _to_psycopg_dialect(os.environ.get("DATABASE_URL", _ADMIN_DSN_FALLBACK))


def _libpq_dsn(url: str) -> str:
    """Strip the SQLAlchemy ``+psycopg`` dialect tag → a plain libpq DSN for psycopg.connect."""
    return url.replace("+psycopg://", "://", 1)


def split_db(url: str) -> tuple[str, str]:
    """Return ``(base_url_without_db, dbname)`` for a ``.../<db>`` SQLAlchemy URL."""
    base, _, dbname = url.rpartition("/")
    return base, dbname


def _maintenance_dsn(admin: str) -> str:
    """A libpq DSN pointed at the maintenance ``postgres`` DB (for CREATE/DROP DATABASE)."""
    base, _ = split_db(admin)
    return _libpq_dsn(base + "/postgres")


def throwaway_db_name() -> str:
    """A throwaway test-DB name unique to this OS process (rerun/parallel-safe)."""
    return f"agentforge_test_{os.getpid()}"


_UNREACHABLE_MSG = (
    "Postgres is unreachable — the M2 storage invariants (S1/S2 append-only by DB "
    "permission, S3 replay UNIQUE) MUST run against a real Postgres and are NOT allowed "
    "to silently skip. Start Postgres (docker compose up -d postgres) and retry. "
    "Underlying error: {err}"
)


@contextmanager
def _autocommit_maintenance_conn(admin: str) -> Iterator[psycopg.Connection]:
    """Open an AUTOCOMMIT superuser connection to the maintenance DB, or fail loudly."""
    try:
        conn = psycopg.connect(_maintenance_dsn(admin), autocommit=True)
    except psycopg.OperationalError as err:  # Postgres down / wrong DSN
        pytest.fail(_UNREACHABLE_MSG.format(err=err), pytrace=False)
    try:
        yield conn
    finally:
        conn.close()


def create_fresh_database(admin: str, dbname: str) -> None:
    """DROP-IF-EXISTS then CREATE a fresh throwaway test database (autocommit superuser)."""
    with _autocommit_maintenance_conn(admin) as conn, conn.cursor() as cur:
        # Terminate stragglers so DROP DATABASE cannot block on a lingering backend.
        cur.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()",
            (dbname,),
        )
        cur.execute(f'DROP DATABASE IF EXISTS "{dbname}"')
        cur.execute(f'CREATE DATABASE "{dbname}"')


def drop_database(admin: str, dbname: str) -> None:
    """Tear down the throwaway test database (best-effort; teardown must not mask failures)."""
    with _autocommit_maintenance_conn(admin) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()",
            (dbname,),
        )
        cur.execute(f'DROP DATABASE IF EXISTS "{dbname}"')


def alembic_config(db_url: str):
    """Build an in-memory Alembic ``Config`` bound to ``db_url``, rooted at the repo.

    Imported lazily by callers so the (not-yet-existing) migration package does not need to
    import cleanly at test-collection time. The Alembic ``env.py`` reads ``DATABASE_URL``;
    we ALSO set the ``sqlalchemy.url`` main option so a test DB name (per-PID) overrides the
    admin DSN's default database.
    """
    from alembic.config import Config

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(repo_root, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(repo_root, "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def alembic_upgrade(db_url: str, revision: str = "head") -> None:
    """Run ``alembic upgrade <revision>`` against ``db_url`` (the single migration apply path)."""
    from alembic import command

    command.upgrade(alembic_config(db_url), revision)


def alembic_downgrade(db_url: str, revision: str) -> None:
    """Run ``alembic downgrade <revision>`` against ``db_url``."""
    from alembic import command

    command.downgrade(alembic_config(db_url), revision)


def build_engine(db_url: str) -> Engine:
    """A short-lived Engine on ``db_url`` with pre-ping (fail fast on a dead connection)."""
    return create_engine(db_url, pool_pre_ping=True, future=True)


def throwaway_db_url() -> str:
    """The SQLAlchemy URL of THIS session's throwaway test database."""
    base, _ = split_db(admin_url())
    return f"{base}/{throwaway_db_name()}"
