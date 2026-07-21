"""Alembic environment for the AgentForge exploit-DB migrations (M2).

Resolves the DB URL from env ``DATABASE_URL`` (translating CI's bare ``postgresql://`` to
the ``postgresql+psycopg://`` SQLAlchemy dialect required by SQLAlchemy 2.x + psycopg3),
falling back to the local admin DSN. When Alembic is driven programmatically (the tests set
``sqlalchemy.url`` on the Config to point at a per-PID throwaway DB), that explicit main
option wins over the environment — so a test run migrates its OWN database, never the shared
one. Uses the models' ``Base.metadata`` as ``target_metadata`` and supports offline + online
modes. ARCHITECTURE.md §6/§7/§12.
"""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from agentforge.storage.models import Base

# Alembic Config object — provides access to values in alembic.ini.
config = context.config

# The models' MetaData is the autogenerate/target schema source.
target_metadata = Base.metadata

# Local admin/superuser fallback DSN. 'local_dev_only' is a throwaway local-dev password
# already committed in compose.yaml — not a secret.
_ADMIN_DSN_FALLBACK = "postgresql+psycopg://agentforge:local_dev_only@localhost:5432/agentforge"


def _to_psycopg_dialect(url: str) -> str:
    """Normalize a DSN to the ``postgresql+psycopg://`` SQLAlchemy dialect (psycopg3).

    CI hands a bare ``postgresql://`` (or ``postgres://``) scheme; SQLAlchemy 2.x would
    otherwise select the default psycopg2 driver. An explicit ``+psycopg`` dialect is
    left untouched.
    """
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://") :]
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    return url


def _resolve_url() -> str:
    """Pick the DB URL: a Config ``sqlalchemy.url`` (tests) wins; else env; else fallback."""
    configured = config.get_main_option("sqlalchemy.url")
    if configured:
        return _to_psycopg_dialect(configured)
    return _to_psycopg_dialect(os.environ.get("DATABASE_URL", _ADMIN_DSN_FALLBACK))


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emit SQL against a URL, without a live DBAPI."""
    context.configure(
        url=_resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode — against a live psycopg3 connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _resolve_url()
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
