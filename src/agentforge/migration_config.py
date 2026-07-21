"""Pure database-URL selection for the Alembic deployment boundary.

The checked-in Alembic configuration deliberately contains no usable database URL.
Programmatic callers may inject one (the isolated migration tests do); otherwise the
runtime ``DATABASE_URL`` supplied by Railway wins, with a local-only fallback for the
throwaway Compose database.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

LOCAL_ADMIN_DSN = "postgresql+psycopg://agentforge:local_dev_only@localhost:5432/agentforge"


def normalize_psycopg_url(url: str) -> str:
    """Select psycopg 3 for ordinary Postgres URLs without exposing their contents."""

    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://") :]
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    return url


def resolve_database_url(
    *,
    configured_url: str | None,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Resolve explicit test config, then process config, then the local fallback.

    No value is logged or included in an exception. The explicit Alembic value exists
    for programmatic, per-test databases; normal CLI deployments leave it blank so the
    environment-specific Railway binding is authoritative.
    """

    source = os.environ if environ is None else environ
    explicit = configured_url.strip() if configured_url else ""
    environment = source.get("DATABASE_URL", "").strip()
    return normalize_psycopg_url(explicit or environment or LOCAL_ADMIN_DSN)
