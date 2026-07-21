"""Networkless readiness for the Railway Web service."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from agentforge.auth.config import ClerkAuthConfig
from agentforge.migration_config import normalize_psycopg_url
from agentforge.web import WebSecurityConfig

_logger = logging.getLogger(__name__)
_CONNECT_TIMEOUT_SECONDS = 2


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _alembic_config_path() -> Path:
    configured = os.environ.get("ALEMBIC_CONFIG")
    if configured:
        return Path(configured)
    container = Path("/app/alembic.ini")
    return container if container.is_file() else _repository_root() / "alembic.ini"


def expected_alembic_head() -> str:
    """Resolve the sole packaged migration head without opening a database connection."""

    config_path = _alembic_config_path()
    config = Config(str(config_path))
    script_location = Path(config.get_main_option("script_location", "migrations"))
    if not script_location.is_absolute():
        script_location = config_path.parent / script_location
    config.set_main_option("script_location", str(script_location))
    heads = ScriptDirectory.from_config(config).get_heads()
    if len(heads) != 1:
        raise RuntimeError("migration graph must have exactly one head")
    return heads[0]


def _libpq_url(database_url: str) -> str:
    return normalize_psycopg_url(database_url).replace("postgresql+psycopg://", "postgresql://", 1)


def database_schema_ready(database_url: str | None) -> bool:
    """Check PostgreSQL connectivity and exact Alembic head; fail closed and redact errors."""

    if not database_url:
        return False
    try:
        import psycopg

        expected = expected_alembic_head()
        with (
            psycopg.connect(
                _libpq_url(database_url), connect_timeout=_CONNECT_TIMEOUT_SECONDS
            ) as conn,
            conn.cursor() as cursor,
        ):
            cursor.execute("SELECT 1")
            if cursor.fetchone() != (1,):
                return False
            cursor.execute("SELECT version_num FROM alembic_version")
            rows = cursor.fetchall()
        return rows == [(expected,)]
    except Exception:
        _logger.warning("readiness: database_or_schema_unavailable")
        return False


def build_readiness_check(
    *,
    database_url: str | None,
    console_dir: str | os.PathLike[str],
) -> Callable[[], bool]:
    """Compose only local parsing/filesystem checks plus PostgreSQL; never Clerk/JWKS egress."""

    index = Path(console_dir) / "index.html"

    def check() -> bool:
        if not database_url or not index.is_file():
            return False
        if not database_schema_ready(database_url):
            return False
        try:
            ClerkAuthConfig.from_env()
            WebSecurityConfig.from_env()
        except Exception:
            _logger.warning("readiness: security_configuration_invalid")
            return False
        return True

    return check


__all__ = ["build_readiness_check", "database_schema_ready", "expected_alembic_head"]
