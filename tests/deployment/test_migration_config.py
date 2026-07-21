"""Alembic URL selection must be explicit and Railway-safe."""

from __future__ import annotations


def _resolve(*, configured_url: str | None, environment_url: str | None) -> str:
    from agentforge.migration_config import resolve_database_url

    environ = {} if environment_url is None else {"DATABASE_URL": environment_url}
    return resolve_database_url(configured_url=configured_url, environ=environ)


def test_explicit_programmatic_url_wins_for_isolated_migration_tests() -> None:
    assert (
        _resolve(
            configured_url="postgresql://configured:test@db/configured",
            environment_url="postgresql://environment:test@db/environment",
        )
        == "postgresql+psycopg://configured:test@db/configured"
    )


def test_railway_database_url_wins_when_ini_value_is_blank() -> None:
    assert (
        _resolve(
            configured_url="",
            environment_url="postgresql://railway:test@private-postgres/agentforge",
        )
        == "postgresql+psycopg://railway:test@private-postgres/agentforge"
    )


def test_legacy_postgres_scheme_is_normalized_to_psycopg3() -> None:
    assert (
        _resolve(
            configured_url=None,
            environment_url="postgres://railway:test@private-postgres/agentforge",
        )
        == "postgresql+psycopg://railway:test@private-postgres/agentforge"
    )


def test_psycopg3_scheme_is_not_rewritten() -> None:
    value = "postgresql+psycopg://railway:test@private-postgres/agentforge"
    assert _resolve(configured_url=None, environment_url=value) == value


def test_local_fallback_is_used_only_when_no_explicit_url_exists() -> None:
    assert _resolve(configured_url="   ", environment_url="  ") == (
        "postgresql+psycopg://agentforge:local_dev_only@localhost:5432/agentforge"
    )
