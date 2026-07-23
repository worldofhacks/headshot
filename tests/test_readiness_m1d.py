"""M1d readiness requires DB, exact schema head, local Clerk parsing, and console assets."""

from __future__ import annotations

from pathlib import Path

from agentforge.readiness import build_readiness_check, database_schema_ready, expected_alembic_head


def test_integrated_alembic_head_is_the_single_forward_m1d_revision() -> None:
    assert expected_alembic_head() == "0008"


def test_database_schema_ready_accepts_migrated_integrated_head(migrated_db) -> None:
    database_url = migrated_db.url.render_as_string(hide_password=False)
    assert database_schema_ready(database_url) is True


def test_readiness_fails_closed_without_database_url(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("<!doctype html>", encoding="utf-8")
    assert build_readiness_check(database_url=None, console_dir=tmp_path)() is False


def test_readiness_requires_console_and_locally_valid_auth_config(
    monkeypatch, tmp_path: Path
) -> None:
    import agentforge.readiness as readiness

    class Valid:
        @classmethod
        def from_env(cls):
            return cls()

    monkeypatch.setattr(readiness, "database_schema_ready", lambda _url: True)
    monkeypatch.setattr(readiness, "ClerkAuthConfig", Valid)
    monkeypatch.setattr(readiness, "WebSecurityConfig", Valid)
    check = build_readiness_check(database_url="postgresql://fixture", console_dir=tmp_path)

    assert check() is False
    (tmp_path / "index.html").write_text("<!doctype html>", encoding="utf-8")
    assert check() is True


def test_readiness_never_contacts_clerk_target_or_model(monkeypatch, tmp_path: Path) -> None:
    import socket

    import agentforge.readiness as readiness

    class Valid:
        @classmethod
        def from_env(cls):
            return cls()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("readiness attempted network I/O")

    (tmp_path / "index.html").write_text("<!doctype html>", encoding="utf-8")
    monkeypatch.setattr(readiness, "database_schema_ready", lambda _url: True)
    monkeypatch.setattr(readiness, "ClerkAuthConfig", Valid)
    monkeypatch.setattr(readiness, "WebSecurityConfig", Valid)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)

    assert build_readiness_check(database_url="postgresql://fixture", console_dir=tmp_path)()
