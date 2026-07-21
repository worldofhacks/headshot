"""M2 — per-agent DB-role invariants (S1/S2): append-only enforced BY THE DB, not convention.

Test-Agent-owned. This is the crux of M2. ARCHITECTURE.md §5 (S1/S2), §6, §18 and
PRESEARCH.md §5.3 (invariants 1/2) say integrity rests on canonical hashing + append-only
storage + role separation — and that a Red Team write to the Recorder-owned append-only
``attempt_result`` table is **rejected by the DB, not by convention**. These tests prove
exactly that against a real Postgres.

Mechanism: the throwaway ``migrated_db`` connects as the ``agentforge`` cluster superuser,
which OWNS the tables. The per-agent roles (created by migration 0001 from ``roles.sql``)
are **non-owners**, so GRANT checks apply to them. Each assertion opens a SAVEPOINT, runs
``SET LOCAL ROLE <agent_role>``, performs the operation, then ROLLBACKs to the savepoint
(and resets the role) — so the tests never mutate shared state and never depend on order.

A rejection is asserted to be a GENUINE DB permission error via SQLSTATE ``42501``
(``insufficient_privilege``), surfaced by psycopg as ``ProgrammingError`` /
``InsufficientPrivilege`` — never an app-layer guard. Until migration 0001 + roles.sql
exist, ``migrated_db`` fails at ``alembic upgrade head`` and every test errors at setup —
RED for the right reason.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy import Connection, Engine, text
from sqlalchemy.exc import ProgrammingError

# The per-agent roles migration 0001 must create (from src/agentforge/storage/roles.sql).
ROLE_REDTEAM = "headshot_redteam"
ROLE_RECORDER = "headshot_recorder"
ROLE_JUDGE = "headshot_judge"

# SQLSTATE for "insufficient_privilege" — a genuine DB permission denial (not app-layer).
SQLSTATE_INSUFFICIENT_PRIVILEGE = "42501"


def _new_id() -> str:
    return uuid.uuid4().hex


def _sqlstate(exc: BaseException) -> str | None:
    """Best-effort pull of the Postgres SQLSTATE from a SQLAlchemy/psycopg exception chain."""
    cur: BaseException | None = exc
    while cur is not None:
        sqlstate = getattr(cur, "sqlstate", None)
        if sqlstate:
            return sqlstate
        cur = cur.__cause__ or cur.__context__
    return None


@contextmanager
def _as_role(conn: Connection, role: str) -> Iterator[None]:
    """Run a block as ``role`` inside a SAVEPOINT; always roll back and reset role after.

    Uses a nested transaction (SAVEPOINT) so a permission failure can be caught and unwound
    without poisoning the outer transaction, and so the operations under test are never
    committed. ``SET LOCAL ROLE`` scopes the role switch to this transaction.
    """
    nested = conn.begin_nested()
    try:
        conn.execute(text(f"SET LOCAL ROLE {role}"))
        yield
    finally:
        # Unwind any partial/failed statement, then drop back to the owning superuser.
        if nested.is_active:
            nested.rollback()
        conn.execute(text("RESET ROLE"))


def _assert_permission_denied(excinfo: pytest.ExceptionInfo) -> None:
    """Assert the raised error is a genuine DB permission denial (SQLSTATE 42501)."""
    assert _sqlstate(excinfo.value) == SQLSTATE_INSUFFICIENT_PRIVILEGE, (
        "expected a DB permission error (SQLSTATE 42501, insufficient_privilege); "
        f"got SQLSTATE {_sqlstate(excinfo.value)} from {excinfo.value!r}"
    )


# The append-only / staging INSERT statements under test (synthetic content only).
_INSERT_STAGING = text(
    "INSERT INTO red_team_staging (campaign_run_id, attempt_id, payload) "
    "VALUES (:crid, :aid, '{}'::jsonb)"
)
_SELECT_STAGING = text("SELECT id FROM red_team_staging LIMIT 1")
_INSERT_ATTEMPT_RESULT = text(
    "INSERT INTO attempt_result (campaign_run_id, attempt_id, content_hash) "
    "VALUES (:crid, :aid, :h)"
)
_SELECT_ATTEMPT_RESULT = text("SELECT id FROM attempt_result LIMIT 1")
_UPDATE_ATTEMPT_RESULT = text("UPDATE attempt_result SET content_hash = 'tampered'")
_DELETE_ATTEMPT_RESULT = text("DELETE FROM attempt_result")


@pytest.fixture
def conn(migrated_db: Engine) -> Iterator[Connection]:
    """A superuser (table-owner) connection whose outer transaction is rolled back after.

    Everything each test does happens in savepoints under this transaction, so no per-agent
    write ever persists — the role invariants are pure, order-independent assertions.
    """
    with migrated_db.connect() as c:
        trans = c.begin()
        try:
            yield c
        finally:
            trans.rollback()


# ===========================================================================
# headshot_redteam — INSERT-only into staging it CANNOT read back; NOTHING on attempt_result
# ===========================================================================
def test_redteam_insert_into_staging_is_allowed(conn: Connection) -> None:
    """S1: the Red Team role MAY INSERT into its staging table."""
    with _as_role(conn, ROLE_REDTEAM):
        conn.execute(_INSERT_STAGING, {"crid": _new_id(), "aid": _new_id()})  # must not raise


def test_redteam_select_staging_is_db_rejected(conn: Connection) -> None:
    """S1: the Red Team role CANNOT read back its own staging (no read-back) — DB-denied."""
    with _as_role(conn, ROLE_REDTEAM), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_SELECT_STAGING)
    _assert_permission_denied(excinfo)


def test_redteam_insert_into_attempt_result_is_db_rejected(conn: Connection) -> None:
    """S2 HEADLINE: a Red Team write to the Recorder-owned append-only attempt_result table
    is rejected by the DB, not by convention (SQLSTATE 42501)."""
    with _as_role(conn, ROLE_REDTEAM), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_INSERT_ATTEMPT_RESULT, {"crid": _new_id(), "aid": _new_id(), "h": _new_id()})
    _assert_permission_denied(excinfo)


# ===========================================================================
# headshot_recorder — SELECT staging + INSERT attempt_result; NO UPDATE/DELETE (append-only)
# ===========================================================================
def test_recorder_select_staging_is_allowed(conn: Connection) -> None:
    """S2: the Recorder role MAY read Red Team submissions from staging."""
    with _as_role(conn, ROLE_RECORDER):
        conn.execute(_SELECT_STAGING)  # must not raise


def test_recorder_insert_attempt_result_is_allowed(conn: Connection) -> None:
    """S2: the Recorder role MAY append to the authoritative attempt_result table."""
    with _as_role(conn, ROLE_RECORDER):
        conn.execute(
            _INSERT_ATTEMPT_RESULT, {"crid": _new_id(), "aid": _new_id(), "h": _new_id()}
        )  # must not raise


def test_recorder_update_attempt_result_is_db_rejected(conn: Connection) -> None:
    """S2: append-only — the Recorder role has NO UPDATE grant on attempt_result (DB-denied)."""
    with _as_role(conn, ROLE_RECORDER), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_UPDATE_ATTEMPT_RESULT)
    _assert_permission_denied(excinfo)


def test_recorder_delete_attempt_result_is_db_rejected(conn: Connection) -> None:
    """S2: append-only — the Recorder role has NO DELETE grant on attempt_result (DB-denied)."""
    with _as_role(conn, ROLE_RECORDER), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_DELETE_ATTEMPT_RESULT)
    _assert_permission_denied(excinfo)


# ===========================================================================
# headshot_judge — SELECT-only on attempt_result; NO INSERT/UPDATE/DELETE
# ===========================================================================
def test_judge_select_attempt_result_is_allowed(conn: Connection) -> None:
    """S2: the Judge role MAY read the authoritative evidence to render a verdict."""
    with _as_role(conn, ROLE_JUDGE):
        conn.execute(_SELECT_ATTEMPT_RESULT)  # must not raise


def test_judge_insert_attempt_result_is_db_rejected(conn: Connection) -> None:
    """S2: the Judge role is SELECT-only — INSERT into attempt_result is DB-denied."""
    with _as_role(conn, ROLE_JUDGE), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_INSERT_ATTEMPT_RESULT, {"crid": _new_id(), "aid": _new_id(), "h": _new_id()})
    _assert_permission_denied(excinfo)


def test_judge_update_attempt_result_is_db_rejected(conn: Connection) -> None:
    """S2: the Judge role is SELECT-only — UPDATE attempt_result is DB-denied."""
    with _as_role(conn, ROLE_JUDGE), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_UPDATE_ATTEMPT_RESULT)
    _assert_permission_denied(excinfo)


def test_judge_delete_attempt_result_is_db_rejected(conn: Connection) -> None:
    """S2: the Judge role is SELECT-only — DELETE attempt_result is DB-denied."""
    with _as_role(conn, ROLE_JUDGE), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_DELETE_ATTEMPT_RESULT)
    _assert_permission_denied(excinfo)


# ===========================================================================
# The overarching invariant: NO role anywhere may UPDATE or DELETE attempt_result.
# ===========================================================================
@pytest.mark.parametrize("role", [ROLE_REDTEAM, ROLE_RECORDER, ROLE_JUDGE])
def test_no_agent_role_can_mutate_or_delete_attempt_result(conn: Connection, role: str) -> None:
    """S2 invariant: append-only is DB-enforced — UPDATE and DELETE on the authoritative
    attempt_result table are denied to EVERY per-agent role, Recorder included."""
    with _as_role(conn, role), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_UPDATE_ATTEMPT_RESULT)
    _assert_permission_denied(excinfo)

    with _as_role(conn, role), pytest.raises(ProgrammingError) as excinfo:
        conn.execute(_DELETE_ATTEMPT_RESULT)
    _assert_permission_denied(excinfo)
