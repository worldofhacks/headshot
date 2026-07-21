"""M2 — Alembic expand/contract migration round-trip (NFR7: migrations don't lose data).

Test-Agent-owned. ARCHITECTURE.md §12 (rollback discipline: expand/contract migrations are
the rule; destructive migrations forbidden alongside their consumers) and §7 (D7) require
that a single deploy is rollback-safe without a DB downgrade. PRESEARCH.md §6 NFR7 requires
migrations that don't lose data.

This suite drives Alembic revision-by-revision (not straight to ``head``) against its OWN
throwaway Postgres DB so it can:

  1. ``upgrade 0001`` and seed synthetic rows into a table 0002 will expand;
  2. capture the 0001 column set of that table;
  3. ``upgrade 0002`` (the EXPAND-only demonstrator) and assert the seeded rows SURVIVE
     unchanged AND the new nullable column is present AND it is genuinely nullable AND 0002
     did NOT drop/rename any existing column (0002 column set ⊇ 0001 set — expand-only);
  4. ``downgrade 0001`` and assert the rows STILL survive AND the added column is gone
     (the contract half — a clean expand/contract round-trip preserves data both ways).

Until the ``migrations/`` package + revisions 0001/0002 exist, ``alembic upgrade`` raises
and these tests error at fixture setup — RED for the right reason.

The table the demonstrator expands is discovered at runtime (the column set delta between
0001 and 0002) so the test does not hard-code whether 0002 touches ``finding`` or
``attempt_result`` — only that it is expand-only and lossless.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text

import _db

# The two revisions M2 must ship. 0001 = initial (all tables/enums/indexes/roles);
# 0002 = the expand-only demonstrator (adds ONE nullable column to an existing table).
REV_INITIAL = "0001"
REV_EXPAND = "0002"


def _new_id() -> str:
    return uuid.uuid4().hex


@pytest.fixture
def revisioned_db() -> Iterator[tuple[str, str]]:
    """A fresh throwaway DB left at ``0001`` (NOT head), yielding ``(db_url, admin_url)``.

    Unlike the session-scoped ``migrated_db``, this is function-scoped and stops at 0001 so
    the test itself drives the 0001→0002→0001 round-trip. A dead Postgres fails loudly in
    ``create_fresh_database`` (no silent skip).
    """
    admin = _db.admin_url()
    dbname = f"agentforge_mig_{uuid.uuid4().hex[:12]}"
    base, _sep = _db.split_db(admin)
    url = f"{base}/{dbname}"

    _db.create_fresh_database(admin, dbname)
    try:
        _db.alembic_upgrade(url, REV_INITIAL)
        yield url, admin
    finally:
        _db.drop_database(admin, dbname)


def _columns(engine: Engine, table: str) -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT column_name FROM information_schema.columns WHERE table_name = :t"),
            {"t": table},
        ).all()
    return {r[0] for r in rows}


def _nullable_columns(engine: Engine, table: str) -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :t AND is_nullable = 'YES'"
            ),
            {"t": table},
        ).all()
    return {r[0] for r in rows}


def _table_with_expanded_column(url: str) -> tuple[str, str, set[str]]:
    """Upgrade to 0002 and return ``(table, added_column, cols_at_0001)`` for the touched table.

    Discovers which table 0002 expands by diffing the column sets of every business table
    across the 0001→0002 step, so the assertions do not hard-code the demonstrator's choice.
    Asserts exactly ONE column was added to exactly ONE table, and no column was removed
    (expand-only). Leaves the DB at 0002.
    """
    tables = (
        "campaign",
        "attack_case",
        "attempt",
        "red_team_staging",
        "attempt_result",
        "verdict",
        "finding",
        "regression_case",
    )
    engine = _db.build_engine(url)
    try:
        before = {t: _columns(engine, t) for t in tables}
    finally:
        engine.dispose()

    _db.alembic_upgrade(url, REV_EXPAND)

    engine = _db.build_engine(url)
    try:
        after = {t: _columns(engine, t) for t in tables}
    finally:
        engine.dispose()

    added_by_table = {t: (after[t] - before[t]) for t in tables if after[t] - before[t]}
    removed_by_table = {t: (before[t] - after[t]) for t in tables if before[t] - after[t]}

    assert not removed_by_table, (
        f"0002 must be EXPAND-only but DROPPED/renamed columns: {removed_by_table}"
    )
    assert len(added_by_table) == 1, (
        f"0002 must add ONE nullable column to ONE table; added: {added_by_table}"
    )
    table, added = next(iter(added_by_table.items()))
    assert len(added) == 1, f"0002 added more than one column to {table}: {added}"
    return table, next(iter(added)), before[table]


def test_expand_migration_preserves_rows_and_adds_a_nullable_column(
    revisioned_db: tuple[str, str],
) -> None:
    """0001→0002 expand: seeded rows survive unchanged; a new NULLABLE column appears; the
    step is expand-only (no existing column dropped/renamed) — proves lossless expand (NFR7)."""
    url, _admin = revisioned_db

    # Seed synthetic rows at 0001 (two findings — a distinct, countable population).
    seeded = [_new_id(), _new_id()]
    engine = _db.build_engine(url)
    try:
        with engine.begin() as conn:
            for fid in seeded:
                conn.execute(
                    text(
                        "INSERT INTO finding (finding_id, severity, category) "
                        "VALUES (:fid, 'high', 'prompt-injection')"
                    ),
                    {"fid": fid},
                )
    finally:
        engine.dispose()

    # Upgrade to 0002 and locate the expanded table + added column (expand-only asserted).
    table, added_column, cols_at_0001 = _table_with_expanded_column(url)

    engine = _db.build_engine(url)
    try:
        # The added column exists and is genuinely nullable (expand columns are nullable).
        assert added_column in _nullable_columns(engine, table), (
            f"the expand column {table}.{added_column} must be nullable (backward-compatible)"
        )
        # Every pre-existing column is still present (⊇): nothing dropped/renamed.
        assert cols_at_0001 <= _columns(engine, table)

        # The seeded finding rows survived the expand unchanged.
        with engine.connect() as conn:
            surviving = {
                r[0]
                for r in conn.execute(
                    text("SELECT finding_id FROM finding WHERE finding_id = ANY(:ids)"),
                    {"ids": seeded},
                ).all()
            }
        assert surviving == set(seeded), "expand migration lost or altered seeded rows"
    finally:
        engine.dispose()


def test_contract_downgrade_preserves_rows_and_drops_only_the_added_column(
    revisioned_db: tuple[str, str],
) -> None:
    """0002→0001 contract (downgrade): seeded rows STILL survive AND the added column is gone
    — a clean expand/contract round-trip is lossless in both directions (NFR7, §12)."""
    url, _admin = revisioned_db

    seeded = [_new_id(), _new_id(), _new_id()]
    engine = _db.build_engine(url)
    try:
        with engine.begin() as conn:
            for fid in seeded:
                conn.execute(
                    text(
                        "INSERT INTO finding (finding_id, severity, category) "
                        "VALUES (:fid, 'medium', 'ssrf')"
                    ),
                    {"fid": fid},
                )
    finally:
        engine.dispose()

    table, added_column, _cols_at_0001 = _table_with_expanded_column(url)

    # Contract: downgrade back to 0001.
    _db.alembic_downgrade(url, REV_INITIAL)

    engine = _db.build_engine(url)
    try:
        # The added column is gone (contract dropped exactly what expand added).
        assert added_column not in _columns(engine, table), (
            f"downgrade must drop the added column {table}.{added_column}"
        )
        # The seeded rows STILL survive the round-trip (no data loss on downgrade).
        with engine.connect() as conn:
            surviving = {
                r[0]
                for r in conn.execute(
                    text("SELECT finding_id FROM finding WHERE finding_id = ANY(:ids)"),
                    {"ids": seeded},
                ).all()
            }
        assert surviving == set(seeded), "contract downgrade lost seeded rows"
    finally:
        engine.dispose()
