"""M2 — data-model schema tests (RED until agentforge.storage.models + migrations exist).

Test-Agent-owned. Exercises the shape the M2 exploit-DB data model MUST expose once
migration 0001 has run against the throwaway ``migrated_db`` (a real Postgres, per-session).
Anchors: ARCHITECTURE.md §4 (AttemptResult field set), §6 (data model, indexes on
severity/category/target_version — PRD-OPT-16), §5/§18 (S3 replay UNIQUE); PRESEARCH.md
§5.2 (state machines) / §5.3 (invariants).

These assertions are schema-level and DB-truthed — they introspect ``pg_catalog`` /
``information_schema`` and prove constraints by attempting inserts and catching the DB's
own :class:`sqlalchemy.exc.IntegrityError` / :class:`~sqlalchemy.exc.DataError`. Nothing is
app-layer stubbed. Until migration 0001 exists, ``migrated_db`` raises at
``alembic upgrade head`` and every test here errors at fixture setup — RED for the right
reason.

Table + column names below are the CONTRACT the Implementation Agent must build to (frozen).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

# ---------------------------------------------------------------------------
# The tables migration 0001 must create (business surface, not the LangGraph/queue tables).
# ---------------------------------------------------------------------------
EXPECTED_TABLES = frozenset(
    {
        "campaign",
        "attack_case",
        "attempt",
        "red_team_staging",
        "attempt_result",
        "verdict",
        "finding",
        "regression_case",
    }
)

# The enum types (Postgres native enums) migration 0001 must create, with their labels.
EXPECTED_ENUMS = {
    "campaign_state": {"queued", "running", "complete", "halted", "aborted"},
    "attack_case_state": {"draft", "active", "retired"},
    "attack_class": {"boundary", "invariant", "regression"},
    "attempt_state": {"queued", "running", "success", "fail", "partial", "error"},
    "attempt_typed_error": {
        "target_unreachable",
        "budget_exceeded",
        "judge_timeout",
        "rate_limited",
        "adapter_error",
    },
    "verdict_state": {
        "EXPLOIT_CONFIRMED",
        "EXPLOIT_LIKELY",
        "NO_EXPLOIT_OBSERVED",
        "INDETERMINATE",
        "ERROR",
    },
    "finding_state": {
        "candidate",
        "judged",
        "documented",
        "approved",
        "published",
        "remediated",
        "validated",
        "resolved",
        "regressed",
    },
    "finding_severity": {"low", "medium", "high", "critical"},
    "regression_case_state": {"admitted", "passing", "failing"},
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _enum_labels(engine: Engine, enum_name: str) -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT e.enumlabel FROM pg_type t "
                "JOIN pg_enum e ON e.enumtypid = t.oid "
                "WHERE t.typname = :name"
            ),
            {"name": enum_name},
        ).all()
    return {r[0] for r in rows}


def _indexes_on(engine: Engine, table: str) -> str:
    """Concatenated CREATE INDEX defs for ``table`` (so a column name can be substring-matched)."""
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT indexdef FROM pg_indexes WHERE tablename = :t"),
            {"t": table},
        ).all()
    return "\n".join(r[0] for r in rows)


def _column_is_not_null(engine: Engine, table: str, column: str) -> bool:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_name = :t AND column_name = :c"
            ),
            {"t": table, "c": column},
        ).first()
    assert row is not None, f"{table}.{column} does not exist"
    return row[0] == "NO"


def _new_id() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Tables + enums exist
# ---------------------------------------------------------------------------
def test_all_expected_tables_exist(migrated_db: Engine) -> None:
    """Every M2 business table is present after ``alembic upgrade head`` (§6)."""
    with migrated_db.connect() as conn:
        rows = conn.execute(
            text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        ).all()
    present = {r[0] for r in rows}
    missing = EXPECTED_TABLES - present
    assert not missing, f"migration 0001 did not create tables: {sorted(missing)}"


@pytest.mark.parametrize("enum_name,labels", sorted(EXPECTED_ENUMS.items()))
def test_state_machine_enums_exist_with_exact_labels(
    migrated_db: Engine, enum_name: str, labels: set[str]
) -> None:
    """Each state-machine / taxonomy enum exists with EXACTLY its PRESEARCH §5.2 labels."""
    assert _enum_labels(migrated_db, enum_name) == labels


# ---------------------------------------------------------------------------
# attempt_result — authoritative append-only evidence (D14 field set) + S3 UNIQUE
# ---------------------------------------------------------------------------
def test_attempt_result_content_hash_is_not_null(migrated_db: Engine) -> None:
    """``attempt_result.content_hash`` is TEXT NOT NULL — evidence must always be hashed (D14)."""
    assert _column_is_not_null(migrated_db, "attempt_result", "content_hash")


def test_attempt_result_carries_the_d14_evidence_fields(migrated_db: Engine) -> None:
    """The D14 evidence field set (ARCHITECTURE §4) is present on attempt_result."""
    expected = {
        "schema_version",
        "campaign_run_id",
        "attempt_id",
        "campaign_id",
        "target_id",
        "target_version",
        "attack_attempt",
        "request_transcript",
        "response_transcript",
        "policy_decision_id",
        "executed_at",
        "trace_id",
        "correlation_id",
        "recorder_identity",
        "recorder_version",
        "content_hash",
    }
    with migrated_db.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'attempt_result'"
            )
        ).all()
    present = {r[0] for r in rows}
    missing = expected - present
    assert not missing, f"attempt_result is missing D14 fields: {sorted(missing)}"


def _insert_attempt_result(conn, *, campaign_run_id: str, attempt_id: str) -> None:
    """Insert one minimal attempt_result row (synthetic-only content). Raises on constraint."""
    conn.execute(
        text(
            "INSERT INTO attempt_result "
            "(campaign_run_id, attempt_id, content_hash) "
            "VALUES (:crid, :aid, :h)"
        ),
        {"crid": campaign_run_id, "aid": attempt_id, "h": _new_id()},
    )


def test_attempt_result_unique_pair_rejects_a_replay(migrated_db: Engine) -> None:
    """UNIQUE(campaign_run_id, attempt_id) rejects a duplicate pair (S3 replay foundation).

    The DB — not the app — must raise IntegrityError on the second identical pair. This is
    the storage-level half of the run-nonce replay defense (ARCHITECTURE §6, S3).
    """
    crid, aid = _new_id(), _new_id()
    with migrated_db.begin() as conn:
        _insert_attempt_result(conn, campaign_run_id=crid, attempt_id=aid)

    with pytest.raises(IntegrityError), migrated_db.begin() as conn:
        _insert_attempt_result(conn, campaign_run_id=crid, attempt_id=aid)


def test_attempt_result_content_hash_null_is_rejected(migrated_db: Engine) -> None:
    """A NULL content_hash is rejected by the DB (evidence integrity, D14)."""
    with pytest.raises(IntegrityError), migrated_db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO attempt_result (campaign_run_id, attempt_id, content_hash) "
                "VALUES (:crid, :aid, NULL)"
            ),
            {"crid": _new_id(), "aid": _new_id()},
        )


def test_attempt_result_indexes_target_version(migrated_db: Engine) -> None:
    """attempt_result is indexed on target_version (query pattern, §6)."""
    assert "target_version" in _indexes_on(migrated_db, "attempt_result")


# ---------------------------------------------------------------------------
# verdict → attempt_result referential integrity (§5.3 #6): a verdict cannot point at a
# non-existent evidence row. Closes the Important review finding — the (campaign_run_id,
# attempt_id) linkage is a real DB foreign key onto attempt_result's UNIQUE pair, not a
# loose string. A missing target must be rejected by the DB (SQLSTATE 23503), not the app.
# ---------------------------------------------------------------------------
def _insert_verdict(conn, *, campaign_run_id: str, attempt_id: str) -> None:
    """Insert one verdict referencing the given attempt_result pair. Raises on constraint."""
    conn.execute(
        text(
            "INSERT INTO verdict (state, campaign_run_id, attempt_id) "
            "VALUES ('INDETERMINATE', :crid, :aid)"
        ),
        {"crid": campaign_run_id, "aid": attempt_id},
    )


def test_verdict_without_matching_attempt_result_is_fk_rejected(migrated_db: Engine) -> None:
    """A verdict whose (campaign_run_id, attempt_id) has no attempt_result is FK-rejected.

    No orphan verdict may point at non-existent evidence. The rejection must be the DB's own
    foreign-key violation (SQLSTATE 23503), proving referential integrity is schema-enforced.
    """
    with pytest.raises(IntegrityError) as exc, migrated_db.begin() as conn:
        _insert_verdict(conn, campaign_run_id="no-such-run", attempt_id="no-such-attempt")
    assert getattr(exc.value.orig, "sqlstate", None) == "23503"


def test_verdict_with_matching_attempt_result_is_accepted(migrated_db: Engine) -> None:
    """A verdict referencing an existing attempt_result pair is accepted (the FK is satisfied)."""
    crid, aid = _new_id(), _new_id()
    with migrated_db.begin() as conn:
        _insert_attempt_result(conn, campaign_run_id=crid, attempt_id=aid)
        _insert_verdict(conn, campaign_run_id=crid, attempt_id=aid)


# ---------------------------------------------------------------------------
# finding — PRD-OPT-16 three query patterns are indexed
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("column", ["severity", "category", "target_version"])
def test_finding_indexes_the_three_query_patterns(migrated_db: Engine, column: str) -> None:
    """finding has an index covering severity / category / target_version (PRD-OPT-16, §6)."""
    assert column in _indexes_on(migrated_db, "finding"), (
        f"finding is missing a PRD-OPT-16 index on {column}"
    )


def test_finding_id_is_unique(migrated_db: Engine) -> None:
    """A duplicate finding_id is rejected by the DB (unique business key, §6 / invariant 6)."""
    fid = _new_id()

    def _insert(conn) -> None:
        conn.execute(
            text(
                "INSERT INTO finding (finding_id, severity, category) "
                "VALUES (:fid, 'high', 'prompt-injection')"
            ),
            {"fid": fid},
        )

    with migrated_db.begin() as conn:
        _insert(conn)
    with pytest.raises(IntegrityError), migrated_db.begin() as conn:
        _insert(conn)


# ---------------------------------------------------------------------------
# attack_case — no happy-path-only case: attack_class + owasp tags column exist
# ---------------------------------------------------------------------------
def test_attack_case_has_class_and_owasp_tags(migrated_db: Engine) -> None:
    """attack_case exposes attack_class (enum) + an owasp tags (jsonb) column (§6, invariant 9)."""
    with migrated_db.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name, data_type, udt_name FROM information_schema.columns "
                "WHERE table_name = 'attack_case'"
            )
        ).all()
    # information_schema row is (column_name, data_type, udt_name); the stored 2-tuple is
    # therefore (data_type, udt_name) — index [0] = data_type, [1] = udt_name. A native enum
    # column reports data_type 'USER-DEFINED' and udt_name = the enum type name.
    by_name = {r[0]: (r[1], r[2]) for r in rows}
    assert "attack_class" in by_name, "attack_case must carry a boundary|invariant|regression class"
    assert by_name["attack_class"][0] == "USER-DEFINED"
    assert by_name["attack_class"][1] == "attack_class"
    assert "owasp_tags" in by_name, "attack_case must carry an owasp tags column"
    assert by_name["owasp_tags"][0] == "jsonb"


# ---------------------------------------------------------------------------
# Enum rejection — a value outside the enum is refused by the DB, not silently coerced
# ---------------------------------------------------------------------------
def test_bad_enum_value_is_rejected_by_the_db(migrated_db: Engine) -> None:
    """Writing an out-of-domain enum value raises a DB error (native enum, not free text).

    psycopg surfaces an invalid-enum-input as a DBAPIError (invalid_text_representation);
    a plain TEXT column would silently accept it. This proves the state columns are real
    Postgres enums.
    """
    with pytest.raises((DBAPIError, IntegrityError)), migrated_db.begin() as conn:
        conn.execute(
            text("INSERT INTO campaign (campaign_id, state) VALUES (:cid, 'not_a_state')"),
            {"cid": _new_id()},
        )
