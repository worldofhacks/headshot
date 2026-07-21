"""M4 — Execution Recorder RED tests (written first, no src/ code).

Anchors: ARCHITECTURE.md §4 (D14 AttemptResult field set + content_hash the Judge/Orchestrator
recompute-and-verify before every read), §5 (S1/S2 append-only-by-DB-permission, S3 run-nonce
replay UNIQUE); IMPLEMENTATION_PLAN.md M4; wf-m4-policy-gateway DESIGN(recorder) + ACCEPTANCE.

The trusted **Execution Recorder** computes a canonical content_hash (sorted-key / explicit
field-order bytes — recompute-stable, D14) and INSERTs the evidence APPEND-ONLY into the
authoritative ``attempt_result`` table (INSERT only — never UPDATE/DELETE). ``verify()``
recomputes the hash and FAILS CLOSED on any mismatch/missing (an evidence-integrity error).
A duplicate ``(campaign_run_id, attempt_id)`` is rejected by the DB UNIQUE (S3 replay),
surfaced as a typed error — never an overwrite.

These DB-backed tests use the M2 ``migrated_db`` fixture (a real Postgres, migrated to head —
tables, roles, and the UNIQUE constraint all exist). They pin the edge/error cases the ACs
demand (canonical recompute-verify fail-closed, S3 replay rejection), never a happy path alone.

Until ``agentforge.policy.recorder`` exists, the import below fails and this module RED-collects
— RED for the right reason. (The ``migrated_db`` fixture migrates cleanly on this branch, so the
RED is attributable to the missing recorder module, not to an unavailable DB.)
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from agentforge.policy.recorder import (
    EvidenceIntegrityError,
    ExecutionRecorder,
    ReplayRejectedError,
)


def _new_id() -> str:
    return uuid.uuid4().hex


def _fields(*, campaign_run_id: str | None = None, attempt_id: str | None = None) -> dict:
    """A minimal, synthetic-only AttemptResult field set (D14) for the recorder to hash+append.

    No real PHI — the transcript is inert synthetic content.
    """
    return {
        "schema_version": "1",
        "campaign_run_id": campaign_run_id or _new_id(),
        "attempt_id": attempt_id or _new_id(),
        "campaign_id": "c1",
        "target_id": "fake",
        "target_version": "v1",
        "attack_attempt": {"case_ref": "case-1", "input_sequence": ["hello"]},
        "request_transcript": {"request": ["hello"]},
        "response_transcript": "I can only access the current patient's record.",
        "policy_decision_id": "pd-1",
        "recorder_identity": "recorder@1",
    }


def _count_rows(engine: Engine, campaign_run_id: str) -> int:
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT count(*) FROM attempt_result WHERE campaign_run_id = :crid"),
            {"crid": campaign_run_id},
        ).scalar_one()


# ===========================================================================
# AC-2 — canonical hashing: recompute-stable, deterministic, 64-hex sha256.
# ===========================================================================
def test_content_hash_is_canonical_and_deterministic() -> None:
    """The recorder's canonical content_hash is a pure function of the fields — the SAME
    fields hash to the SAME 64-hex digest every time (recompute-stable, D14)."""
    recorder = ExecutionRecorder()
    fields = _fields(campaign_run_id="run-1", attempt_id="att-1")
    h1 = recorder.canonical_hash(fields)
    h2 = recorder.canonical_hash(dict(fields))
    assert h1 == h2
    assert len(h1) == 64
    assert all(c in "0123456789abcdef" for c in h1)


def test_content_hash_is_field_order_independent() -> None:
    """Canonical serialization sorts keys / fixes field order, so a differently-ordered dict
    with the same content produces the SAME hash — the Judge can recompute it independently."""
    recorder = ExecutionRecorder()
    fields = _fields(campaign_run_id="run-2", attempt_id="att-2")
    reordered = {k: fields[k] for k in reversed(list(fields))}
    assert recorder.canonical_hash(fields) == recorder.canonical_hash(reordered)


def test_content_hash_changes_when_evidence_changes() -> None:
    """A change to the recorded evidence changes the hash — the hash actually binds the
    content (a tamper is detectable on recompute)."""
    recorder = ExecutionRecorder()
    fields = _fields(campaign_run_id="run-3", attempt_id="att-3")
    tampered = dict(fields, response_transcript="ATTACKER EXFILTRATED THE CHART")
    assert recorder.canonical_hash(fields) != recorder.canonical_hash(tampered)


# ===========================================================================
# AC-2 — append-only INSERT of hashed evidence into the authoritative table.
# ===========================================================================
def test_record_appends_one_hashed_row(migrated_db: Engine) -> None:
    """record() computes the canonical content_hash and INSERTs exactly one append-only row
    into attempt_result; the stored content_hash matches the recompute."""
    recorder = ExecutionRecorder()
    crid = _new_id()
    fields = _fields(campaign_run_id=crid, attempt_id=_new_id())
    with migrated_db.begin() as conn:
        stored = recorder.record(fields, conn)
    assert _count_rows(migrated_db, crid) == 1
    assert stored.content_hash == recorder.canonical_hash(fields)
    assert len(stored.content_hash) == 64


def test_record_persists_the_content_hash_column(migrated_db: Engine) -> None:
    """The persisted row carries the canonical content_hash in its content_hash column, so a
    later reader can recompute-and-verify it (D14)."""
    recorder = ExecutionRecorder()
    crid = _new_id()
    aid = _new_id()
    fields = _fields(campaign_run_id=crid, attempt_id=aid)
    with migrated_db.begin() as conn:
        recorder.record(fields, conn)
    with migrated_db.connect() as conn:
        row_hash = conn.execute(
            text(
                "SELECT content_hash FROM attempt_result "
                "WHERE campaign_run_id = :crid AND attempt_id = :aid"
            ),
            {"crid": crid, "aid": aid},
        ).scalar_one()
    assert row_hash == recorder.canonical_hash(fields)


# ===========================================================================
# AC-2 (D14) — recompute-and-verify: FAIL CLOSED on any mismatch/missing hash.
# ===========================================================================
def test_verify_passes_for_an_untampered_record(migrated_db: Engine) -> None:
    """A record whose stored hash still matches its content verifies successfully."""
    recorder = ExecutionRecorder()
    fields = _fields(campaign_run_id=_new_id(), attempt_id=_new_id())
    with migrated_db.begin() as conn:
        stored = recorder.record(fields, conn)
    recorder.verify(stored)  # must not raise


def test_verify_fails_closed_on_a_tampered_record() -> None:
    """If the stored content_hash no longer matches a recompute of the fields, verify() FAILS
    CLOSED with a typed evidence-integrity error — it never returns a passing verdict on
    tampered evidence."""
    recorder = ExecutionRecorder()
    fields = _fields(campaign_run_id="run-t", attempt_id="att-t")
    good_hash = recorder.canonical_hash(fields)
    tampered = dict(fields, response_transcript="TAMPERED", content_hash=good_hash)
    with pytest.raises(EvidenceIntegrityError):
        recorder.verify(tampered)


def test_verify_fails_closed_on_a_missing_hash() -> None:
    """A record with a missing/empty content_hash FAILS CLOSED (evidence-missing/integrity) —
    an unhashed record is never trusted."""
    recorder = ExecutionRecorder()
    fields = _fields(campaign_run_id="run-m", attempt_id="att-m")
    fields["content_hash"] = ""
    with pytest.raises(EvidenceIntegrityError):
        recorder.verify(fields)


# ===========================================================================
# AC-4 (S3) — a duplicate (campaign_run_id, attempt_id) is REJECTED by the DB UNIQUE,
# surfaced as a typed replay error — never an overwrite.
# ===========================================================================
def test_replayed_pair_is_rejected_not_overwritten(migrated_db: Engine) -> None:
    """A second record() of the SAME (campaign_run_id, attempt_id) is rejected via the DB
    UNIQUE constraint and surfaced as a typed ReplayRejectedError — the original row is NOT
    overwritten (append-only + run-nonce = S3 replay defense)."""
    recorder = ExecutionRecorder()
    crid = _new_id()
    aid = _new_id()
    first = _fields(campaign_run_id=crid, attempt_id=aid)
    with migrated_db.begin() as conn:
        recorder.record(first, conn)

    # Same pair, different evidence — must be rejected, and must not clobber the first row.
    replay = _fields(campaign_run_id=crid, attempt_id=aid)
    replay["response_transcript"] = "DIFFERENT — a replay attempt"
    with pytest.raises(ReplayRejectedError), migrated_db.begin() as conn:
        recorder.record(replay, conn)

    assert _count_rows(migrated_db, crid) == 1  # still exactly the original row


def test_non_unique_integrity_error_is_not_mislabeled_as_replay(migrated_db: Engine) -> None:
    """Only a genuine UNIQUE(campaign_run_id, attempt_id) conflict (SQLSTATE 23505) is a
    replay. A different integrity violation — here a NOT-NULL breach (23502) — must surface as
    the DB's own IntegrityError, NEVER be relabeled ReplayRejectedError, so genuine evidence
    corruption is not silently masked as a benign duplicate (resolves the Important finding)."""
    recorder = ExecutionRecorder()
    fields = _fields()
    fields["campaign_run_id"] = None  # force a NOT-NULL violation (23502), not a replay (23505)
    with migrated_db.begin() as conn, pytest.raises(IntegrityError) as exc:
        recorder.record(fields, conn)
    assert not isinstance(exc.value, ReplayRejectedError)
    assert exc.value.orig.sqlstate == "23502"  # NOT NULL — genuinely not a replay


def test_distinct_pairs_both_persist(migrated_db: Engine) -> None:
    """Two records that differ only in attempt_id both persist — the UNIQUE key is the PAIR,
    not the run id alone (so distinct attempts under one run are all recorded)."""
    recorder = ExecutionRecorder()
    crid = _new_id()
    with migrated_db.begin() as conn:
        recorder.record(_fields(campaign_run_id=crid, attempt_id=_new_id()), conn)
        recorder.record(_fields(campaign_run_id=crid, attempt_id=_new_id()), conn)
    assert _count_rows(migrated_db, crid) == 2


# ===========================================================================
# AC-4 / S2 — the recorder only ever APPENDS: it exposes no update/delete path.
# ===========================================================================
def test_recorder_exposes_no_update_or_delete() -> None:
    """The recorder is append-only by construction: it offers record() (INSERT) + verify(),
    and NO update/delete/overwrite method — append-only is not merely a DB grant, the code
    surface has no mutation path either."""
    for banned in ("update", "delete", "overwrite", "upsert", "modify"):
        assert not hasattr(ExecutionRecorder, banned)
