"""Execution Recorder — canonical-hash, append-only evidence writer (ARCHITECTURE §4/§5, D14).

The recorder is the authoritative sink for attempt evidence. It:

* computes a canonical ``content_hash`` — a sorted-key, UTF-8 JSON serialization hashed with
  sha256 (D14). The hash is a pure function of the D14 field set, independent of dict order,
  so the Judge/Orchestrator can recompute-and-verify it independently before every read.
* INSERTs the hashed evidence **APPEND-ONLY** into ``attempt_result`` — INSERT only, never
  UPDATE / DELETE. The class exposes no mutation method at all (append-only is a property of
  the code surface, not merely a DB grant — S2).
* :meth:`verify` recomputes the hash and **FAILS CLOSED** on any mismatch or missing hash
  (:class:`EvidenceIntegrityError`) — tampered or unhashed evidence is never trusted.
* surfaces a duplicate ``(campaign_run_id, attempt_id)`` — rejected by the DB UNIQUE (the
  storage half of the S3 replay defense) — as a typed :class:`ReplayRejectedError`, never an
  overwrite.

SQLAlchemy is imported here because this is a storage-adjacent policy component; it never
imports a web framework (D10).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

# The field that carries the digest itself is NEVER part of the hashed payload — the hash is
# computed over the evidence, then stored alongside it.
_HASH_FIELD = "content_hash"

# Postgres SQLSTATE for a unique-constraint violation — the ONLY integrity error that is a
# replay. Any other IntegrityError (NOT NULL 23502, FK 23503, CHECK 23514) is real corruption.
_UNIQUE_VIOLATION = "23505"

# The D14 attempt_result columns the recorder persists (the authoritative evidence field set).
# Only these keys are written; extra keys in the field mapping are hashed but not columns.
_PERSISTED_COLUMNS: tuple[str, ...] = (
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
    "recorder_identity",
    "recorder_version",
)

# Columns whose SQL type is JSONB — serialized to a JSON string for the psycopg parameter.
_JSONB_COLUMNS: frozenset[str] = frozenset({"attack_attempt", "request_transcript"})


class EvidenceIntegrityError(Exception):
    """Raised when a record's stored ``content_hash`` does not match a recompute, or is
    missing/empty — :meth:`ExecutionRecorder.verify` FAILS CLOSED rather than returning a
    passing verdict over untrustworthy evidence (D14)."""


class ReplayRejectedError(Exception):
    """Raised when a duplicate ``(campaign_run_id, attempt_id)`` pair is rejected by the DB
    UNIQUE constraint (S3 replay defense). The original row is NOT overwritten — the replay is
    refused with this typed error."""


@dataclass(frozen=True)
class StoredRecord:
    """The evidence a :meth:`ExecutionRecorder.record` call appended: the canonical
    ``content_hash`` plus an immutable copy of the exact fields it was computed over."""

    content_hash: str
    fields: dict[str, Any]


def _canonical_bytes(fields: dict[str, Any]) -> bytes:
    """Serialize ``fields`` to canonical bytes: sorted keys, no whitespace ambiguity, UTF-8.

    The ``content_hash`` key (if present) is excluded so a record can be re-hashed with its
    own digest embedded and still reproduce the original hash. ``sort_keys=True`` makes the
    serialization field-order independent; ``ensure_ascii=False`` + explicit separators keep
    it stable and byte-reproducible for an independent recompute.
    """
    payload = {k: v for k, v in fields.items() if k != _HASH_FIELD}
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


class ExecutionRecorder:
    """Append-only, hash-verified evidence recorder.

    The surface is deliberately minimal — ``canonical_hash``, ``record``, ``verify`` — and
    carries NO update/delete/overwrite/upsert/modify method: append-only is enforced by the
    absence of any mutation path in the code, not only by a DB grant (S2).
    """

    def canonical_hash(self, fields: dict[str, Any]) -> str:
        """Return the canonical sha256 hex digest (64 lowercase hex chars) of ``fields``.

        A pure function of the field content, independent of dict ordering (D14) — the same
        content always hashes to the same digest, so any reader can recompute and verify it.
        """
        return hashlib.sha256(_canonical_bytes(fields)).hexdigest()

    def record(self, fields: dict[str, Any], conn: Connection) -> StoredRecord:
        """Compute the canonical hash and APPEND (INSERT only) one row to ``attempt_result``.

        A duplicate ``(campaign_run_id, attempt_id)`` is rejected by the DB UNIQUE constraint
        and surfaced as :class:`ReplayRejectedError` — the existing row is never overwritten
        (no UPDATE/UPSERT path exists). Returns the :class:`StoredRecord` (hash + fields).
        """
        content_hash = self.canonical_hash(fields)
        params: dict[str, Any] = {_HASH_FIELD: content_hash}
        for column in _PERSISTED_COLUMNS:
            value = fields.get(column)
            if column in _JSONB_COLUMNS and value is not None:
                value = json.dumps(value)
            params[column] = value

        columns = (*_PERSISTED_COLUMNS, _HASH_FIELD)
        placeholders = ", ".join(
            f"CAST(:{col} AS JSONB)" if col in _JSONB_COLUMNS else f":{col}" for col in columns
        )
        statement = text(
            f"INSERT INTO attempt_result ({', '.join(columns)}) VALUES ({placeholders})"
        )
        try:
            conn.execute(statement, params)
        except IntegrityError as exc:
            # ONLY a genuine UNIQUE(campaign_run_id, attempt_id) conflict is a replay (SQLSTATE
            # 23505). A NOT-NULL / FK / CHECK violation (23502/23503/23514) is real evidence
            # corruption — re-raise it unchanged rather than masking it as a benign duplicate.
            sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
            if sqlstate != _UNIQUE_VIOLATION:
                raise
            raise ReplayRejectedError(
                "duplicate (campaign_run_id="
                f"{fields.get('campaign_run_id')!r}, attempt_id={fields.get('attempt_id')!r}) "
                "rejected by the append-only replay UNIQUE — the original evidence is not "
                "overwritten (S3)"
            ) from exc

        return StoredRecord(content_hash=content_hash, fields=dict(fields))

    def verify(self, record: StoredRecord | dict[str, Any]) -> None:
        """Recompute the canonical hash and FAIL CLOSED on any mismatch or missing hash.

        Accepts either a :class:`StoredRecord` (from :meth:`record`) or a raw field mapping
        with an embedded ``content_hash``. A missing/empty stored hash, or a hash that no
        longer matches a recompute of the fields, raises :class:`EvidenceIntegrityError` — an
        untrustworthy record never verifies (D14)."""
        if isinstance(record, StoredRecord):
            fields = record.fields
            stored_hash = record.content_hash
        else:
            fields = record
            stored_hash = record.get(_HASH_FIELD, "")

        if not stored_hash:
            raise EvidenceIntegrityError(
                "record has no content_hash — an unhashed record is never trusted "
                "(fail closed, D14)"
            )
        recomputed = self.canonical_hash(fields)
        if recomputed != stored_hash:
            raise EvidenceIntegrityError(
                "content_hash mismatch on recompute — evidence has been tampered with; "
                "verification FAILS CLOSED (D14)"
            )
