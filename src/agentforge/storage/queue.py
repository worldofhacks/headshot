"""Durable Postgres queue with short SKIP LOCKED claims and bounded leases.

This module implements M3's two logical queues. Delivery is deliberately *at least once*:
claiming commits before a worker processes the payload, expired work is recovered, and the
matching lease token is required for terminal queue commitment. Consumers must still make
their external effects idempotent; the queue never claims exactly-once execution.

All eligibility and lease comparisons use database time. No target, model, policy, or
campaign decision is made here.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sqlalchemy import Engine, text
from sqlalchemy.engine import RowMapping

_DEFAULT_LEASE = datetime.timedelta(seconds=60)
_MAX_LEASE = datetime.timedelta(hours=24)
_MAX_PAYLOAD_BYTES = 1_048_576
_MAX_POISON_ROWS_PER_TRANSACTION = 32
_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class QueueError(RuntimeError):
    """Base class for typed queue failures."""


class InvalidQueueError(QueueError):
    """The requested logical queue is not one of the two M3 queues."""


class UnsupportedPayloadError(QueueError):
    """A payload schema/version is not trusted by this queue process."""


class IdempotencyConflictError(QueueError):
    """A deduplication identity already names different immutable work."""


class LeaseLostError(QueueError):
    """The caller no longer owns the active lease required by an operation."""


class JobNotFoundError(QueueError):
    """No queue row exists for the requested immutable job ID."""


class LogicalQueue(StrEnum):
    """The complete, closed set of M3 logical queues."""

    AGENT_WORK = "agent_work"
    REGRESSION_RUN = "regression_run"


class JobStatus(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    DEAD_LETTER = "dead_letter"


class CompletionOutcome(StrEnum):
    COMMITTED = "committed"
    ALREADY_COMMITTED = "already_committed"


class FailureOutcome(StrEnum):
    RETRY_SCHEDULED = "retry_scheduled"
    DEAD_LETTERED = "dead_lettered"


class CancellationOutcome(StrEnum):
    CANCELLED = "cancelled"
    ALREADY_CANCELLED = "already_cancelled"
    NOT_CANCELLABLE = "not_cancellable"


@dataclass(frozen=True, slots=True)
class JobRecord:
    """An immutable copy of one durable queue row."""

    job_id: str
    queue: LogicalQueue
    campaign_run_id: str
    attempt_id: str
    payload_schema: str
    payload_version: int
    payload: Any = field(repr=False)
    priority: int
    run_after: datetime.datetime
    attempts: int
    max_attempts: int
    status: JobStatus
    worker_id: str | None
    lease_token: str | None = field(repr=False)
    leased_at: datetime.datetime | None
    lease_expires_at: datetime.datetime | None
    last_heartbeat_at: datetime.datetime | None
    last_failure_code: str | None
    last_failure_message: str | None
    last_failure_at: datetime.datetime | None
    completed_at: datetime.datetime | None
    cancelled_at: datetime.datetime | None
    dead_lettered_at: datetime.datetime | None
    created_at: datetime.datetime
    updated_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class CompletionReceipt:
    job_id: str
    outcome: CompletionOutcome
    completed_at: datetime.datetime


@dataclass(frozen=True, slots=True)
class ReapResult:
    requeued_job_ids: tuple[str, ...]
    dead_lettered_job_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BackpressureResult:
    queue: LogicalQueue
    depth: int
    threshold: int
    active: bool


def _logical_queue(value: LogicalQueue | str) -> LogicalQueue:
    try:
        return LogicalQueue(value)
    except (TypeError, ValueError) as exc:
        raise InvalidQueueError("queue must be agent_work or regression_run") from exc


def _job_status(value: JobStatus | str) -> JobStatus:
    try:
        return JobStatus(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("unknown job status") from exc


def _bounded_identifier(value: str, *, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} must contain 1 to {maximum} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _positive_duration(
    value: datetime.timedelta,
    *,
    field: str,
    allow_zero: bool = False,
) -> float:
    if not isinstance(value, datetime.timedelta):
        raise TypeError(f"{field} must be a timedelta")
    seconds = value.total_seconds()
    if seconds < 0 or (seconds == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{field} must be {qualifier}")
    if value > _MAX_LEASE:
        raise ValueError(f"{field} must not exceed {_MAX_LEASE}")
    return seconds


def _normalized_run_after(value: datetime.datetime | None) -> datetime.datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime.datetime) or value.tzinfo is None:
        raise ValueError("run_after must be a timezone-aware datetime")
    return value.astimezone(datetime.UTC)


def _canonical_payload(payload: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    if not isinstance(payload, Mapping):
        raise TypeError("payload must be a JSON object")
    try:
        encoded = json.dumps(
            dict(payload),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("payload must be a valid JSON object") from exc
    if len(encoded.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise ValueError("payload exceeds the 1 MiB queue limit")
    canonical = json.loads(encoded)
    if not isinstance(canonical, dict):  # Defensive: the public type is a Mapping.
        raise TypeError("payload must be a JSON object")
    return canonical, encoded


def _sanitize_failure_message(message: str | None) -> str | None:
    if message is None:
        return None
    if not isinstance(message, str):
        raise TypeError("failure_message must be a string or None")
    # Caller detail may contain a DSN, header, token, hostile payload, or exception repr.
    # Pattern-based redaction cannot prove absence, so persist only an allowlisted summary.
    return "worker-supplied failure detail omitted" if message else None


class PostgresJobQueue:
    """Postgres-backed M3 queue API.

    ``supported_payload_versions`` is trusted process configuration. Attack-controlled
    payload data cannot register a version or choose queue behavior.
    """

    def __init__(
        self,
        engine: Engine,
        *,
        supported_payload_versions: Mapping[LogicalQueue | str, Mapping[str, Iterable[int]]]
        | None = None,
    ) -> None:
        self._engine = engine
        configured = (
            {
                LogicalQueue.AGENT_WORK: {LogicalQueue.AGENT_WORK.value: (1,)},
                LogicalQueue.REGRESSION_RUN: {LogicalQueue.REGRESSION_RUN.value: (1,)},
            }
            if supported_payload_versions is None
            else supported_payload_versions
        )
        normalized: dict[LogicalQueue, dict[str, frozenset[int]]] = {}
        for queue, schemas in configured.items():
            logical_queue = _logical_queue(queue)
            normalized[logical_queue] = {
                _bounded_identifier(schema, field="payload_schema", maximum=64): frozenset(versions)
                for schema, versions in schemas.items()
            }
        self._supported_payload_versions = normalized

    def _supports(self, queue: LogicalQueue, schema: str, version: int) -> bool:
        return version in self._supported_payload_versions.get(queue, {}).get(schema, frozenset())

    @staticmethod
    def _record(row: RowMapping) -> JobRecord:
        # JSON round-tripping returns a detached copy and remains safe for a malformed poison
        # row whose JSONB value is not the object required for dispatch.
        payload = json.loads(json.dumps(row["payload"], allow_nan=False))
        return JobRecord(
            job_id=row["job_id"],
            queue=LogicalQueue(row["queue"]),
            campaign_run_id=row["campaign_run_id"],
            attempt_id=row["attempt_id"],
            payload_schema=row["payload_schema"],
            payload_version=row["payload_version"],
            payload=payload,
            priority=row["priority"],
            run_after=row["run_after"],
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            status=JobStatus(row["status"]),
            worker_id=row["worker_id"],
            lease_token=row["lease_token"],
            leased_at=row["leased_at"],
            lease_expires_at=row["lease_expires_at"],
            last_heartbeat_at=row["last_heartbeat_at"],
            last_failure_code=row["last_failure_code"],
            last_failure_message=row["last_failure_message"],
            last_failure_at=row["last_failure_at"],
            completed_at=row["completed_at"],
            cancelled_at=row["cancelled_at"],
            dead_lettered_at=row["dead_lettered_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def enqueue(
        self,
        *,
        queue: LogicalQueue | str,
        campaign_run_id: str,
        attempt_id: str,
        payload_schema: str,
        payload_version: int,
        payload: Mapping[str, Any],
        priority: int = 0,
        run_after: datetime.datetime | None = None,
        max_attempts: int = 3,
    ) -> JobRecord:
        logical_queue = _logical_queue(queue)
        campaign_run_id = _bounded_identifier(campaign_run_id, field="campaign_run_id", maximum=64)
        attempt_id = _bounded_identifier(attempt_id, field="attempt_id", maximum=64)
        payload_schema = _bounded_identifier(payload_schema, field="payload_schema", maximum=64)
        if isinstance(payload_version, bool) or not isinstance(payload_version, int):
            raise TypeError("payload_version must be an integer")
        if payload_version <= 0 or not self._supports(
            logical_queue, payload_schema, payload_version
        ):
            raise UnsupportedPayloadError("payload schema/version is not supported")
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise TypeError("priority must be an integer")
        if not -(2**31) <= priority < 2**31:
            raise ValueError("priority is outside the Postgres integer range")
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int):
            raise TypeError("max_attempts must be an integer")
        if not 1 <= max_attempts <= 100_000:
            raise ValueError("max_attempts must be between 1 and 100000")
        scheduled_at = _normalized_run_after(run_after)
        canonical_payload, payload_json = _canonical_payload(payload)

        identity = f"m3-job:v1\0{logical_queue.value}\0{campaign_run_id}\0{attempt_id}"
        job_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        fingerprint_document = {
            "max_attempts": max_attempts,
            "payload": canonical_payload,
            "payload_schema": payload_schema,
            "payload_version": payload_version,
            "priority": priority,
            "run_after": scheduled_at.isoformat() if scheduled_at else "immediate",
        }
        fingerprint = hashlib.sha256(
            json.dumps(
                fingerprint_document,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

        insert = text(
            "INSERT INTO jobs ("
            "job_id, queue, campaign_run_id, attempt_id, payload_schema, payload_version, "
            "payload, enqueue_fingerprint, priority, run_after, max_attempts"
            ") VALUES ("
            ":job_id, CAST(:queue AS job_queue), :campaign_run_id, :attempt_id, "
            ":payload_schema, :payload_version, CAST(:payload AS jsonb), :fingerprint, "
            ":priority, COALESCE(CAST(:run_after AS timestamptz), clock_timestamp()), "
            ":max_attempts"
            ") ON CONFLICT DO NOTHING RETURNING *"
        )
        parameters = {
            "job_id": job_id,
            "queue": logical_queue.value,
            "campaign_run_id": campaign_run_id,
            "attempt_id": attempt_id,
            "payload_schema": payload_schema,
            "payload_version": payload_version,
            "payload": payload_json,
            "fingerprint": fingerprint,
            "priority": priority,
            "run_after": scheduled_at,
            "max_attempts": max_attempts,
        }
        with self._engine.begin() as connection:
            row = connection.execute(insert, parameters).mappings().one_or_none()
            if row is None:
                row = (
                    connection.execute(
                        text(
                            "SELECT * FROM jobs WHERE queue = CAST(:queue AS job_queue) "
                            "AND campaign_run_id = :campaign_run_id AND attempt_id = :attempt_id"
                        ),
                        parameters,
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None or row["enqueue_fingerprint"] != fingerprint:
                    raise IdempotencyConflictError(
                        "deduplication identity already names different immutable work"
                    )
            record = self._record(row)
        return record

    def claim(
        self,
        queue: LogicalQueue | str,
        *,
        worker_id: str,
        lease_duration: datetime.timedelta = _DEFAULT_LEASE,
    ) -> JobRecord | None:
        logical_queue = _logical_queue(queue)
        worker_id = _bounded_identifier(worker_id, field="worker_id", maximum=128)
        lease_seconds = _positive_duration(lease_duration, field="lease_duration")
        selected = text(
            "SELECT * FROM jobs WHERE queue = CAST(:queue AS job_queue) "
            "AND status = 'queued'::job_status AND attempts < max_attempts "
            "AND run_after <= clock_timestamp() "
            "ORDER BY priority DESC, run_after ASC, id ASC "
            "FOR UPDATE SKIP LOCKED LIMIT 1"
        )
        lease = text(
            "UPDATE jobs SET status = 'leased'::job_status, worker_id = :worker_id, "
            "lease_token = :lease_token, leased_at = lease_clock.now, "
            "last_heartbeat_at = lease_clock.now, "
            "lease_expires_at = lease_clock.now + (:lease_seconds * interval '1 second'), "
            "attempts = attempts + 1, updated_at = lease_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS lease_clock "
            "WHERE jobs.id = :id AND jobs.status = 'queued'::job_status RETURNING jobs.*"
        )
        dead_letter_poison = text(
            "UPDATE jobs SET status = 'dead_letter'::job_status, "
            "last_failure_code = :failure_code, last_failure_message = :failure_message, "
            "last_failure_at = poison_clock.now, dead_lettered_at = poison_clock.now, "
            "updated_at = poison_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS poison_clock "
            "WHERE jobs.id = :id AND jobs.status = 'queued'::job_status"
        )
        while True:
            claimed_row: RowMapping | None = None
            queue_empty = False
            # A poison backlog is drained in bounded transactions. After each commit, this
            # logical claim continues so ``None`` never falsely signals an empty queue.
            with self._engine.begin() as connection:
                for _ in range(_MAX_POISON_ROWS_PER_TRANSACTION):
                    candidate = (
                        connection.execute(selected, {"queue": logical_queue.value})
                        .mappings()
                        .one_or_none()
                    )
                    if candidate is None:
                        queue_empty = True
                        break
                    poison_reason = self._poison_reason(logical_queue, candidate)
                    if poison_reason is not None:
                        failure_code, failure_message = poison_reason
                        connection.execute(
                            dead_letter_poison,
                            {
                                "id": candidate["id"],
                                "failure_code": failure_code,
                                "failure_message": failure_message,
                            },
                        )
                        continue
                    claimed_row = (
                        connection.execute(
                            lease,
                            {
                                "id": candidate["id"],
                                "worker_id": worker_id,
                                "lease_token": secrets.token_urlsafe(32),
                                "lease_seconds": lease_seconds,
                            },
                        )
                        .mappings()
                        .one()
                    )
                    break
            if claimed_row is not None:
                return self._record(claimed_row)
            if queue_empty:
                return None

    def _poison_reason(self, queue: LogicalQueue, candidate: RowMapping) -> tuple[str, str] | None:
        if not self._supports(
            queue,
            candidate["payload_schema"],
            candidate["payload_version"],
        ):
            return (
                "unsupported_payload_version",
                "payload schema/version is not supported by this worker",
            )
        payload = candidate["payload"]
        if not isinstance(payload, dict):
            return ("malformed_payload", "payload is not a JSON object")
        encoded = json.dumps(payload, allow_nan=False, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
            return ("malformed_payload", "payload exceeds the dispatch size limit")
        return None

    def get(self, job_id: str) -> JobRecord:
        job_id = _bounded_identifier(job_id, field="job_id", maximum=64)
        with self._engine.connect() as connection:
            row = (
                connection.execute(
                    text("SELECT * FROM jobs WHERE job_id = :job_id"),
                    {"job_id": job_id},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise JobNotFoundError("job does not exist")
        return self._record(row)

    def heartbeat(
        self,
        claimed: JobRecord,
        *,
        extension: datetime.timedelta = _DEFAULT_LEASE,
    ) -> datetime.datetime:
        worker_id, lease_token = self._lease_credentials(claimed)
        extension_seconds = _positive_duration(extension, field="extension")
        statement = text(
            "UPDATE jobs SET "
            "lease_expires_at = GREATEST(lease_expires_at, "
            "heartbeat_clock.now + (:extension_seconds * interval '1 second')), "
            "last_heartbeat_at = heartbeat_clock.now, updated_at = heartbeat_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS heartbeat_clock "
            "WHERE jobs.job_id = :job_id AND jobs.status = 'leased'::job_status "
            "AND jobs.worker_id = :worker_id AND jobs.lease_token = :lease_token "
            "AND jobs.lease_expires_at > heartbeat_clock.now "
            "RETURNING jobs.lease_expires_at"
        )
        with self._engine.begin() as connection:
            expires_at = connection.execute(
                statement,
                {
                    "job_id": claimed.job_id,
                    "worker_id": worker_id,
                    "lease_token": lease_token,
                    "extension_seconds": extension_seconds,
                },
            ).scalar_one_or_none()
        if expires_at is None:
            raise LeaseLostError("active lease ownership could not be verified")
        return expires_at

    def fail(
        self,
        claimed: JobRecord,
        *,
        failure_code: str,
        failure_message: str | None = None,
        retryable: bool,
        retry_delay: datetime.timedelta = datetime.timedelta(0),
    ) -> FailureOutcome:
        worker_id, lease_token = self._lease_credentials(claimed)
        if not isinstance(failure_code, str) or not _FAILURE_CODE.fullmatch(failure_code):
            raise ValueError("failure_code must be a lowercase bounded identifier")
        safe_message = _sanitize_failure_message(failure_message)
        retry_seconds = _positive_duration(retry_delay, field="retry_delay", allow_zero=True)
        statement = text(
            "UPDATE jobs SET "
            "status = CASE WHEN :retryable AND attempts < max_attempts "
            "THEN 'queued'::job_status ELSE 'dead_letter'::job_status END, "
            "run_after = CASE WHEN :retryable AND attempts < max_attempts "
            "THEN GREATEST(run_after, failure_clock.now + "
            "(:retry_seconds * interval '1 second')) ELSE run_after END, "
            "last_failure_code = :failure_code, last_failure_message = :failure_message, "
            "last_failure_at = failure_clock.now, last_failure_worker_id = worker_id, "
            "dead_lettered_at = CASE WHEN :retryable AND attempts < max_attempts "
            "THEN NULL ELSE failure_clock.now END, "
            "worker_id = NULL, lease_token = NULL, leased_at = NULL, "
            "lease_expires_at = NULL, last_heartbeat_at = NULL, updated_at = failure_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS failure_clock "
            "WHERE jobs.job_id = :job_id AND jobs.status = 'leased'::job_status "
            "AND jobs.worker_id = :worker_id AND jobs.lease_token = :lease_token "
            "AND jobs.lease_expires_at > failure_clock.now RETURNING jobs.status"
        )
        with self._engine.begin() as connection:
            status = connection.execute(
                statement,
                {
                    "job_id": claimed.job_id,
                    "worker_id": worker_id,
                    "lease_token": lease_token,
                    "retryable": retryable,
                    "retry_seconds": retry_seconds,
                    "failure_code": failure_code,
                    "failure_message": safe_message,
                },
            ).scalar_one_or_none()
        if status is None:
            raise LeaseLostError("active lease ownership could not be verified")
        if JobStatus(status) is JobStatus.QUEUED:
            return FailureOutcome.RETRY_SCHEDULED
        return FailureOutcome.DEAD_LETTERED

    def reap_expired(self, *, limit: int = 100) -> ReapResult:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("limit must be a positive integer")
        select_expired = text(
            "SELECT id, job_id, attempts, max_attempts FROM jobs "
            "WHERE status = 'leased'::job_status AND lease_expires_at <= clock_timestamp() "
            "ORDER BY lease_expires_at ASC, id ASC FOR UPDATE SKIP LOCKED LIMIT :limit"
        )
        requeue = text(
            "UPDATE jobs SET status = 'queued'::job_status, run_after = reap_clock.now, "
            "last_failure_code = 'lease_expired', "
            "last_failure_message = 'lease expired before completion', "
            "last_failure_at = reap_clock.now, last_failure_worker_id = worker_id, "
            "worker_id = NULL, lease_token = NULL, leased_at = NULL, "
            "lease_expires_at = NULL, last_heartbeat_at = NULL, updated_at = reap_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS reap_clock WHERE jobs.id = :id"
        )
        dead_letter = text(
            "UPDATE jobs SET status = 'dead_letter'::job_status, "
            "last_failure_code = 'lease_attempts_exhausted', "
            "last_failure_message = 'lease expired at the maximum attempt count', "
            "last_failure_at = reap_clock.now, last_failure_worker_id = worker_id, "
            "dead_lettered_at = reap_clock.now, worker_id = NULL, lease_token = NULL, "
            "leased_at = NULL, lease_expires_at = NULL, last_heartbeat_at = NULL, "
            "updated_at = reap_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS reap_clock WHERE jobs.id = :id"
        )
        requeued: list[str] = []
        dead_lettered: list[str] = []
        with self._engine.begin() as connection:
            rows = connection.execute(select_expired, {"limit": limit}).mappings().all()
            for row in rows:
                if row["attempts"] >= row["max_attempts"]:
                    connection.execute(dead_letter, {"id": row["id"]})
                    dead_lettered.append(row["job_id"])
                else:
                    connection.execute(requeue, {"id": row["id"]})
                    requeued.append(row["job_id"])
        return ReapResult(tuple(requeued), tuple(dead_lettered))

    def complete(self, claimed: JobRecord) -> CompletionReceipt:
        worker_id, lease_token = self._lease_credentials(claimed)
        commit = text(
            "UPDATE jobs SET status = 'completed'::job_status, "
            "completion_worker_id = worker_id, completion_lease_token = lease_token, "
            "completed_at = completion_clock.now, worker_id = NULL, lease_token = NULL, "
            "leased_at = NULL, lease_expires_at = NULL, last_heartbeat_at = NULL, "
            "updated_at = completion_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS completion_clock "
            "WHERE jobs.job_id = :job_id AND jobs.status = 'leased'::job_status "
            "AND jobs.worker_id = :worker_id AND jobs.lease_token = :lease_token "
            "AND jobs.lease_expires_at > completion_clock.now RETURNING jobs.completed_at"
        )
        inspect = text(
            "SELECT status, completion_worker_id, completion_lease_token, completed_at "
            "FROM jobs WHERE job_id = :job_id"
        )
        with self._engine.begin() as connection:
            completed_at = connection.execute(
                commit,
                {
                    "job_id": claimed.job_id,
                    "worker_id": worker_id,
                    "lease_token": lease_token,
                },
            ).scalar_one_or_none()
            if completed_at is not None:
                return CompletionReceipt(claimed.job_id, CompletionOutcome.COMMITTED, completed_at)
            row = connection.execute(inspect, {"job_id": claimed.job_id}).mappings().one_or_none()
            if (
                row is not None
                and JobStatus(row["status"]) is JobStatus.COMPLETED
                and row["completion_worker_id"] == worker_id
                and row["completion_lease_token"] == lease_token
            ):
                return CompletionReceipt(
                    claimed.job_id,
                    CompletionOutcome.ALREADY_COMMITTED,
                    row["completed_at"],
                )
        raise LeaseLostError("active or completed lease ownership could not be verified")

    def cancel(self, job_id: str) -> CancellationOutcome:
        job_id = _bounded_identifier(job_id, field="job_id", maximum=64)
        cancel = text(
            "UPDATE jobs SET status = 'cancelled'::job_status, "
            "cancelled_at = cancel_clock.now, updated_at = cancel_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS cancel_clock "
            "WHERE jobs.job_id = :job_id AND jobs.status = 'queued'::job_status "
            "RETURNING jobs.status"
        )
        with self._engine.begin() as connection:
            cancelled = connection.execute(cancel, {"job_id": job_id}).scalar_one_or_none()
            if cancelled is not None:
                return CancellationOutcome.CANCELLED
            status = connection.execute(
                text("SELECT status FROM jobs WHERE job_id = :job_id"),
                {"job_id": job_id},
            ).scalar_one_or_none()
        if status is None:
            raise JobNotFoundError("job does not exist")
        if JobStatus(status) is JobStatus.CANCELLED:
            return CancellationOutcome.ALREADY_CANCELLED
        return CancellationOutcome.NOT_CANCELLABLE

    def cancel_campaign(
        self,
        campaign_run_id: str,
        *,
        queue: LogicalQueue | str | None = None,
    ) -> int:
        campaign_run_id = _bounded_identifier(campaign_run_id, field="campaign_run_id", maximum=64)
        logical_queue = _logical_queue(queue) if queue is not None else None
        queue_predicate = (
            " AND jobs.queue = CAST(:queue AS job_queue)" if logical_queue is not None else ""
        )
        statement = text(
            "UPDATE jobs SET status = 'cancelled'::job_status, "
            "cancelled_at = cancel_clock.now, updated_at = cancel_clock.now "
            "FROM (SELECT clock_timestamp() AS now) AS cancel_clock "
            "WHERE jobs.campaign_run_id = :campaign_run_id "
            "AND jobs.status = 'queued'::job_status" + queue_predicate
        )
        parameters = {"campaign_run_id": campaign_run_id}
        if logical_queue is not None:
            parameters["queue"] = logical_queue.value
        with self._engine.begin() as connection:
            result = connection.execute(statement, parameters)
        return result.rowcount

    def depth(self, queue: LogicalQueue | str, status: JobStatus | str) -> int:
        logical_queue = _logical_queue(queue)
        job_status = _job_status(status)
        with self._engine.connect() as connection:
            return connection.execute(
                text(
                    "SELECT count(*) FROM jobs WHERE queue = CAST(:queue AS job_queue) "
                    "AND status = CAST(:status AS job_status)"
                ),
                {"queue": logical_queue.value, "status": job_status.value},
            ).scalar_one()

    def backpressure(
        self,
        queue: LogicalQueue | str,
        *,
        threshold: int,
    ) -> BackpressureResult:
        logical_queue = _logical_queue(queue)
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold <= 0:
            raise ValueError("threshold must be a positive integer")
        depth = self.depth(logical_queue, JobStatus.QUEUED)
        return BackpressureResult(logical_queue, depth, threshold, depth >= threshold)

    @staticmethod
    def _lease_credentials(claimed: JobRecord) -> tuple[str, str]:
        if not isinstance(claimed, JobRecord):
            raise TypeError("operation requires a claimed JobRecord")
        if claimed.worker_id is None or claimed.lease_token is None:
            raise LeaseLostError("job record does not carry lease credentials")
        return claimed.worker_id, claimed.lease_token
