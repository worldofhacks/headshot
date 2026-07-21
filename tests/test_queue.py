"""M3 durable Postgres queue integration tests.

Every behavioral assertion runs against the real ephemeral Postgres fixture. Locking,
SKIP LOCKED, leases, database-time comparisons, uniqueness, and migrations are never
simulated in memory.
"""

from __future__ import annotations

import datetime
import json
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import IntegrityError

import _db
from agentforge.storage.models import Base
from agentforge.storage.queue import (
    CancellationOutcome,
    CompletionOutcome,
    FailureOutcome,
    IdempotencyConflictError,
    InvalidQueueError,
    JobStatus,
    LeaseLostError,
    LogicalQueue,
    PostgresJobQueue,
    UnsupportedPayloadError,
)

REV_PRE_QUEUE = "0003"
REV_QUEUE = "0004"


def _identifier(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:20]}"


def _schema_for(queue: LogicalQueue) -> str:
    return queue.value


@pytest.fixture(autouse=True)
def _empty_jobs(migrated_db: Engine):
    """Keep the session-scoped database deterministic across queue tests."""
    with migrated_db.begin() as conn:
        conn.execute(text("TRUNCATE TABLE jobs RESTART IDENTITY"))
    yield
    with migrated_db.begin() as conn:
        conn.execute(text("TRUNCATE TABLE jobs RESTART IDENTITY"))


@pytest.fixture
def queue_store(migrated_db: Engine) -> PostgresJobQueue:
    return PostgresJobQueue(migrated_db)


def _enqueue(
    store: PostgresJobQueue,
    *,
    queue: LogicalQueue = LogicalQueue.AGENT_WORK,
    campaign_run_id: str | None = None,
    attempt_id: str | None = None,
    payload: dict[str, object] | None = None,
    payload_version: int = 1,
    priority: int = 0,
    run_after: datetime.datetime | None = None,
    max_attempts: int = 3,
):
    return store.enqueue(
        queue=queue,
        campaign_run_id=campaign_run_id or _identifier("run"),
        attempt_id=attempt_id or _identifier("attempt"),
        payload_schema=_schema_for(queue),
        payload_version=payload_version,
        payload=payload or {"fixture": "synthetic"},
        priority=priority,
        run_after=run_after,
        max_attempts=max_attempts,
    )


def _db_now(engine: Engine) -> datetime.datetime:
    with engine.connect() as conn:
        return conn.execute(text("SELECT clock_timestamp()")).scalar_one()


def _expire_lease(engine: Engine, job_id: str) -> None:
    """Expire a lease without sleeps while preserving the lease interval CHECK."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE jobs SET "
                "leased_at = clock_timestamp() - interval '2 seconds', "
                "last_heartbeat_at = clock_timestamp() - interval '2 seconds', "
                "lease_expires_at = clock_timestamp() - interval '1 second', "
                "updated_at = clock_timestamp() "
                "WHERE job_id = :job_id"
            ),
            {"job_id": job_id},
        )


def _job_row(engine: Engine, job_id: str):
    with engine.connect() as conn:
        return (
            conn.execute(text("SELECT * FROM jobs WHERE job_id = :job_id"), {"job_id": job_id})
            .mappings()
            .one()
        )


def test_enqueue_and_claim_happy_path(queue_store: PostgresJobQueue) -> None:
    enqueued = _enqueue(queue_store, priority=7)

    claimed = queue_store.claim(
        LogicalQueue.AGENT_WORK,
        worker_id="worker-alpha",
        lease_duration=datetime.timedelta(seconds=30),
    )

    assert claimed is not None
    assert claimed.job_id == enqueued.job_id
    assert claimed.worker_id == "worker-alpha"
    assert claimed.attempts == 1
    assert claimed.lease_expires_at > claimed.leased_at
    assert queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta") is None


def test_only_two_logical_queues_are_accepted(queue_store: PostgresJobQueue) -> None:
    assert {queue.value for queue in LogicalQueue} == {"agent_work", "regression_run"}

    with pytest.raises(InvalidQueueError):
        queue_store.enqueue(
            queue="other",  # type: ignore[arg-type]
            campaign_run_id=_identifier("run"),
            attempt_id=_identifier("attempt"),
            payload_schema="other",
            payload_version=1,
            payload={"fixture": "synthetic"},
        )


def test_priority_and_stable_tie_break_ordering(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    eligible_at = _db_now(migrated_db) - datetime.timedelta(seconds=1)
    low = _enqueue(queue_store, priority=1, run_after=eligible_at)
    high_first = _enqueue(queue_store, priority=9, run_after=eligible_at)
    high_second = _enqueue(queue_store, priority=9, run_after=eligible_at)

    claimed = [
        queue_store.claim(LogicalQueue.AGENT_WORK, worker_id=f"worker-{index}")
        for index in range(3)
    ]

    assert [job.job_id for job in claimed if job is not None] == [
        high_first.job_id,
        high_second.job_id,
        low.job_id,
    ]


def test_run_after_uses_inclusive_database_time_boundary(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    now = _db_now(migrated_db)
    eligible = _enqueue(queue_store, run_after=now)
    future = _enqueue(queue_store, run_after=now + datetime.timedelta(hours=1), priority=100)

    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")

    assert claimed is not None and claimed.job_id == eligible.job_id
    assert queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta") is None
    assert queue_store.get(future.job_id).status is JobStatus.QUEUED


def test_concurrent_workers_never_claim_the_same_active_lease(
    queue_store: PostgresJobQueue,
) -> None:
    enqueued = _enqueue(queue_store)
    barrier = Barrier(2)

    def claim(worker: str):
        barrier.wait()
        return queue_store.claim(LogicalQueue.AGENT_WORK, worker_id=worker)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, ("worker-alpha", "worker-beta")))

    claimed = [result for result in results if result is not None]
    assert len(claimed) == 1
    assert claimed[0].job_id == enqueued.job_id


def test_locked_job_does_not_block_another_eligible_job(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    first = _enqueue(queue_store, priority=10)
    second = _enqueue(queue_store, priority=5)
    bounded_engine = create_engine(
        migrated_db.url,
        connect_args={"options": "-c statement_timeout=1000"},
        pool_pre_ping=True,
    )
    bounded_store = PostgresJobQueue(bounded_engine)
    try:
        with migrated_db.connect() as locker:
            transaction = locker.begin()
            locker.execute(
                text("SELECT id FROM jobs WHERE job_id = :job_id FOR UPDATE"),
                {"job_id": first.job_id},
            )
            claimed = bounded_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta")
            transaction.rollback()
    finally:
        bounded_engine.dispose()

    assert claimed is not None and claimed.job_id == second.job_id


def test_claim_transaction_commits_before_processing(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    enqueued = _enqueue(queue_store)
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None

    with migrated_db.begin() as conn:
        locked_id = conn.execute(
            text("SELECT id FROM jobs WHERE job_id = :job_id FOR UPDATE NOWAIT"),
            {"job_id": enqueued.job_id},
        ).scalar_one()
    assert locked_id > 0


def test_claimed_record_repr_hides_hostile_payload_and_lease_capability(
    queue_store: PostgresJobQueue,
) -> None:
    hostile_marker = "HOSTILE-PAYLOAD-MUST-NOT-REACH-REPR"
    _enqueue(queue_store, payload={"untrusted": hostile_marker})
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None and claimed.lease_token is not None

    rendered = repr(claimed)

    assert hostile_marker not in rendered
    assert claimed.lease_token not in rendered


def test_active_owner_heartbeat_extends_but_never_shortens_lease(
    queue_store: PostgresJobQueue,
) -> None:
    _enqueue(queue_store)
    claimed = queue_store.claim(
        LogicalQueue.AGENT_WORK,
        worker_id="worker-alpha",
        lease_duration=datetime.timedelta(seconds=60),
    )
    assert claimed is not None

    extended = queue_store.heartbeat(claimed, extension=datetime.timedelta(seconds=120))
    not_shortened = queue_store.heartbeat(claimed, extension=datetime.timedelta(seconds=1))

    assert extended > claimed.lease_expires_at
    assert not_shortened >= extended


@pytest.mark.parametrize("field", ["worker_id", "lease_token"])
def test_wrong_owner_or_token_cannot_heartbeat(queue_store: PostgresJobQueue, field: str) -> None:
    _enqueue(queue_store)
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None
    altered = replace(claimed, **{field: f"wrong-{field}"})

    with pytest.raises(LeaseLostError):
        queue_store.heartbeat(altered)


@pytest.mark.parametrize("field", ["worker_id", "lease_token"])
def test_wrong_owner_or_token_cannot_fail_active_job(
    queue_store: PostgresJobQueue, field: str
) -> None:
    enqueued = _enqueue(queue_store)
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None
    altered = replace(claimed, **{field: f"wrong-{field}"})

    with pytest.raises(LeaseLostError):
        queue_store.fail(
            altered,
            failure_code="synthetic_failure",
            retryable=True,
        )

    current = queue_store.get(enqueued.job_id)
    assert current.status is JobStatus.LEASED
    assert current.worker_id == claimed.worker_id
    assert current.lease_token == claimed.lease_token


def test_expired_lease_is_reaped_and_claimable_with_a_new_token(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    enqueued = _enqueue(queue_store, max_attempts=3)
    first = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert first is not None
    _expire_lease(migrated_db, enqueued.job_id)

    reaped = queue_store.reap_expired()
    second = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta")

    assert reaped.requeued_job_ids == (enqueued.job_id,)
    assert reaped.dead_lettered_job_ids == ()
    assert second is not None
    assert second.lease_token != first.lease_token
    assert second.attempts == 2


def test_stale_worker_cannot_complete_after_lease_reassignment(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    enqueued = _enqueue(queue_store)
    stale = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-stale")
    assert stale is not None
    _expire_lease(migrated_db, enqueued.job_id)
    queue_store.reap_expired()
    current = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-current")
    assert current is not None

    with pytest.raises(LeaseLostError):
        queue_store.heartbeat(stale)
    assert queue_store.heartbeat(current) > current.lease_expires_at
    with pytest.raises(LeaseLostError):
        queue_store.complete(stale)
    receipt = queue_store.complete(current)
    assert receipt.outcome is CompletionOutcome.COMMITTED


def test_retry_increments_attempts_only_when_reclaimed(queue_store: PostgresJobQueue) -> None:
    enqueued = _enqueue(queue_store, max_attempts=3)
    first = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert first is not None and first.attempts == 1

    outcome = queue_store.fail(
        first,
        failure_code="temporary_failure",
        failure_message="synthetic transient failure",
        retryable=True,
    )
    after_fail = queue_store.get(enqueued.job_id)
    second = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta")

    assert outcome is FailureOutcome.RETRY_SCHEDULED
    assert after_fail.attempts == 1
    assert second is not None and second.attempts == 2


def test_poison_work_dead_letters_at_max_attempts_and_cannot_be_reclaimed(
    queue_store: PostgresJobQueue,
) -> None:
    enqueued = _enqueue(queue_store, max_attempts=2)
    first = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert first is not None
    queue_store.fail(first, failure_code="poison", retryable=True)
    second = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta")
    assert second is not None and second.attempts == 2

    outcome = queue_store.fail(second, failure_code="poison", retryable=True)

    assert outcome is FailureOutcome.DEAD_LETTERED
    assert queue_store.get(enqueued.job_id).status is JobStatus.DEAD_LETTER
    assert queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-gamma") is None


def test_unknown_payload_version_is_rejected_at_enqueue(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    with pytest.raises(UnsupportedPayloadError):
        _enqueue(queue_store, payload_version=999)
    with migrated_db.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM jobs")).scalar_one() == 0


def test_explicit_empty_payload_registry_fails_closed(migrated_db: Engine) -> None:
    closed_store = PostgresJobQueue(migrated_db, supported_payload_versions={})

    with pytest.raises(UnsupportedPayloadError):
        _enqueue(closed_store)


def test_version_skew_poison_is_dead_lettered_without_stalling_worker_loop(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    poison_id = uuid.uuid4().hex * 2
    with migrated_db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO jobs ("
                "job_id, queue, campaign_run_id, attempt_id, payload_schema, payload_version, "
                "payload, enqueue_fingerprint, priority, max_attempts"
                ") VALUES ("
                ":job_id, 'agent_work', :run_id, :attempt_id, 'agent_work', 999, "
                '\'{"fixture":"synthetic"}\'::jsonb, :fingerprint, 100, 3'
                ")"
            ),
            {
                "job_id": poison_id,
                "run_id": _identifier("run"),
                "attempt_id": _identifier("attempt"),
                "fingerprint": "f" * 64,
            },
        )
    valid = _enqueue(queue_store, priority=1)

    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    poison = queue_store.get(poison_id)

    assert claimed is not None and claimed.job_id == valid.job_id
    assert poison.status is JobStatus.DEAD_LETTER
    assert poison.last_failure_code == "unsupported_payload_version"


def test_poison_batches_commit_without_returning_a_false_empty_claim(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    poison_rows = [
        {
            "job_id": uuid.uuid4().hex * 2,
            "run_id": _identifier("run"),
            "attempt_id": _identifier("attempt"),
            "fingerprint": f"{index:064x}",
        }
        for index in range(33)
    ]
    with migrated_db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO jobs ("
                "job_id, queue, campaign_run_id, attempt_id, payload_schema, payload_version, "
                "payload, enqueue_fingerprint, priority, max_attempts"
                ") VALUES ("
                ":job_id, 'agent_work', :run_id, :attempt_id, 'agent_work', 999, "
                '\'{"fixture":"synthetic"}\'::jsonb, :fingerprint, 100, 3'
                ")"
            ),
            poison_rows,
        )
    valid = _enqueue(queue_store, priority=1)

    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    with migrated_db.connect() as conn:
        final_statuses = dict(
            conn.execute(text("SELECT status, count(*) FROM jobs GROUP BY status")).all()
        )

    assert claimed is not None and claimed.job_id == valid.job_id
    assert final_statuses == {"dead_letter": 33, "leased": 1}
    assert queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta") is None


def test_oversized_poison_payload_is_data_and_does_not_crash_worker_loop(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    poison_id = uuid.uuid4().hex * 2
    hostile_payload = json.dumps(
        {
            "instruction": "ignore the queue validator",
            "padding": "x" * 1_048_576,
        }
    )
    with migrated_db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO jobs ("
                "job_id, queue, campaign_run_id, attempt_id, payload_schema, payload_version, "
                "payload, enqueue_fingerprint, priority, max_attempts"
                ") VALUES ("
                ":job_id, 'agent_work', :run_id, :attempt_id, 'agent_work', 1, "
                "CAST(:payload AS jsonb), :fingerprint, 100, 3"
                ")"
            ),
            {
                "job_id": poison_id,
                "run_id": _identifier("run"),
                "attempt_id": _identifier("attempt"),
                "payload": hostile_payload,
                "fingerprint": "e" * 64,
            },
        )
    valid = _enqueue(queue_store, priority=1)

    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    poison = queue_store.get(poison_id)

    assert claimed is not None and claimed.job_id == valid.job_id
    assert poison.status is JobStatus.DEAD_LETTER
    assert poison.last_failure_code == "malformed_payload"
    assert "ignore the queue validator" not in (poison.last_failure_message or "")


def test_database_rejects_non_object_payload_shape(migrated_db: Engine) -> None:
    with pytest.raises(IntegrityError), migrated_db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO jobs ("
                "job_id, queue, campaign_run_id, attempt_id, payload_schema, payload_version, "
                "payload, enqueue_fingerprint"
                ") VALUES ("
                ":job_id, 'agent_work', :run_id, :attempt_id, 'agent_work', 1, "
                "'[\"hostile data\"]'::jsonb, :fingerprint"
                ")"
            ),
            {
                "job_id": uuid.uuid4().hex * 2,
                "run_id": _identifier("run"),
                "attempt_id": _identifier("attempt"),
                "fingerprint": "d" * 64,
            },
        )


def test_concurrent_idempotent_enqueue_creates_one_logical_job(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    campaign_run_id = _identifier("run")
    attempt_id = _identifier("attempt")
    barrier = Barrier(2)

    def enqueue_duplicate(_index: int):
        barrier.wait()
        return _enqueue(
            queue_store,
            campaign_run_id=campaign_run_id,
            attempt_id=attempt_id,
            payload={"fixture": "same-synthetic-payload"},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(pool.map(enqueue_duplicate, (1, 2)))

    assert records[0].job_id == records[1].job_id
    with migrated_db.connect() as conn:
        count = conn.execute(
            text(
                "SELECT count(*) FROM jobs "
                "WHERE queue = 'agent_work' AND campaign_run_id = :run AND attempt_id = :attempt"
            ),
            {"run": campaign_run_id, "attempt": attempt_id},
        ).scalar_one()
    assert count == 1


def test_deduplication_scope_is_queue_campaign_and_attempt(
    queue_store: PostgresJobQueue,
) -> None:
    campaign = _identifier("run")
    attempt = _identifier("attempt")
    agent = _enqueue(queue_store, campaign_run_id=campaign, attempt_id=attempt)
    regression = _enqueue(
        queue_store,
        queue=LogicalQueue.REGRESSION_RUN,
        campaign_run_id=campaign,
        attempt_id=attempt,
    )
    other_campaign = _enqueue(
        queue_store,
        campaign_run_id=_identifier("run"),
        attempt_id=attempt,
    )

    assert len({agent.job_id, regression.job_id, other_campaign.job_id}) == 3


def test_same_dedup_identity_with_different_work_fails_closed(
    queue_store: PostgresJobQueue,
) -> None:
    campaign = _identifier("run")
    attempt = _identifier("attempt")
    original = _enqueue(
        queue_store,
        campaign_run_id=campaign,
        attempt_id=attempt,
        payload={"fixture": "original"},
    )

    with pytest.raises(IdempotencyConflictError):
        _enqueue(
            queue_store,
            campaign_run_id=campaign,
            attempt_id=attempt,
            payload={"fixture": "different"},
        )
    assert queue_store.get(original.job_id).payload == {"fixture": "original"}


def test_completion_is_terminal_and_same_token_repeat_is_idempotent(
    queue_store: PostgresJobQueue,
) -> None:
    enqueued = _enqueue(queue_store)
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None

    first = queue_store.complete(claimed)
    second = queue_store.complete(claimed)

    assert first.outcome is CompletionOutcome.COMMITTED
    assert second.outcome is CompletionOutcome.ALREADY_COMMITTED
    assert first.completed_at == second.completed_at
    record = queue_store.get(enqueued.job_id)
    assert record.status is JobStatus.COMPLETED
    assert record.completed_at == first.completed_at


def test_wrong_token_cannot_complete_active_job(queue_store: PostgresJobQueue) -> None:
    _enqueue(queue_store)
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None

    with pytest.raises(LeaseLostError):
        queue_store.complete(replace(claimed, lease_token="wrong-token"))


def test_reassignment_and_duplicate_delivery_cannot_double_commit(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    enqueued = _enqueue(queue_store)
    first = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert first is not None
    _expire_lease(migrated_db, enqueued.job_id)
    queue_store.reap_expired()
    second = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta")
    assert second is not None

    committed = queue_store.complete(second)
    repeated = queue_store.complete(second)
    with pytest.raises(LeaseLostError):
        queue_store.complete(first)

    row = _job_row(migrated_db, enqueued.job_id)
    assert committed.outcome is CompletionOutcome.COMMITTED
    assert repeated.outcome is CompletionOutcome.ALREADY_COMMITTED
    assert row["status"] == "completed"
    assert row["completed_at"] == committed.completed_at
    assert row["completion_lease_token"] == second.lease_token


def test_cancellation_prevents_scheduled_job_from_being_claimed(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    future = _enqueue(
        queue_store,
        run_after=_db_now(migrated_db) + datetime.timedelta(days=1),
    )

    outcome = queue_store.cancel(future.job_id)

    assert outcome is CancellationOutcome.CANCELLED
    assert queue_store.get(future.job_id).status is JobStatus.CANCELLED
    assert queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha") is None


def test_campaign_cancellation_is_scoped_and_queue_optional(
    queue_store: PostgresJobQueue,
) -> None:
    selected_campaign = _identifier("run")
    other_campaign = _identifier("run")
    selected_agent = _enqueue(queue_store, campaign_run_id=selected_campaign)
    selected_regression = _enqueue(
        queue_store,
        queue=LogicalQueue.REGRESSION_RUN,
        campaign_run_id=selected_campaign,
    )
    unaffected = _enqueue(queue_store, campaign_run_id=other_campaign)

    cancelled = queue_store.cancel_campaign(selected_campaign, queue=LogicalQueue.AGENT_WORK)

    assert cancelled == 1
    assert queue_store.get(selected_agent.job_id).status is JobStatus.CANCELLED
    assert queue_store.get(selected_regression.job_id).status is JobStatus.QUEUED
    assert queue_store.get(unaffected.job_id).status is JobStatus.QUEUED


def test_default_campaign_cancellation_covers_both_queues_only_for_selected_campaign(
    queue_store: PostgresJobQueue,
) -> None:
    selected_campaign = _identifier("run")
    other_campaign = _identifier("run")
    selected_agent = _enqueue(queue_store, campaign_run_id=selected_campaign)
    selected_regression = _enqueue(
        queue_store,
        queue=LogicalQueue.REGRESSION_RUN,
        campaign_run_id=selected_campaign,
    )
    unaffected = _enqueue(queue_store, campaign_run_id=other_campaign)

    cancelled = queue_store.cancel_campaign(selected_campaign)

    assert cancelled == 2
    assert queue_store.get(selected_agent.job_id).status is JobStatus.CANCELLED
    assert queue_store.get(selected_regression.job_id).status is JobStatus.CANCELLED
    assert queue_store.get(unaffected.job_id).status is JobStatus.QUEUED


def test_depth_counts_exact_queue_and_status(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    queued = _enqueue(queue_store)
    _enqueue(queue_store)
    _enqueue(queue_store, queue=LogicalQueue.REGRESSION_RUN)
    leased = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert leased is not None
    completed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-beta")
    assert completed is not None
    queue_store.complete(completed)

    assert queue_store.depth(LogicalQueue.AGENT_WORK, JobStatus.QUEUED) == 0
    assert queue_store.depth(LogicalQueue.AGENT_WORK, JobStatus.LEASED) == 1
    assert queue_store.depth(LogicalQueue.AGENT_WORK, JobStatus.COMPLETED) == 1
    assert queue_store.depth(LogicalQueue.REGRESSION_RUN, JobStatus.QUEUED) == 1
    assert queue_store.get(queued.job_id).status in {JobStatus.LEASED, JobStatus.COMPLETED}
    with migrated_db.connect() as conn:
        direct = conn.execute(
            text("SELECT count(*) FROM jobs WHERE queue = 'agent_work' AND status = 'completed'")
        ).scalar_one()
    assert direct == queue_store.depth(LogicalQueue.AGENT_WORK, JobStatus.COMPLETED)


def test_backpressure_activates_at_greater_than_or_equal_threshold(
    queue_store: PostgresJobQueue,
) -> None:
    _enqueue(queue_store)
    _enqueue(queue_store)
    below = queue_store.backpressure(LogicalQueue.AGENT_WORK, threshold=3)
    _enqueue(queue_store)
    at = queue_store.backpressure(LogicalQueue.AGENT_WORK, threshold=3)
    _enqueue(queue_store)
    above = queue_store.backpressure(LogicalQueue.AGENT_WORK, threshold=3)

    assert (below.depth, below.active) == (2, False)
    assert (at.depth, at.active) == (3, True)
    assert (above.depth, above.active) == (4, True)
    with pytest.raises(ValueError):
        queue_store.backpressure(LogicalQueue.AGENT_WORK, threshold=0)


def test_failure_metadata_is_bounded_and_secret_redacted(
    queue_store: PostgresJobQueue,
) -> None:
    enqueued = _enqueue(queue_store)
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None
    synthetic_token = "sk-" + ("a" * 24)

    queue_store.fail(
        claimed,
        failure_code="synthetic_failure",
        failure_message=(
            f"request failed with {synthetic_token}\n"
            "Traceback (most recent call last): synthetic stack detail"
        ),
        retryable=False,
    )
    record = queue_store.get(enqueued.job_id)

    assert record.last_failure_message is not None
    assert synthetic_token not in record.last_failure_message
    assert "Traceback" not in record.last_failure_message
    assert len(record.last_failure_message) <= 512


def _synthetic_sensitive_diagnostics() -> tuple[str, ...]:
    return (
        "postgresql://" + "synthetic-user:synthetic-pass" + "@localhost/synthetic",
        "Authorization: " + "Basic c3ludGhldGljOnN5bnRoZXRpYw==",
        "Cookie: " + "sessionid=synthetic-session-value",
        "eyJ" + ("a" * 24) + "." + ("b" * 24) + "." + ("c" * 24),
    )


@pytest.mark.parametrize("sensitive_detail", _synthetic_sensitive_diagnostics())
def test_arbitrary_failure_detail_is_never_persisted(
    queue_store: PostgresJobQueue, sensitive_detail: str
) -> None:
    enqueued = _enqueue(queue_store)
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None

    queue_store.fail(
        claimed,
        failure_code="synthetic_failure",
        failure_message=sensitive_detail,
        retryable=False,
    )
    stored = queue_store.get(enqueued.job_id).last_failure_message

    assert stored == "worker-supplied failure detail omitted"
    assert sensitive_detail not in stored


def test_no_job_is_silently_zero_delivered_after_worker_death(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    enqueued = _enqueue(queue_store, max_attempts=3)
    first = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-dead")
    assert first is not None
    _expire_lease(migrated_db, enqueued.job_id)

    reaped = queue_store.reap_expired()
    after_reap = queue_store.get(enqueued.job_id)
    second = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-recovery")

    assert reaped.requeued_job_ids == (enqueued.job_id,)
    assert after_reap.status is JobStatus.QUEUED
    assert second is not None and second.attempts == 2
    assert queue_store.complete(second).outcome is CompletionOutcome.COMMITTED


def test_reaper_dead_letters_expired_job_at_attempt_limit(
    queue_store: PostgresJobQueue, migrated_db: Engine
) -> None:
    enqueued = _enqueue(queue_store, max_attempts=1)
    claimed = queue_store.claim(LogicalQueue.AGENT_WORK, worker_id="worker-alpha")
    assert claimed is not None and claimed.attempts == 1
    _expire_lease(migrated_db, enqueued.job_id)

    result = queue_store.reap_expired()

    assert result.dead_lettered_job_ids == (enqueued.job_id,)
    assert queue_store.get(enqueued.job_id).status is JobStatus.DEAD_LETTER


def test_jobs_schema_has_exact_enums_constraints_and_indexes(migrated_db: Engine) -> None:
    with migrated_db.connect() as conn:
        queues = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT e.enumlabel FROM pg_type t JOIN pg_enum e ON e.enumtypid=t.oid "
                    "WHERE t.typname='job_queue'"
                )
            )
        }
        statuses = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT e.enumlabel FROM pg_type t JOIN pg_enum e ON e.enumtypid=t.oid "
                    "WHERE t.typname='job_status'"
                )
            )
        }
        timestamp_types = {
            row[0]: row[1]
            for row in conn.execute(
                text(
                    "SELECT column_name, data_type FROM information_schema.columns "
                    "WHERE table_name='jobs' AND column_name IN "
                    "('run_after','leased_at','lease_expires_at','created_at','updated_at')"
                )
            )
        }
        index_defs = "\n".join(
            row[0]
            for row in conn.execute(text("SELECT indexdef FROM pg_indexes WHERE tablename='jobs'"))
        )

    assert queues == {"agent_work", "regression_run"}
    assert statuses == {"queued", "leased", "completed", "cancelled", "dead_letter"}
    assert set(timestamp_types.values()) == {"timestamp with time zone"}
    for index_name in (
        "ix_jobs_claim",
        "ix_jobs_reap",
        "ix_jobs_campaign_cancel",
        "ix_jobs_depth",
        "uq_jobs_queue_campaign_attempt",
    ):
        assert index_name in index_defs
    assert "WHERE (status = 'queued'::job_status)" in index_defs
    assert "WHERE (status = 'leased'::job_status)" in index_defs


def test_jobs_schema_is_registered_in_alembic_target_metadata(migrated_db: Engine) -> None:
    with migrated_db.connect() as conn:
        context = MigrationContext.configure(conn)
        differences = compare_metadata(context, Base.metadata)

    jobs_drift = [difference for difference in differences if "jobs" in repr(difference)]
    assert jobs_drift == []


def test_existing_agent_roles_receive_no_jobs_privileges(migrated_db: Engine) -> None:
    roles = ("headshot_redteam", "headshot_recorder", "headshot_judge")
    table_privileges = (
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    )
    sequence_privileges = ("SELECT", "USAGE", "UPDATE")
    with migrated_db.connect() as conn:
        for role in roles:
            for privilege in table_privileges:
                allowed = conn.execute(
                    text("SELECT has_table_privilege(:role, 'jobs', :privilege)"),
                    {"role": role, "privilege": privilege},
                ).scalar_one()
                assert allowed is False, f"{role} unexpectedly gained {privilege} on jobs"
            for privilege in sequence_privileges:
                allowed = conn.execute(
                    text("SELECT has_sequence_privilege(:role, 'jobs_id_seq', :privilege)"),
                    {"role": role, "privilege": privilege},
                ).scalar_one()
                assert allowed is False, f"{role} unexpectedly gained {privilege} on jobs_id_seq"


def test_public_receives_no_jobs_or_sequence_privileges(migrated_db: Engine) -> None:
    with migrated_db.connect() as conn:
        public_table_acl = conn.execute(
            text(
                "SELECT count(*) FROM pg_class c "
                "CROSS JOIN LATERAL aclexplode("
                "COALESCE(c.relacl, acldefault('r', c.relowner))) acl "
                "WHERE c.relname = 'jobs' AND acl.grantee = 0"
            )
        ).scalar_one()
        public_sequence_acl = conn.execute(
            text(
                "SELECT count(*) FROM pg_class c "
                "CROSS JOIN LATERAL aclexplode("
                "COALESCE(c.relacl, acldefault('S', c.relowner))) acl "
                "WHERE c.relname = 'jobs_id_seq' AND acl.grantee = 0"
            )
        ).scalar_one()

    assert public_table_acl == 0
    assert public_sequence_acl == 0


def test_attempt_result_unique_constraint_remains_independent(
    migrated_db: Engine,
) -> None:
    campaign = _identifier("run")
    attempt = _identifier("attempt")
    with migrated_db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO attempt_result (campaign_run_id, attempt_id, content_hash) "
                "VALUES (:run, :attempt, :hash)"
            ),
            {"run": campaign, "attempt": attempt, "hash": "a" * 64},
        )
    with pytest.raises(IntegrityError), migrated_db.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO attempt_result (campaign_run_id, attempt_id, content_hash) "
                "VALUES (:run, :attempt, :hash)"
            ),
            {"run": campaign, "attempt": attempt, "hash": "b" * 64},
        )


def test_migration_upgrade_downgrade_upgrade_owns_only_m3_objects(admin_url: str) -> None:
    dbname = f"agentforge_queue_migration_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    url = f"{base}/{dbname}"
    _db.create_fresh_database(admin_url, dbname)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(url, REV_PRE_QUEUE)
        engine = _db.build_engine(url)
        finding_id = _identifier("finding")
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO finding (finding_id, severity, category) "
                    "VALUES (:finding_id, 'high', 'synthetic-category')"
                ),
                {"finding_id": finding_id},
            )
            # Simulate dangerous owner default-ACL drift. Migration 0004 must explicitly
            # revoke these grants when it creates its own table and sequence.
            conn.execute(
                text(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                    "GRANT SELECT ON TABLES TO PUBLIC, headshot_redteam"
                )
            )
            conn.execute(
                text(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                    "GRANT USAGE ON SEQUENCES TO PUBLIC, headshot_redteam"
                )
            )
        _db.alembic_upgrade(url, REV_QUEUE)
        with engine.connect() as conn:
            assert conn.execute(text("SELECT to_regclass('public.jobs')")).scalar_one() == "jobs"
            assert (
                conn.execute(
                    text("SELECT has_table_privilege('headshot_redteam', 'jobs', 'SELECT')")
                ).scalar_one()
                is False
            )
            assert (
                conn.execute(
                    text(
                        "SELECT has_sequence_privilege('headshot_redteam', 'jobs_id_seq', 'USAGE')"
                    )
                ).scalar_one()
                is False
            )
            public_acl_count = conn.execute(
                text(
                    "SELECT count(*) FROM pg_class c "
                    "CROSS JOIN LATERAL aclexplode("
                    "COALESCE(c.relacl, acldefault(CAST("
                    "CASE WHEN c.relkind = 'S' THEN 'S' ELSE 'r' END AS \"char\"), "
                    "c.relowner))) acl "
                    "WHERE c.relname IN ('jobs', 'jobs_id_seq') AND acl.grantee = 0"
                )
            ).scalar_one()
            assert public_acl_count == 0

        _db.alembic_downgrade(url, REV_PRE_QUEUE)
        with engine.connect() as conn:
            assert conn.execute(text("SELECT to_regclass('public.jobs')")).scalar_one() is None
            finding_relation = conn.execute(
                text("SELECT to_regclass('public.finding')")
            ).scalar_one()
            assert finding_relation == "finding"
            assert (
                conn.execute(text("SELECT to_regclass('public.coverage_metric')")).scalar_one()
                == "coverage_metric"
            )
            assert (
                conn.execute(
                    text("SELECT count(*) FROM finding WHERE finding_id=:finding_id"),
                    {"finding_id": finding_id},
                ).scalar_one()
                == 1
            )
            queue_type = conn.execute(
                text("SELECT count(*) FROM pg_type WHERE typname IN ('job_queue','job_status')")
            ).scalar_one()
            assert queue_type == 0

        _db.alembic_upgrade(url, REV_QUEUE)
        with engine.connect() as conn:
            assert conn.execute(text("SELECT to_regclass('public.jobs')")).scalar_one() == "jobs"
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, dbname)
