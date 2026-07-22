"""0004 jobs queue — durable Postgres SKIP LOCKED work delivery.

Adds the M3-owned ``jobs`` table and its two native enums. The table implements the
at-least-once delivery state machine for exactly two logical queues, bounded leases,
deterministic retry/reaping, dead-letter containment, queue-scoped idempotency, and
terminal completion credentials. Processing happens outside the short claim transaction.

No existing evidence table, role, grant, or migration is changed. In particular, the
append-only ``attempt_result`` permissions and UNIQUE constraint remain independent.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-21

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_JOB_QUEUE = postgresql.ENUM("agent_work", "regression_run", name="job_queue")
_JOB_STATUS = postgresql.ENUM(
    "queued",
    "leased",
    "completed",
    "cancelled",
    "dead_letter",
    name="job_status",
)


def _enum_ref(enum: postgresql.ENUM) -> postgresql.ENUM:
    """Reference an enum that this migration has already created."""
    return postgresql.ENUM(name=enum.name, create_type=False)


def upgrade() -> None:
    bind = op.get_bind()
    _JOB_QUEUE.create(bind, checkfirst=True)
    _JOB_STATUS.create(bind, checkfirst=True)

    op.create_table(
        "jobs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("queue", _enum_ref(_JOB_QUEUE), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("payload_schema", sa.String(length=64), nullable=False),
        sa.Column("payload_version", sa.Integer(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("enqueue_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "run_after",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("status", _enum_ref(_JOB_STATUS), nullable=False, server_default="queued"),
        sa.Column("worker_id", sa.String(length=128), nullable=True),
        sa.Column("lease_token", sa.String(length=128), nullable=True),
        sa.Column("leased_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_failure_code", sa.String(length=64), nullable=True),
        sa.Column("last_failure_message", sa.String(length=512), nullable=True),
        sa.Column("last_failure_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_failure_worker_id", sa.String(length=128), nullable=True),
        sa.Column("completion_worker_id", sa.String(length=128), nullable=True),
        sa.Column("completion_lease_token", sa.String(length=128), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("dead_lettered_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("job_id", name="uq_jobs_job_id"),
        sa.UniqueConstraint(
            "queue",
            "campaign_run_id",
            "attempt_id",
            name="uq_jobs_queue_campaign_attempt",
        ),
        sa.CheckConstraint(
            "payload_version > 0",
            name="ck_jobs_job_payload_version_positive",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'",
            name="ck_jobs_job_payload_object",
        ),
        sa.CheckConstraint(
            "char_length(enqueue_fingerprint) = 64",
            name="ck_jobs_job_fingerprint_length",
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND max_attempts > 0 AND attempts <= max_attempts",
            name="ck_jobs_job_attempt_bounds",
        ),
        sa.CheckConstraint(
            "status <> 'queued'::job_status OR attempts < max_attempts",
            name="ck_jobs_job_queued_attempt_budget",
        ),
        sa.CheckConstraint(
            "(status = 'leased'::job_status AND worker_id IS NOT NULL "
            "AND lease_token IS NOT NULL AND leased_at IS NOT NULL "
            "AND lease_expires_at IS NOT NULL AND last_heartbeat_at IS NOT NULL "
            "AND lease_expires_at > leased_at) OR "
            "(status <> 'leased'::job_status AND worker_id IS NULL "
            "AND lease_token IS NULL AND leased_at IS NULL "
            "AND lease_expires_at IS NULL AND last_heartbeat_at IS NULL)",
            name="ck_jobs_job_active_lease_shape",
        ),
        sa.CheckConstraint(
            "(status = 'completed'::job_status AND completed_at IS NOT NULL "
            "AND completion_worker_id IS NOT NULL AND completion_lease_token IS NOT NULL) OR "
            "(status <> 'completed'::job_status AND completed_at IS NULL "
            "AND completion_worker_id IS NULL AND completion_lease_token IS NULL)",
            name="ck_jobs_job_completion_shape",
        ),
        sa.CheckConstraint(
            "(status = 'cancelled'::job_status) = (cancelled_at IS NOT NULL)",
            name="ck_jobs_job_cancellation_shape",
        ),
        sa.CheckConstraint(
            "(status = 'dead_letter'::job_status) = (dead_lettered_at IS NOT NULL)",
            name="ck_jobs_job_dead_letter_shape",
        ),
        sa.CheckConstraint(
            "last_failure_message IS NULL OR char_length(last_failure_message) <= 512",
            name="ck_jobs_job_failure_message_length",
        ),
    )

    # Converge to fail-closed ACLs even if the database owner has drifted ALTER DEFAULT
    # PRIVILEGES. Queue mutation is not granted to any M2 agent role in this storage-only
    # slice; a future consumer must add a dedicated least-privilege role in a new migration.
    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE jobs FROM "
        "PUBLIC, headshot_redteam, headshot_recorder, headshot_judge"
    )
    op.execute(
        "REVOKE ALL PRIVILEGES ON SEQUENCE jobs_id_seq FROM "
        "PUBLIC, headshot_redteam, headshot_recorder, headshot_judge"
    )

    # Partial predicates contain only immutable enum comparisons. Eligibility time remains
    # in the scan condition because PostgreSQL does not allow ``now()`` in an index predicate.
    op.execute(
        "CREATE INDEX ix_jobs_claim "
        "ON jobs (queue, priority DESC, run_after, id) "
        "WHERE status = 'queued'::job_status"
    )
    op.execute(
        "CREATE INDEX ix_jobs_reap "
        "ON jobs (lease_expires_at, id) "
        "WHERE status = 'leased'::job_status"
    )
    op.execute(
        "CREATE INDEX ix_jobs_campaign_cancel "
        "ON jobs (campaign_run_id, queue, id) "
        "WHERE status = 'queued'::job_status"
    )
    op.create_index("ix_jobs_depth", "jobs", ["queue", "status"], unique=False)


def downgrade() -> None:
    # Indexes and the owned BIGSERIAL sequence drop with the M3 table. Existing objects remain.
    op.drop_table("jobs")
    bind = op.get_bind()
    _JOB_STATUS.drop(bind, checkfirst=True)
    _JOB_QUEUE.drop(bind, checkfirst=True)
