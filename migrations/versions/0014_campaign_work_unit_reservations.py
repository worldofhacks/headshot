"""Add durable campaign physical-work-unit reservations.

Revision ID: 0014
Revises: 0013
Create Date: 2026-07-24

This is an expand-only schema change.  A Runner must reserve one immutable coordinate before
each physical target send.  The nullable observation fields are the sole permitted mutation:
they move once from NULL to a terminal ``returned``/``raised`` marker after adapter control
returns.  A reservation left unobserved after a crash is intentionally ambiguous and cannot be
replayed or reconciled as completed work.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "campaign_work_unit_reservations",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("turn_index", sa.Integer(), nullable=False),
        sa.Column("retry_index", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("job_attempt", sa.Integer(), nullable=False),
        sa.Column("worker_id", sa.String(length=128), nullable=False),
        sa.Column("lease_token_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "reserved_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column("observed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("observation_outcome", sa.String(length=16), nullable=True),
        sa.PrimaryKeyConstraint(
            "run_id",
            "attempt_id",
            "turn_index",
            "retry_index",
            name="pk_campaign_work_unit_reservations",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "run_id", "attempt_id"],
            [
                "campaign_attempts.organization_id",
                "campaign_attempts.run_id",
                "campaign_attempts.attempt_id",
            ],
            name="fk_campaign_work_unit_reservation_attempt",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["jobs.job_id"],
            name="fk_campaign_work_unit_reservation_job",
        ),
        sa.CheckConstraint(
            "turn_index >= 0 AND retry_index >= 0",
            name="campaign_work_unit_coordinate_nonnegative",
        ),
        sa.CheckConstraint(
            "job_attempt > 0",
            name="campaign_work_unit_job_attempt_positive",
        ),
        sa.CheckConstraint(
            "lease_token_sha256 ~ '^[0-9a-f]{64}$'",
            name="campaign_work_unit_lease_hash",
        ),
        sa.CheckConstraint(
            "(observed_at IS NULL AND observation_outcome IS NULL) OR "
            "(observed_at IS NOT NULL AND observation_outcome IN ('returned','raised'))",
            name="campaign_work_unit_observation_shape",
        ),
    )
    op.create_index(
        "ix_campaign_work_unit_reservations_org_run",
        "campaign_work_unit_reservations",
        ["organization_id", "run_id"],
    )
    op.create_index(
        "ix_campaign_work_unit_reservations_unobserved",
        "campaign_work_unit_reservations",
        ["run_id", "reserved_at"],
        postgresql_where=sa.text("observed_at IS NULL"),
    )

    op.execute(
        """
        CREATE FUNCTION m1d_guard_work_unit_reservation_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'campaign work-unit reservations are durable';
          END IF;
          IF OLD.organization_id IS DISTINCT FROM NEW.organization_id
             OR OLD.run_id IS DISTINCT FROM NEW.run_id
             OR OLD.attempt_id IS DISTINCT FROM NEW.attempt_id
             OR OLD.turn_index IS DISTINCT FROM NEW.turn_index
             OR OLD.retry_index IS DISTINCT FROM NEW.retry_index
             OR OLD.job_id IS DISTINCT FROM NEW.job_id
             OR OLD.job_attempt IS DISTINCT FROM NEW.job_attempt
             OR OLD.worker_id IS DISTINCT FROM NEW.worker_id
             OR OLD.lease_token_sha256 IS DISTINCT FROM NEW.lease_token_sha256
             OR OLD.reserved_at IS DISTINCT FROM NEW.reserved_at
             OR OLD.observed_at IS NOT NULL
             OR NEW.observed_at IS NULL
             OR OLD.observation_outcome IS NOT NULL
             OR NEW.observation_outcome IS NULL THEN
            RAISE EXCEPTION 'campaign work-unit reservations permit one observation only';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        "CREATE TRIGGER trg_campaign_work_unit_reservations_guard "
        "BEFORE UPDATE OR DELETE ON campaign_work_unit_reservations "
        "FOR EACH ROW EXECUTE FUNCTION m1d_guard_work_unit_reservation_mutation()"
    )
    op.execute("GRANT SELECT, INSERT ON TABLE campaign_work_unit_reservations TO headshot_runner")
    op.execute(
        "GRANT UPDATE (observed_at, observation_outcome) "
        "ON TABLE campaign_work_unit_reservations TO headshot_runner"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_campaign_work_unit_reservations_guard ON campaign_work_unit_reservations"
    )
    op.execute("DROP FUNCTION m1d_guard_work_unit_reservation_mutation()")
    op.drop_index(
        "ix_campaign_work_unit_reservations_unobserved",
        table_name="campaign_work_unit_reservations",
    )
    op.drop_index(
        "ix_campaign_work_unit_reservations_org_run",
        table_name="campaign_work_unit_reservations",
    )
    op.drop_table("campaign_work_unit_reservations")
