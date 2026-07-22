"""Durable outbound-request telemetry and runtime component status.

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-21

The request ledger is written before a physical target dispatch and completed after the
response/error is observed.  It is deliberately separate from append-only evidence: telemetry
may move from ``in_flight`` to a terminal transport/export state, while evidence remains immutable.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "outbound_http_requests",
        sa.Column("request_id", sa.String(length=64), primary_key=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("trace_id", sa.String(length=32), nullable=False, unique=True),
        sa.Column("operation", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("destination_host", sa.String(length=255), nullable=False),
        sa.Column("relative_path", sa.String(length=1024), nullable=False),
        sa.Column(
            "request_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("response_payload", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="in_flight"),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("request_bytes", sa.Integer(), nullable=False),
        sa.Column("response_bytes", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Numeric(14, 3), nullable=True),
        sa.Column("measured_cost", sa.Numeric(14, 6), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default="USD"),
        sa.Column(
            "langfuse_status",
            sa.String(length=16),
            nullable=False,
            server_default="disabled",
        ),
        sa.Column(
            "started_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "campaign_run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_outbound_request_campaign",
        ),
        sa.CheckConstraint("trace_id ~ '^[0-9a-f]{32}$'", name="outbound_request_trace_id"),
        sa.CheckConstraint(
            "status IN ('in_flight','succeeded','failed')",
            name="outbound_request_status",
        ),
        sa.CheckConstraint(
            "langfuse_status IN ('disabled','queued','exported','error')",
            name="outbound_request_langfuse_status",
        ),
        sa.CheckConstraint(
            "request_bytes >= 0 AND (response_bytes IS NULL OR response_bytes >= 0)",
            name="outbound_request_bytes",
        ),
        sa.CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0",
            name="outbound_request_duration",
        ),
        sa.CheckConstraint("measured_cost >= 0", name="outbound_request_cost"),
    )
    op.create_index(
        "ix_outbound_requests_org_started",
        "outbound_http_requests",
        ["organization_id", "started_at"],
    )
    op.create_index(
        "ix_outbound_requests_run_attempt",
        "outbound_http_requests",
        ["organization_id", "campaign_run_id", "attempt_id"],
    )

    op.create_table(
        "runtime_component_status",
        sa.Column("environment", sa.String(length=16), nullable=False),
        sa.Column("component_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("availability", sa.String(length=48), nullable=False),
        sa.Column("detail", sa.String(length=128), nullable=False),
        sa.Column(
            "heartbeat_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.PrimaryKeyConstraint("environment", "component_id", name="pk_runtime_component_status"),
        sa.CheckConstraint(
            "availability IN ('operational and evidenced',"
            "'adapter integrated, execution deferred','evaluated and rejected',"
            "'blocked pending authorization')",
            name="runtime_component_availability",
        ),
    )

    op.execute(
        "GRANT SELECT ON TABLE outbound_http_requests, runtime_component_status "
        "TO headshot_web, headshot_runner"
    )
    op.execute(
        "GRANT INSERT, UPDATE ON TABLE outbound_http_requests, runtime_component_status "
        "TO headshot_runner"
    )


def downgrade() -> None:
    op.drop_table("runtime_component_status")
    op.drop_index("ix_outbound_requests_run_attempt", table_name="outbound_http_requests")
    op.drop_index("ix_outbound_requests_org_started", table_name="outbound_http_requests")
    op.drop_table("outbound_http_requests")
