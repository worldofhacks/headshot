"""Persist agent delivery state and allow a campaign trace to contain many observations.

Revision ID: 0016
Revises: 0015
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(
        op.f("uq_outbound_http_requests_trace_id"),
        "outbound_http_requests",
        type_="unique",
    )
    op.create_index(
        "ix_outbound_requests_trace_id",
        "outbound_http_requests",
        ["trace_id"],
    )
    op.add_column(
        "outbound_http_requests",
        sa.Column("langfuse_verified_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    # Earlier runtimes treated a non-raising SDK flush as remote delivery. That signal is not
    # authoritative, so require an exact Langfuse query-back before retaining "exported".
    op.execute(
        "UPDATE outbound_http_requests SET langfuse_status = 'queued' "
        "WHERE langfuse_status = 'exported'"
    )
    op.create_check_constraint(
        "outbound_request_langfuse_verification",
        "outbound_http_requests",
        "(langfuse_status = 'exported' AND langfuse_verified_at IS NOT NULL) OR "
        "(langfuse_status <> 'exported' AND langfuse_verified_at IS NULL)",
    )
    op.add_column(
        "agent_executions",
        sa.Column(
            "langfuse_status",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'not_attempted'"),
        ),
    )
    op.create_check_constraint(
        "agent_execution_langfuse_status",
        "agent_executions",
        "langfuse_status IN ('not_attempted','disabled','queued','exported','error')",
    )
    op.create_index(
        "ix_agent_execution_langfuse_delivery",
        "agent_executions",
        ["organization_id", "langfuse_status", "started_at"],
    )
    op.add_column(
        "agent_executions",
        sa.Column("langfuse_verified_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "agent_execution_langfuse_verification",
        "agent_executions",
        "(langfuse_status = 'exported' AND langfuse_verified_at IS NOT NULL) OR "
        "(langfuse_status <> 'exported' AND langfuse_verified_at IS NULL)",
    )


def downgrade() -> None:
    op.drop_constraint(
        "agent_execution_langfuse_verification",
        "agent_executions",
        type_="check",
    )
    op.drop_column("agent_executions", "langfuse_verified_at")
    op.drop_index(
        "ix_agent_execution_langfuse_delivery",
        table_name="agent_executions",
    )
    op.drop_constraint(
        "agent_execution_langfuse_status",
        "agent_executions",
        type_="check",
    )
    op.drop_column("agent_executions", "langfuse_status")
    op.drop_constraint(
        "outbound_request_langfuse_verification",
        "outbound_http_requests",
        type_="check",
    )
    op.drop_column("outbound_http_requests", "langfuse_verified_at")
    op.drop_index(
        "ix_outbound_requests_trace_id",
        table_name="outbound_http_requests",
    )
    # Revision 0015 required request-unique trace IDs. Re-key every request, rather than only
    # duplicate groups, so a derived ID cannot collide with an untouched campaign trace.
    op.execute("UPDATE outbound_http_requests SET trace_id = md5(request_id)")
    op.create_unique_constraint(
        op.f("uq_outbound_http_requests_trace_id"),
        "outbound_http_requests",
        ["trace_id"],
    )
