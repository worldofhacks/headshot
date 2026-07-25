"""Permit failed logical rows to project a recorded provider model substitution.

Revision ID: 0019
Revises: 0018
Create Date: 2026-07-24

Physical provider events remain authoritative. This revision only lets a failed logical
``agent_executions`` projection preserve the differing model observed by that event chain.
Successful logical rows must still match the authorized requested model exactly.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OBSERVATION_TUPLE = (
    "((returned_model IS NULL AND upstream_provider IS NULL "
    "AND provider_request_id IS NULL) OR "
    "(returned_model IS NOT NULL AND upstream_provider IS NOT NULL "
    "AND provider_request_id IS NOT NULL))"
)


def upgrade() -> None:
    op.execute("LOCK TABLE agent_executions IN ACCESS EXCLUSIVE MODE")
    op.drop_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        type_="check",
    )
    op.create_check_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        _OBSERVATION_TUPLE
        + " AND (returned_model IS NULL OR status <> 'succeeded' OR returned_model = model)",
    )


def downgrade() -> None:
    op.execute("LOCK TABLE agent_executions IN ACCESS EXCLUSIVE MODE")
    # Revision 0018 cannot project a differing logical returned_model. Clear only the obsolete
    # logical observation tuple. Physical attempts, event IDs, measured cost, and measurement
    # state remain intact so the append-only provider ledger still proves what happened.
    op.execute(
        "UPDATE agent_executions SET "
        "returned_model = NULL, upstream_provider = NULL, provider_request_id = NULL, "
        "input_tokens = NULL, output_tokens = NULL, reasoning_tokens = NULL "
        "WHERE returned_model IS NOT NULL AND returned_model <> model"
    )
    op.drop_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        type_="check",
    )
    op.create_check_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        _OBSERVATION_TUPLE + " AND (returned_model IS NULL OR returned_model = model)",
    )
