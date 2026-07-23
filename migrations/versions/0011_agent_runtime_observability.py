"""Persist agent assignments, executions, and security-tool case lineage.

Revision ID: 0011
Revises: 0010
Create Date: 2026-07-23

Agent configurations are append-only. Agent executions intentionally transition from running to
one terminal state so the console can show live work without inventing optimistic state.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "campaign_attempts",
        sa.Column("source_tool", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "campaign_attempts",
        sa.Column("source_technique", sa.String(length=200), nullable=True),
    )
    op.create_index(
        "ix_campaign_attempts_source_tool",
        "campaign_attempts",
        ["organization_id", "source_tool", "created_at"],
    )

    op.create_table(
        "agent_configuration_versions",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("agent_role", sa.String(length=32), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=160), nullable=False),
        sa.Column("execution_mode", sa.String(length=32), nullable=False),
        sa.Column("activation_state", sa.String(length=48), nullable=False),
        sa.Column("configuration_sha256", sa.String(length=64), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("actor_user_id", sa.String(length=128), nullable=False),
        sa.Column("actor_session_id", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint(
            "organization_id",
            "agent_role",
            "version",
            name="pk_agent_configuration_versions",
        ),
        sa.CheckConstraint(
            "agent_role IN ('orchestrator','red_team','judge','documentation')",
            name="agent_configuration_role",
        ),
        sa.CheckConstraint("version > 0", name="agent_configuration_version_positive"),
        sa.CheckConstraint(
            "execution_mode IN ('deterministic','hosted_advisory')",
            name="agent_configuration_execution_mode",
        ),
        sa.CheckConstraint(
            "activation_state IN ('active','staged_pending_authorization')",
            name="agent_configuration_activation_state",
        ),
        sa.CheckConstraint(
            "configuration_sha256 ~ '^[0-9a-f]{64}$'",
            name="agent_configuration_hash",
        ),
    )
    op.create_index(
        "ix_agent_configuration_latest",
        "agent_configuration_versions",
        ["organization_id", "agent_role", "version"],
    )

    op.create_table(
        "agent_executions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("execution_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=True),
        sa.Column("parent_execution_id", sa.String(length=64), nullable=True),
        sa.Column("agent_role", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'running'"),
        ),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=160), nullable=False),
        sa.Column("execution_mode", sa.String(length=32), nullable=False),
        sa.Column("configuration_version", sa.Integer(), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=False),
        sa.Column("output_sha256", sa.String(length=64), nullable=True),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column(
            "measured_cost",
            sa.Numeric(14, 6),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "currency",
            sa.String(length=3),
            nullable=False,
            server_default=sa.text("'USD'"),
        ),
        sa.Column("trace_id", sa.String(length=32), nullable=False),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column(
            "started_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Numeric(14, 3), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_agent_executions"),
        sa.UniqueConstraint("execution_id", name="uq_agent_executions_execution_id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "campaign_run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_agent_execution_campaign",
        ),
        sa.CheckConstraint(
            "agent_role IN ('orchestrator','red_team','judge','documentation')",
            name="agent_execution_role",
        ),
        sa.CheckConstraint(
            "status IN ('running','succeeded','failed','skipped')",
            name="agent_execution_status",
        ),
        sa.CheckConstraint(
            "execution_mode IN ('deterministic','hosted_advisory')",
            name="agent_execution_mode",
        ),
        sa.CheckConstraint(
            "input_sha256 ~ '^[0-9a-f]{64}$' AND "
            "(output_sha256 IS NULL OR output_sha256 ~ '^[0-9a-f]{64}$')",
            name="agent_execution_hashes",
        ),
        sa.CheckConstraint(
            "input_tokens IS NULL OR input_tokens >= 0",
            name="agent_execution_input_tokens",
        ),
        sa.CheckConstraint(
            "output_tokens IS NULL OR output_tokens >= 0",
            name="agent_execution_output_tokens",
        ),
        sa.CheckConstraint("measured_cost >= 0", name="agent_execution_cost"),
        sa.CheckConstraint(
            "jsonb_typeof(detail) = 'object'",
            name="agent_execution_detail_object",
        ),
        sa.CheckConstraint(
            "(status = 'running' AND finished_at IS NULL AND duration_ms IS NULL "
            "AND output_sha256 IS NULL AND error_code IS NULL) OR "
            "(status <> 'running' AND finished_at IS NOT NULL AND duration_ms IS NOT NULL "
            "AND output_sha256 IS NOT NULL)",
            name="agent_execution_terminal_shape",
        ),
    )
    op.create_index(
        "ix_agent_execution_campaign_order",
        "agent_executions",
        ["organization_id", "campaign_run_id", "id"],
    )
    op.create_index(
        "ix_agent_execution_role_started",
        "agent_executions",
        ["organization_id", "agent_role", "started_at"],
    )

    op.execute(
        "CREATE TRIGGER trg_agent_configuration_versions_append_only "
        "BEFORE UPDATE OR DELETE ON agent_configuration_versions FOR EACH ROW "
        "EXECUTE FUNCTION m1d_reject_append_only_mutation()"
    )
    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE agent_configuration_versions, agent_executions "
        "FROM PUBLIC, headshot_redteam, headshot_recorder, headshot_judge"
    )
    op.execute(
        "GRANT SELECT ON TABLE agent_configuration_versions, agent_executions "
        "TO headshot_web, headshot_runner"
    )
    op.execute("GRANT INSERT ON TABLE agent_configuration_versions TO headshot_web")
    op.execute("GRANT INSERT, UPDATE ON TABLE agent_executions TO headshot_runner")
    op.execute("GRANT USAGE, SELECT ON SEQUENCE agent_executions_id_seq TO headshot_runner")


def downgrade() -> None:
    op.drop_index("ix_agent_execution_role_started", table_name="agent_executions")
    op.drop_index("ix_agent_execution_campaign_order", table_name="agent_executions")
    op.drop_table("agent_executions")
    op.drop_index(
        "ix_agent_configuration_latest",
        table_name="agent_configuration_versions",
    )
    op.drop_table("agent_configuration_versions")
    op.drop_index("ix_campaign_attempts_source_tool", table_name="campaign_attempts")
    op.drop_column("campaign_attempts", "source_technique")
    op.drop_column("campaign_attempts", "source_tool")
