"""Persist immutable, protected prompt evidence for hosted agent executions.

Revision ID: 0027
Revises: 0026
Create Date: 2026-07-26

The platform previously retained only an input digest on ``agent_executions``.  That proves
identity but cannot show an operator the exact package-owned system prompt and ordered provider
messages that produced a hosted execution.  This expand-only revision adds one snapshot per
hosted logical execution.  The row is inserted in the same transaction as the execution and is
immutable thereafter; it is never an outbound telemetry source.

Only the Runner may append snapshots.  The authenticated Web service may read them, but API
authorization still has to enforce the organization and ``org:evidence:read`` boundary.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

def upgrade() -> None:
    op.create_table(
        "agent_prompt_snapshots",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("execution_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=True),
        sa.Column("agent_role", sa.String(length=32), nullable=False),
        sa.Column("system_prompt_version", sa.String(length=64), nullable=False),
        sa.Column("system_prompt_sha256", sa.String(length=64), nullable=False),
        sa.Column("system_prompt_content", sa.Text(), nullable=False),
        sa.Column("provider_messages", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("transcript_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "redactions",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.PrimaryKeyConstraint(
            "organization_id",
            "execution_id",
            name="pk_agent_prompt_snapshots",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "execution_id"],
            ["agent_executions.organization_id", "agent_executions.execution_id"],
            name="fk_agent_prompt_snapshot_execution",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "campaign_run_id", "attempt_id"],
            [
                "campaign_attempts.organization_id",
                "campaign_attempts.run_id",
                "campaign_attempts.attempt_id",
            ],
            name="fk_agent_prompt_snapshot_attempt",
        ),
        sa.CheckConstraint(
            "agent_role IN ('orchestrator','red_team','judge','documentation')",
            name="agent_prompt_snapshot_role",
        ),
        sa.CheckConstraint(
            "system_prompt_sha256 ~ '^[0-9a-f]{64}$' AND transcript_sha256 ~ '^[0-9a-f]{64}$'",
            name="agent_prompt_snapshot_hashes",
        ),
        sa.CheckConstraint(
            "octet_length(system_prompt_content) BETWEEN 1 AND 1048576",
            name="agent_prompt_snapshot_system_prompt_bound",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(provider_messages) = 'array' "
            "AND jsonb_array_length(provider_messages) BETWEEN 1 AND 64 "
            "AND octet_length(provider_messages::text) <= 1572864",
            name="agent_prompt_snapshot_messages_bound",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(redactions) = 'array' "
            "AND jsonb_array_length(redactions) <= 64 "
            "AND octet_length(redactions::text) <= 16384",
            name="agent_prompt_snapshot_redactions_bound",
        ),
    )
    op.create_index(
        "ix_agent_prompt_snapshots_campaign_attempt",
        "agent_prompt_snapshots",
        ["organization_id", "campaign_run_id", "attempt_id", "agent_role", "created_at"],
    )

    # Denormalized scope is deliberate for organization/campaign/attempt queryability.  Prove it
    # against the execution at birth so a compromised caller cannot mislabel prompt evidence.
    op.execute(
        """
        CREATE FUNCTION m1d_validate_agent_prompt_snapshot()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
          execution_record record;
        BEGIN
          SELECT organization_id, campaign_run_id, attempt_id, agent_role, execution_mode
          INTO execution_record
          FROM agent_executions
          WHERE organization_id = NEW.organization_id
            AND execution_id = NEW.execution_id
          FOR KEY SHARE;

          IF NOT FOUND
             OR execution_record.execution_mode <> 'hosted_advisory'
             OR execution_record.campaign_run_id IS DISTINCT FROM NEW.campaign_run_id
             OR execution_record.attempt_id IS DISTINCT FROM NEW.attempt_id
             OR execution_record.agent_role IS DISTINCT FROM NEW.agent_role THEN
            RAISE EXCEPTION 'agent prompt snapshot scope differs from hosted execution'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        "CREATE TRIGGER trg_agent_prompt_snapshot_scope "
        "BEFORE INSERT ON agent_prompt_snapshots FOR EACH ROW "
        "EXECUTE FUNCTION m1d_validate_agent_prompt_snapshot()"
    )
    op.execute(
        "CREATE TRIGGER trg_agent_prompt_snapshots_append_only "
        "BEFORE UPDATE OR DELETE ON agent_prompt_snapshots FOR EACH ROW "
        "EXECUTE FUNCTION m1d_reject_append_only_mutation()"
    )

    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE agent_prompt_snapshots "
        "FROM PUBLIC, headshot_web, headshot_runner, headshot_redteam, "
        "headshot_recorder, headshot_judge, headshot_scheduler"
    )
    op.execute("GRANT SELECT ON TABLE agent_prompt_snapshots TO headshot_web, headshot_runner")
    op.execute("GRANT INSERT ON TABLE agent_prompt_snapshots TO headshot_runner")


def downgrade() -> None:
    op.execute("DROP TRIGGER trg_agent_prompt_snapshots_append_only ON agent_prompt_snapshots")
    op.execute("DROP TRIGGER trg_agent_prompt_snapshot_scope ON agent_prompt_snapshots")
    op.execute("DROP FUNCTION m1d_validate_agent_prompt_snapshot()")
    op.drop_index(
        "ix_agent_prompt_snapshots_campaign_attempt",
        table_name="agent_prompt_snapshots",
    )
    op.drop_table("agent_prompt_snapshots")
