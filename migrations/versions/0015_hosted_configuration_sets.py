"""Persist atomic append-only four-role hosted configuration sets.

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hosted_configuration_sets",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("configuration_sha256", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("release_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("actor_user_id", sa.String(length=128), nullable=False),
        sa.Column("actor_session_id", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.PrimaryKeyConstraint(
            "organization_id",
            "configuration_sha256",
            name="pk_hosted_configuration_sets",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "release_sha256",
            name="uq_hosted_configuration_release",
        ),
        sa.CheckConstraint(
            "configuration_sha256 ~ '^[0-9a-f]{64}$'",
            name="hosted_configuration_set_hash",
        ),
        sa.CheckConstraint(
            "release_sha256 ~ '^[0-9a-f]{64}$'",
            name="hosted_configuration_release_hash",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'",
            name="hosted_configuration_payload_object",
        ),
    )
    op.create_index(
        "ix_hosted_configuration_sets_created",
        "hosted_configuration_sets",
        ["organization_id", "created_at"],
    )
    op.execute(
        "CREATE TRIGGER trg_hosted_configuration_sets_append_only "
        "BEFORE UPDATE OR DELETE ON hosted_configuration_sets FOR EACH ROW "
        "EXECUTE FUNCTION m1d_reject_append_only_mutation()"
    )
    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE hosted_configuration_sets "
        "FROM PUBLIC, headshot_redteam, headshot_recorder, headshot_judge, headshot_scheduler"
    )
    op.execute(
        "GRANT SELECT ON TABLE hosted_configuration_sets TO headshot_web, headshot_runner"
    )
    op.execute("GRANT INSERT ON TABLE hosted_configuration_sets TO headshot_web")


def downgrade() -> None:
    op.drop_index(
        "ix_hosted_configuration_sets_created",
        table_name="hosted_configuration_sets",
    )
    op.drop_table("hosted_configuration_sets")
