"""Persist draft vulnerability reports and regression dispositions.

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-22

Both tables are append-only and additive.  The Runner can insert validated drafts/dispositions,
but neither table represents publication or remediation authority.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vuln_reports",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("report_id", sa.String(length=80), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("reproduction_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("publication_state", sa.String(length=48), nullable=False),
        sa.Column(
            "contract_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "report_id", name="pk_vuln_reports"),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_vuln_report_finding",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "campaign_run_id", "attempt_id"],
            [
                "attempt_result.organization_id",
                "attempt_result.campaign_run_id",
                "attempt_result.attempt_id",
            ],
            name="fk_vuln_report_attempt_result",
        ),
        sa.UniqueConstraint("organization_id", "finding_id", name="uq_vuln_report_org_finding"),
        sa.UniqueConstraint(
            "organization_id",
            "reproduction_sha256",
            name="uq_vuln_report_org_reproduction",
        ),
        sa.CheckConstraint(
            "reproduction_sha256 ~ '^[0-9a-f]{64}$'", name="vuln_report_reproduction_hash"
        ),
        sa.CheckConstraint("status = 'draft'", name="vuln_report_draft_only"),
        sa.CheckConstraint(
            "publication_state IN ('draft_unpublished','blocked_pending_human_approval')",
            name="vuln_report_publication_draft_only",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(contract_payload) = 'object'", name="vuln_report_payload_object"
        ),
        sa.CheckConstraint(
            "((contract_payload->>'report_id' = report_id) AND "
            "(contract_payload->>'finding_id' = finding_id) AND "
            "(contract_payload->>'campaign_run_id' = campaign_run_id) AND "
            "(contract_payload->>'attempt_id' = attempt_id) AND "
            "(contract_payload->>'reproduction_sha256' = reproduction_sha256) AND "
            "(contract_payload->>'status' = status) AND "
            "(contract_payload->>'publication_state' = publication_state)) IS TRUE",
            name="payload_projection",
        ),
        sa.CheckConstraint(
            "((contract_payload->>'severity' <> 'critical') OR "
            "publication_state = 'blocked_pending_human_approval') IS TRUE",
            name="critical_publication",
        ),
    )
    op.create_index(
        "ix_vuln_reports_run_attempt",
        "vuln_reports",
        ["organization_id", "campaign_run_id", "attempt_id"],
    )

    op.create_table(
        "regression_dispositions",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("disposition_id", sa.String(length=80), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("report_id", sa.String(length=80), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=48), nullable=False),
        sa.Column("admitted", sa.Boolean(), nullable=False),
        sa.Column(
            "contract_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint(
            "organization_id", "disposition_id", name="pk_regression_dispositions"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_regression_disposition_finding",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "report_id"],
            ["vuln_reports.organization_id", "vuln_reports.report_id"],
            name="fk_regression_disposition_report",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "campaign_run_id", "attempt_id"],
            [
                "attempt_result.organization_id",
                "attempt_result.campaign_run_id",
                "attempt_result.attempt_id",
            ],
            name="fk_regression_disposition_attempt_result",
        ),
        sa.CheckConstraint(
            "state IN ('pending_deterministic_reproduction','rejected_non_deterministic',"
            "'rejected_wrong_reason','blocked_pending_human_approval','admitted')",
            name="regression_disposition_state",
        ),
        sa.CheckConstraint(
            "(state = 'admitted' AND admitted) OR (state <> 'admitted' AND NOT admitted)",
            name="regression_disposition_admitted_consistent",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(contract_payload) = 'object'",
            name="regression_disposition_payload_object",
        ),
        sa.CheckConstraint(
            "((contract_payload->>'disposition_id' = disposition_id) AND "
            "(contract_payload->>'finding_id' = finding_id) AND "
            "(contract_payload->>'report_id' = report_id) AND "
            "(contract_payload->>'campaign_run_id' = campaign_run_id) AND "
            "(contract_payload->>'attempt_id' = attempt_id) AND "
            "(contract_payload->>'state' = state) AND "
            "(contract_payload->>'admitted' = "
            "CASE WHEN admitted THEN 'true' ELSE 'false' END)) IS TRUE",
            name="payload_projection",
        ),
        sa.CheckConstraint(
            "((state <> 'admitted') OR "
            "((contract_payload->>'reproduction_attempted' = 'true') AND "
            "(contract_payload->>'deterministic_reproduction' = 'true') AND "
            "(contract_payload->>'passes_for_right_reason' = 'true') AND "
            "(contract_payload->>'human_approved' = 'true'))) IS TRUE",
            name="admission_proof",
        ),
    )
    op.create_index(
        "ix_regression_dispositions_run_attempt",
        "regression_dispositions",
        ["organization_id", "campaign_run_id", "attempt_id"],
    )
    op.create_index(
        "ix_regression_dispositions_finding_history",
        "regression_dispositions",
        ["organization_id", "finding_id", "created_at"],
    )

    op.execute(
        "CREATE TRIGGER trg_vuln_reports_append_only BEFORE UPDATE OR DELETE "
        "ON vuln_reports FOR EACH ROW EXECUTE FUNCTION m1d_reject_append_only_mutation()"
    )
    op.execute(
        "CREATE TRIGGER trg_regression_dispositions_append_only BEFORE UPDATE OR DELETE "
        "ON regression_dispositions FOR EACH ROW "
        "EXECUTE FUNCTION m1d_reject_append_only_mutation()"
    )
    op.execute(
        "GRANT SELECT ON TABLE vuln_reports, regression_dispositions "
        "TO headshot_web, headshot_runner"
    )
    op.execute("GRANT INSERT ON TABLE vuln_reports, regression_dispositions TO headshot_runner")


def downgrade() -> None:
    op.drop_index(
        "ix_regression_dispositions_finding_history",
        table_name="regression_dispositions",
    )
    op.drop_index("ix_regression_dispositions_run_attempt", table_name="regression_dispositions")
    op.drop_table("regression_dispositions")
    op.drop_index("ix_vuln_reports_run_attempt", table_name="vuln_reports")
    op.drop_table("vuln_reports")
