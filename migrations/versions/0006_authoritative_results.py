"""Authoritative campaign results, finding evidence, taxonomy, and accounting.

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-21

This expand-only migration keeps legacy rows readable while requiring the Runner to populate
the new provenance and taxonomy fields for any record that may count toward verified coverage.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "campaign_attempts", sa.Column("case_content_hash", sa.String(length=64), nullable=True)
    )
    op.add_column("campaign_attempts", sa.Column("category", sa.String(length=64), nullable=True))
    op.add_column("campaign_attempts", sa.Column("severity", sa.String(length=16), nullable=True))
    op.add_column(
        "campaign_attempts", sa.Column("attack_class", sa.String(length=16), nullable=True)
    )
    op.add_column(
        "campaign_attempts",
        sa.Column("owasp_mappings", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "campaign_attempts",
        sa.Column("fixture_provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_check_constraint(
        "campaign_attempt_case_hash",
        "campaign_attempts",
        "case_content_hash IS NULL OR case_content_hash ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "campaign_attempt_attack_class",
        "campaign_attempts",
        "attack_class IS NULL OR attack_class IN ('boundary','invariant','regression')",
    )
    op.create_check_constraint(
        "campaign_attempt_severity",
        "campaign_attempts",
        "severity IS NULL OR severity IN ('low','medium','high','critical')",
    )

    op.add_column(
        "attempt_result", sa.Column("execution_profile", sa.String(length=16), nullable=True)
    )
    op.add_column(
        "attempt_result", sa.Column("evidence_provenance", sa.String(length=24), nullable=True)
    )
    op.create_check_constraint(
        "attempt_result_execution_profile",
        "attempt_result",
        "execution_profile IS NULL OR execution_profile IN ('synthetic','live')",
    )
    op.create_check_constraint(
        "attempt_result_evidence_provenance",
        "attempt_result",
        "evidence_provenance IS NULL OR evidence_provenance IN "
        "('synthetic_offline','live_target','scan_only','simulated')",
    )
    op.create_unique_constraint(
        "uq_attempt_result_org_run_attempt",
        "attempt_result",
        ["organization_id", "campaign_run_id", "attempt_id"],
    )

    op.add_column(
        "verdict",
        sa.Column(
            "reason_codes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column("verdict", sa.Column("confirmation_source", sa.String(length=32), nullable=True))
    op.add_column("verdict", sa.Column("error_code", sa.String(length=64), nullable=True))
    op.create_unique_constraint(
        "uq_verdict_org_run_attempt",
        "verdict",
        ["organization_id", "campaign_run_id", "attempt_id"],
    )

    op.add_column("finding", sa.Column("source_kind", sa.String(length=24), nullable=True))
    op.add_column("finding", sa.Column("execution_profile", sa.String(length=16), nullable=True))
    op.add_column(
        "finding",
        sa.Column("published", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_check_constraint(
        "finding_source_kind",
        "finding",
        "source_kind IS NULL OR source_kind IN ('campaign','security_tool','simulated')",
    )
    op.create_check_constraint(
        "finding_execution_profile",
        "finding",
        "execution_profile IS NULL OR execution_profile IN ('synthetic','live')",
    )

    op.create_table(
        "finding_evidence_links",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("evidence_content_hash", sa.String(length=64), nullable=False),
        sa.Column("verdict_id", sa.Integer(), nullable=False),
        sa.Column("provenance", sa.String(length=24), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_finding_evidence_finding",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "campaign_run_id", "attempt_id"],
            [
                "attempt_result.organization_id",
                "attempt_result.campaign_run_id",
                "attempt_result.attempt_id",
            ],
            name="fk_finding_evidence_attempt_result",
        ),
        sa.ForeignKeyConstraint(["verdict_id"], ["verdict.id"], name="fk_finding_evidence_verdict"),
        sa.UniqueConstraint(
            "organization_id",
            "finding_id",
            "campaign_run_id",
            "attempt_id",
            name="uq_finding_evidence_identity",
        ),
        sa.CheckConstraint(
            "evidence_content_hash ~ '^[0-9a-f]{64}$'", name="finding_evidence_hash"
        ),
        sa.CheckConstraint(
            "provenance IN ('synthetic_offline','live_target','scan_only','simulated')",
            name="finding_evidence_provenance",
        ),
    )
    op.create_index(
        "ix_finding_evidence_attempt",
        "finding_evidence_links",
        ["organization_id", "campaign_run_id", "attempt_id"],
    )

    op.create_table(
        "campaign_run_summaries",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("execution_profile", sa.String(length=16), nullable=False),
        sa.Column("provenance", sa.String(length=24), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("confirmed_finding_count", sa.Integer(), nullable=False),
        sa.Column("measured_cost", sa.Numeric(14, 6), nullable=False),
        sa.Column("currency", sa.String(length=3), nullable=False, server_default="USD"),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("ended_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "run_id", name="pk_campaign_run_summaries"),
        sa.ForeignKeyConstraint(
            ["organization_id", "run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_campaign_run_summary_run",
        ),
        sa.CheckConstraint(
            "execution_profile IN ('synthetic','live')", name="campaign_summary_profile"
        ),
        sa.CheckConstraint(
            "provenance IN ('synthetic_offline','live_target')", name="campaign_summary_provenance"
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND request_count >= 0 AND confirmed_finding_count >= 0",
            name="campaign_summary_counts",
        ),
        sa.CheckConstraint("measured_cost >= 0", name="campaign_summary_cost"),
        sa.CheckConstraint("ended_at >= started_at", name="campaign_summary_time_order"),
    )

    op.create_index(
        "uq_campaign_authorization_run_nonce",
        "campaign_authorization_requests",
        ["organization_id", sa.text("(scope_payload->>'run_nonce')")],
        unique=True,
    )

    op.create_table(
        "security_tool_runs",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("tool_version", sa.String(length=64), nullable=False),
        sa.Column("configuration_sha256", sa.String(length=64), nullable=False),
        sa.Column("run_nonce", sa.String(length=128), nullable=False),
        sa.Column("target_id", sa.String(length=128), nullable=False),
        sa.Column("surface_id", sa.String(length=128), nullable=False),
        sa.Column("scan_provenance", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "run_id", name="pk_security_tool_runs"),
        sa.UniqueConstraint(
            "organization_id", "tool_name", "run_nonce", name="uq_security_tool_run_nonce"
        ),
        sa.CheckConstraint(
            "configuration_sha256 ~ '^[0-9a-f]{64}$' AND artifact_sha256 ~ '^[0-9a-f]{64}$'",
            name="security_tool_run_hashes",
        ),
        sa.CheckConstraint(
            "scan_provenance IN ('platform_source','local_fake','platform_staging','live_target')",
            name="security_tool_run_provenance",
        ),
        sa.CheckConstraint(
            "status IN ('completed','failed','deferred')", name="security_tool_run_status"
        ),
        sa.CheckConstraint("finished_at >= started_at", name="security_tool_run_time_order"),
    )
    op.create_table(
        "scan_artifacts",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("artifact_id", sa.String(length=160), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("media_type", sa.String(length=32), nullable=False),
        sa.Column("byte_length", sa.Integer(), nullable=False),
        sa.Column("artifact_locator", sa.String(length=500), nullable=False),
        sa.Column("sanitized_payload", postgresql.BYTEA(), nullable=False),
        sa.Column("contract_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "artifact_id", name="pk_scan_artifacts"),
        sa.ForeignKeyConstraint(
            ["organization_id", "run_id"],
            ["security_tool_runs.organization_id", "security_tool_runs.run_id"],
            name="fk_scan_artifact_run",
        ),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="scan_artifact_hash"),
        sa.CheckConstraint(
            "byte_length >= 0 AND byte_length <= 10485760 AND "
            "octet_length(sanitized_payload) = byte_length",
            name="scan_artifact_size",
        ),
    )
    op.create_table(
        "security_tool_findings",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("finding_id", sa.String(length=160), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("raw_artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("validation_state", sa.String(length=16), nullable=False),
        sa.Column("human_publication_state", sa.String(length=48), nullable=False),
        sa.Column("evidence_provenance", sa.String(length=16), nullable=False),
        sa.Column("contract_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "finding_id", name="pk_security_tool_findings"),
        sa.ForeignKeyConstraint(
            ["organization_id", "run_id"],
            ["security_tool_runs.organization_id", "security_tool_runs.run_id"],
            name="fk_security_tool_finding_run",
        ),
        sa.CheckConstraint(
            "raw_artifact_sha256 ~ '^[0-9a-f]{64}$'", name="security_tool_finding_hash"
        ),
        sa.CheckConstraint(
            "human_publication_state = 'blocked_pending_human_approval'",
            name="security_tool_finding_publication_gate",
        ),
        sa.CheckConstraint(
            "evidence_provenance IN ('scan_only','simulated')",
            name="security_tool_finding_provenance",
        ),
    )
    op.create_table(
        "tool_execution_errors",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("error_id", sa.String(length=160), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("code", sa.String(length=32), nullable=False),
        sa.Column("contract_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "error_id", name="pk_tool_execution_errors"),
        sa.ForeignKeyConstraint(
            ["organization_id", "run_id"],
            ["security_tool_runs.organization_id", "security_tool_runs.run_id"],
            name="fk_tool_execution_error_run",
        ),
    )

    op.execute(
        "CREATE TRIGGER trg_finding_evidence_links_append_only BEFORE UPDATE OR DELETE "
        "ON finding_evidence_links FOR EACH ROW EXECUTE FUNCTION m1d_reject_append_only_mutation()"
    )
    op.execute(
        "CREATE TRIGGER trg_campaign_run_summaries_append_only BEFORE UPDATE OR DELETE "
        "ON campaign_run_summaries FOR EACH ROW EXECUTE FUNCTION m1d_reject_append_only_mutation()"
    )
    for table in (
        "security_tool_runs",
        "scan_artifacts",
        "security_tool_findings",
        "tool_execution_errors",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_append_only BEFORE UPDATE OR DELETE "
            f"ON {table} FOR EACH ROW EXECUTE FUNCTION m1d_reject_append_only_mutation()"
        )

    op.execute(
        "GRANT SELECT ON TABLE attempt_result, verdict, finding, finding_evidence_links, "
        "campaign_run_summaries, security_tool_runs, scan_artifacts, "
        "security_tool_findings, tool_execution_errors "
        "TO headshot_web, headshot_runner"
    )
    op.execute(
        "GRANT INSERT ON TABLE attempt_result, finding_evidence_links, campaign_run_summaries, "
        "verdict, finding, security_tool_runs, scan_artifacts, security_tool_findings, "
        "tool_execution_errors TO headshot_runner"
    )
    op.execute(
        "GRANT USAGE, SELECT ON SEQUENCE attempt_result_id_seq, finding_evidence_links_id_seq, "
        "verdict_id_seq, finding_id_seq TO headshot_runner"
    )


def downgrade() -> None:
    op.drop_table("tool_execution_errors")
    op.drop_table("security_tool_findings")
    op.drop_table("scan_artifacts")
    op.drop_table("security_tool_runs")
    op.drop_index(
        "uq_campaign_authorization_run_nonce", table_name="campaign_authorization_requests"
    )
    op.drop_table("campaign_run_summaries")
    op.drop_index("ix_finding_evidence_attempt", table_name="finding_evidence_links")
    op.drop_table("finding_evidence_links")

    op.drop_constraint("finding_execution_profile", "finding", type_="check")
    op.drop_constraint("finding_source_kind", "finding", type_="check")
    op.drop_column("finding", "published")
    op.drop_column("finding", "execution_profile")
    op.drop_column("finding", "source_kind")

    op.drop_constraint("uq_verdict_org_run_attempt", "verdict", type_="unique")
    op.drop_column("verdict", "error_code")
    op.drop_column("verdict", "confirmation_source")
    op.drop_column("verdict", "reason_codes")

    op.drop_constraint("uq_attempt_result_org_run_attempt", "attempt_result", type_="unique")
    op.drop_constraint("attempt_result_evidence_provenance", "attempt_result", type_="check")
    op.drop_constraint("attempt_result_execution_profile", "attempt_result", type_="check")
    op.drop_column("attempt_result", "evidence_provenance")
    op.drop_column("attempt_result", "execution_profile")

    op.drop_constraint("campaign_attempt_attack_class", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_severity", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_case_hash", "campaign_attempts", type_="check")
    op.drop_column("campaign_attempts", "fixture_provenance")
    op.drop_column("campaign_attempts", "owasp_mappings")
    op.drop_column("campaign_attempts", "attack_class")
    op.drop_column("campaign_attempts", "category")
    op.drop_column("campaign_attempts", "severity")
    op.drop_column("campaign_attempts", "case_content_hash")
