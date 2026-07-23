"""Persist versioned regression cases, blocked replay plans, and replay results.

Revision ID: 0010
Revises: 0009
Create Date: 2026-07-22

All objects are additive and append-only.  A replay plan is data, never execution authority;
results must reference a real two-person-authorized campaign run and its exact scope hash.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "regression_replay_plans",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("replay_id", sa.String(length=67), nullable=False),
        sa.Column("regression_case_id", sa.String(length=67), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("report_id", sa.String(length=80), nullable=False),
        sa.Column("disposition_id", sa.String(length=80), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("source_target_version", sa.String(length=128), nullable=False),
        sa.Column("replay_target_version", sa.String(length=128), nullable=False),
        sa.Column("attack_sequence_sha256", sa.String(length=64), nullable=False),
        sa.Column("contract_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "replay_id", name="pk_regression_replay_plans"),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_regression_replay_plan_finding",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "report_id"],
            ["vuln_reports.organization_id", "vuln_reports.report_id"],
            name="fk_regression_replay_plan_report",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "disposition_id"],
            ["regression_dispositions.organization_id", "regression_dispositions.disposition_id"],
            name="fk_regression_replay_plan_disposition",
        ),
        sa.CheckConstraint(
            "attack_sequence_sha256 ~ '^[0-9a-f]{64}$'",
            name="regression_replay_plan_attack_hash",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(contract_payload) = 'object'",
            name="regression_replay_plan_payload_object",
        ),
        sa.CheckConstraint(
            "((contract_payload->>'replay_id' = replay_id) AND "
            "(contract_payload->>'regression_case_id' = regression_case_id) AND "
            "(contract_payload->>'finding_id' = finding_id) AND "
            "(contract_payload->>'report_id' = report_id) AND "
            "(contract_payload->>'target_id' = target_id) AND "
            "(contract_payload->>'source_target_version' = source_target_version) AND "
            "(contract_payload->>'replay_target_version' = replay_target_version) AND "
            "(contract_payload->>'attack_sequence_sha256' = attack_sequence_sha256) AND "
            "(contract_payload->>'authorization_state' = 'pending_human_authorization') AND "
            "(contract_payload->>'execution_state' = 'blocked')) IS TRUE",
            name="regression_replay_plan_payload_projection",
        ),
    )
    op.create_index(
        "ix_regression_replay_plans_target_version",
        "regression_replay_plans",
        ["organization_id", "target_id", "replay_target_version"],
    )
    op.create_index(
        "ix_regression_replay_plans_case",
        "regression_replay_plans",
        ["organization_id", "regression_case_id", "created_at"],
    )

    op.create_table(
        "regression_replay_results",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("result_id", sa.String(length=68), nullable=False),
        sa.Column("replay_id", sa.String(length=67), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("authorization_scope_hash", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("replay_target_version", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("reappeared", sa.Boolean(), nullable=False),
        sa.Column("contract_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint(
            "organization_id", "result_id", name="pk_regression_replay_results"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "replay_id"],
            ["regression_replay_plans.organization_id", "regression_replay_plans.replay_id"],
            name="fk_regression_replay_result_plan",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "campaign_run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_regression_replay_result_campaign",
        ),
        sa.UniqueConstraint(
            "organization_id", "replay_id", "campaign_run_id", name="uq_replay_result_run"
        ),
        sa.CheckConstraint(
            "authorization_scope_hash ~ '^[0-9a-f]{64}$'",
            name="regression_replay_result_scope_hash",
        ),
        sa.CheckConstraint(
            "state IN ('passing','failing','inconclusive')",
            name="regression_replay_result_state",
        ),
        sa.CheckConstraint(
            "(state = 'failing' AND reappeared) OR (state <> 'failing')",
            name="regression_replay_result_reappearance",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(contract_payload) = 'object'",
            name="regression_replay_result_payload_object",
        ),
        sa.CheckConstraint(
            "((contract_payload->>'result_id' = result_id) AND "
            "(contract_payload->>'replay_id' = replay_id) AND "
            "(contract_payload->>'campaign_run_id' = campaign_run_id) AND "
            "(contract_payload->>'authorization_scope_hash' = authorization_scope_hash) AND "
            "(contract_payload->>'target_id' = target_id) AND "
            "(contract_payload->>'replay_target_version' = replay_target_version) AND "
            "(contract_payload->>'state' = state) AND "
            "(contract_payload->>'reappeared' = "
            "CASE WHEN reappeared THEN 'true' ELSE 'false' END)) IS TRUE",
            name="regression_replay_result_payload_projection",
        ),
    )
    op.create_index(
        "ix_regression_replay_results_target_version",
        "regression_replay_results",
        ["organization_id", "target_id", "replay_target_version", "state"],
    )

    op.create_table(
        "regression_case_versions",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("regression_case_id", sa.String(length=67), nullable=False),
        sa.Column("case_version", sa.String(length=32), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("report_id", sa.String(length=80), nullable=False),
        sa.Column("admission_disposition_id", sa.String(length=80), nullable=False),
        sa.Column("admission_result_id", sa.String(length=68), nullable=False),
        sa.Column("source_case_id", sa.String(length=120), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("source_target_version", sa.String(length=128), nullable=False),
        sa.Column("attack_sequence_sha256", sa.String(length=64), nullable=False),
        sa.Column("attack_attempt", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("required_oracle_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("planned_repetitions", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint(
            "organization_id",
            "regression_case_id",
            "case_version",
            name="pk_regression_case_versions",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["finding.organization_id", "finding.finding_id"],
            name="fk_regression_case_version_finding",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "report_id"],
            ["vuln_reports.organization_id", "vuln_reports.report_id"],
            name="fk_regression_case_version_report",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "admission_disposition_id"],
            ["regression_dispositions.organization_id", "regression_dispositions.disposition_id"],
            name="fk_regression_case_version_admission",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "admission_result_id"],
            ["regression_replay_results.organization_id", "regression_replay_results.result_id"],
            name="fk_regression_case_version_result",
        ),
        sa.CheckConstraint(
            "case_version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+$'",
            name="regression_case_version_semver",
        ),
        sa.CheckConstraint(
            "attack_sequence_sha256 ~ '^[0-9a-f]{64}$'",
            name="regression_case_version_attack_hash",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(attack_attempt) = 'object'",
            name="regression_case_version_attack_object",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(required_oracle_ids) = 'array' AND "
            "jsonb_array_length(required_oracle_ids) > 0",
            name="regression_case_version_oracles",
        ),
        sa.CheckConstraint(
            "planned_repetitions BETWEEN 2 AND 20",
            name="regression_case_version_repetitions",
        ),
    )
    op.create_index(
        "ix_regression_case_versions_target",
        "regression_case_versions",
        ["organization_id", "target_id", "source_target_version"],
    )
    op.create_index(
        "ix_regression_case_versions_finding",
        "regression_case_versions",
        ["organization_id", "finding_id", "case_version"],
    )

    for table in (
        "regression_replay_plans",
        "regression_replay_results",
        "regression_case_versions",
    ):
        op.execute(
            f"CREATE TRIGGER trg_{table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION m1d_reject_append_only_mutation()"
        )

    op.execute(
        "REVOKE ALL PRIVILEGES ON TABLE regression_replay_plans, "
        "regression_replay_results, regression_case_versions FROM PUBLIC, "
        "headshot_redteam, headshot_recorder, headshot_judge"
    )
    op.execute(
        "GRANT SELECT ON TABLE regression_replay_plans, regression_replay_results, "
        "regression_case_versions TO headshot_web, headshot_runner"
    )
    op.execute("GRANT INSERT ON TABLE regression_replay_plans TO headshot_web, headshot_runner")
    op.execute("GRANT INSERT ON TABLE regression_replay_results TO headshot_runner")
    op.execute("GRANT INSERT ON TABLE regression_case_versions TO headshot_web")


def downgrade() -> None:
    op.drop_index("ix_regression_case_versions_finding", table_name="regression_case_versions")
    op.drop_index("ix_regression_case_versions_target", table_name="regression_case_versions")
    op.drop_table("regression_case_versions")
    op.drop_index(
        "ix_regression_replay_results_target_version", table_name="regression_replay_results"
    )
    op.drop_table("regression_replay_results")
    op.drop_index("ix_regression_replay_plans_case", table_name="regression_replay_plans")
    op.drop_index("ix_regression_replay_plans_target_version", table_name="regression_replay_plans")
    op.drop_table("regression_replay_plans")
