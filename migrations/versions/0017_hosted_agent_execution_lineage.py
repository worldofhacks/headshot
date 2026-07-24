"""Persist authoritative hosted-agent identity, accounting, and Judge reconciliation.

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "agent_executions",
        "measured_cost",
        existing_type=sa.Numeric(14, 6),
        type_=sa.Numeric(20, 12),
        existing_nullable=False,
        existing_server_default=sa.text("0"),
    )
    op.add_column(
        "agent_executions",
        sa.Column("returned_model", sa.String(length=160), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("upstream_provider", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("provider_request_id", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("reasoning_tokens", sa.Integer(), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("configuration_set_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("role_configuration_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("generation_policy_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("physical_attempts", sa.Integer(), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("judge_calibration_id", sa.String(length=67), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("judge_calibration_state", sa.String(length=16), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("oracle_agreement", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "agent_executions",
        sa.Column("decision_authority", sa.String(length=16), nullable=True),
    )

    op.create_check_constraint(
        "agent_execution_hosted_hashes",
        "agent_executions",
        "(configuration_set_sha256 IS NULL OR "
        "configuration_set_sha256 ~ '^[0-9a-f]{64}$') AND "
        "(role_configuration_sha256 IS NULL OR "
        "role_configuration_sha256 ~ '^[0-9a-f]{64}$') AND "
        "(generation_policy_sha256 IS NULL OR "
        "generation_policy_sha256 ~ '^[0-9a-f]{64}$')",
    )
    op.create_check_constraint(
        "agent_execution_hosted_accounting",
        "agent_executions",
        "(reasoning_tokens IS NULL OR reasoning_tokens >= 0) AND "
        "(physical_attempts IS NULL OR physical_attempts > 0)",
    )
    op.create_check_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        "((returned_model IS NULL AND upstream_provider IS NULL "
        "AND provider_request_id IS NULL) OR "
        "(returned_model IS NOT NULL AND upstream_provider IS NOT NULL "
        "AND provider_request_id IS NOT NULL)) AND "
        "(returned_model IS NULL OR returned_model = model)",
    )
    op.create_check_constraint(
        "agent_execution_hosted_measurement_tuple",
        "agent_executions",
        "configuration_set_sha256 IS NULL OR "
        "((returned_model IS NULL AND upstream_provider IS NULL "
        "AND provider_request_id IS NULL AND input_tokens IS NULL "
        "AND output_tokens IS NULL AND reasoning_tokens IS NULL) OR "
        "(returned_model IS NOT NULL AND upstream_provider IS NOT NULL "
        "AND provider_request_id IS NOT NULL AND input_tokens IS NOT NULL "
        "AND output_tokens IS NOT NULL AND reasoning_tokens IS NOT NULL "
        "AND physical_attempts IS NOT NULL))",
    )
    # A NULL configuration_set_sha256 identifies a pre-0017 row. New hosted rows are inserted
    # only by the run-bound hosted lifecycle and therefore carry the complete authority tuple.
    op.create_check_constraint(
        "agent_execution_hosted_authority",
        "agent_executions",
        "configuration_set_sha256 IS NULL OR "
        "(execution_mode = 'hosted_advisory' "
        "AND role_configuration_sha256 IS NOT NULL "
        "AND generation_policy_sha256 IS NOT NULL)",
    )
    op.create_check_constraint(
        "agent_execution_hosted_terminal_lineage",
        "agent_executions",
        "NOT (configuration_set_sha256 IS NOT NULL AND status = 'succeeded') OR "
        "(returned_model IS NOT NULL AND upstream_provider IS NOT NULL "
        "AND provider_request_id IS NOT NULL AND input_tokens IS NOT NULL "
        "AND output_tokens IS NOT NULL AND reasoning_tokens IS NOT NULL "
        "AND physical_attempts IS NOT NULL)",
    )
    op.create_check_constraint(
        "agent_execution_judge_calibration_state",
        "agent_executions",
        "judge_calibration_state IS NULL OR judge_calibration_state IN "
        "('unavailable','failed','passed','invalidated','enabled')",
    )
    op.create_check_constraint(
        "agent_execution_judge_calibration_id",
        "agent_executions",
        "judge_calibration_id IS NULL OR judge_calibration_id ~ '^JC-[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "agent_execution_judge_reconciliation",
        "agent_executions",
        "(judge_calibration_id IS NULL AND judge_calibration_state IS NULL "
        "AND oracle_agreement IS NULL AND decision_authority IS NULL) OR "
        "(agent_role = 'judge' AND execution_mode = 'hosted_advisory' "
        "AND configuration_set_sha256 IS NOT NULL "
        "AND judge_calibration_state IS NOT NULL "
        "AND ((judge_calibration_state = 'unavailable' "
        "AND judge_calibration_id IS NULL) OR "
        "(judge_calibration_state <> 'unavailable' "
        "AND judge_calibration_id IS NOT NULL)) "
        "AND (decision_authority IS NULL OR "
        "decision_authority IN ('oracle','model','none')) "
        "AND (decision_authority <> 'model' OR "
        "judge_calibration_state = 'enabled'))",
    )
    op.create_check_constraint(
        "agent_execution_judge_terminal_authority",
        "agent_executions",
        "NOT (configuration_set_sha256 IS NOT NULL AND agent_role = 'judge' "
        "AND status = 'succeeded') OR decision_authority IS NOT NULL",
    )
    op.create_check_constraint(
        "agent_execution_reconciliation_terminal",
        "agent_executions",
        "(oracle_agreement IS NULL AND decision_authority IS NULL) OR status <> 'running'",
    )
    op.create_index(
        "ix_agent_execution_provider_request",
        "agent_executions",
        ["organization_id", "provider_request_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_agent_execution_provider_request",
        table_name="agent_executions",
    )
    for constraint in (
        "agent_execution_reconciliation_terminal",
        "agent_execution_judge_terminal_authority",
        "agent_execution_judge_reconciliation",
        "agent_execution_judge_calibration_id",
        "agent_execution_judge_calibration_state",
        "agent_execution_hosted_terminal_lineage",
        "agent_execution_hosted_authority",
        "agent_execution_hosted_measurement_tuple",
        "agent_execution_provider_identity",
        "agent_execution_hosted_accounting",
        "agent_execution_hosted_hashes",
    ):
        op.drop_constraint(constraint, "agent_executions", type_="check")
    for column in (
        "decision_authority",
        "oracle_agreement",
        "judge_calibration_state",
        "judge_calibration_id",
        "physical_attempts",
        "generation_policy_sha256",
        "role_configuration_sha256",
        "configuration_set_sha256",
        "reasoning_tokens",
        "provider_request_id",
        "upstream_provider",
        "returned_model",
    ):
        op.drop_column("agent_executions", column)
    op.alter_column(
        "agent_executions",
        "measured_cost",
        existing_type=sa.Numeric(20, 12),
        type_=sa.Numeric(14, 6),
        existing_nullable=False,
        existing_server_default=sa.text("0"),
    )
