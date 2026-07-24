"""Persist append-only physical provider-call lineage.

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-24
"""

from __future__ import annotations

import datetime
import hashlib
import json
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _terminal_contract_hash(row: sa.RowMapping) -> str:
    payload = {
        "schema_version": 1,
        "event_id": row["event_id"],
        "invocation_id": row["invocation_id"],
        "physical_sequence": row["physical_sequence"],
        "status": row["status"],
        "returned_model": row["returned_model"],
        "upstream_provider": row["upstream_provider"],
        "provider_request_id": row["provider_request_id"],
        "input_tokens": row["input_tokens"],
        "output_tokens": row["output_tokens"],
        "reasoning_tokens": row["reasoning_tokens"],
        "cost_measurement_state": row["cost_measurement_state"],
        "measured_cost_usd": (
            format(row["measured_cost_usd"], ".12f")
            if row["measured_cost_usd"] is not None
            else None
        ),
        "error_code": row["error_code"],
        "finished_at": row["finished_at"]
        .astimezone(datetime.UTC)
        .isoformat(timespec="microseconds"),
    }
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def upgrade() -> None:
    op.add_column(
        "agent_executions",
        sa.Column(
            "cost_measurement_state",
            sa.String(length=16),
            nullable=False,
            server_default=sa.text("'not_observed'"),
        ),
    )
    op.add_column(
        "agent_executions",
        sa.Column(
            "provider_event_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.alter_column("agent_executions", "measured_cost", nullable=True, server_default=None)
    op.execute(
        "UPDATE agent_executions SET measured_cost = NULL, "
        "cost_measurement_state = 'not_observed' WHERE measured_cost = 0"
    )
    op.execute(
        "UPDATE agent_executions SET cost_measurement_state = 'measured' "
        "WHERE measured_cost IS NOT NULL"
    )
    op.drop_constraint("agent_execution_terminal_shape", "agent_executions", type_="check")
    op.create_check_constraint(
        "agent_execution_terminal_shape",
        "agent_executions",
        "(status = 'running' AND finished_at IS NULL AND duration_ms IS NULL "
        "AND output_sha256 IS NULL AND error_code IS NULL) OR "
        "(status = 'succeeded' AND finished_at IS NOT NULL AND duration_ms IS NOT NULL "
        "AND output_sha256 IS NOT NULL AND error_code IS NULL) OR "
        "(status = 'failed' AND finished_at IS NOT NULL AND duration_ms IS NOT NULL "
        "AND error_code IS NOT NULL) OR "
        "(status = 'skipped' AND finished_at IS NOT NULL AND duration_ms IS NOT NULL "
        "AND output_sha256 IS NOT NULL)",
    )
    op.create_check_constraint(
        "agent_execution_cost_measurement",
        "agent_executions",
        "cost_measurement_state IN ('measured','partial','not_observed','invalid') AND "
        "((cost_measurement_state IN ('measured','partial') AND measured_cost IS NOT NULL "
        "AND measured_cost >= 0 AND measured_cost < 'Infinity'::numeric) OR "
        "(cost_measurement_state IN ('not_observed','invalid') AND measured_cost IS NULL) OR "
        "(cost_measurement_state = 'not_observed' AND measured_cost = 0 "
        "AND provider_event_ids = '[]'::jsonb))",
    )
    op.create_check_constraint(
        "agent_execution_provider_event_ids",
        "agent_executions",
        "jsonb_typeof(provider_event_ids) = 'array'",
    )
    op.create_unique_constraint(
        "uq_agent_execution_org_execution",
        "agent_executions",
        ["organization_id", "execution_id"],
    )
    op.execute(
        "CREATE FUNCTION normalize_agent_execution_unknown_cost() RETURNS trigger "
        "LANGUAGE plpgsql AS $body$ BEGIN "
        "IF NEW.cost_measurement_state = 'not_observed' AND NEW.measured_cost = 0 THEN "
        "NEW.measured_cost := NULL; END IF; RETURN NEW; END $body$"
    )
    op.execute(
        "CREATE TRIGGER trg_agent_execution_unknown_cost "
        "BEFORE INSERT OR UPDATE OF measured_cost, cost_measurement_state "
        "ON agent_executions FOR EACH ROW "
        "EXECUTE FUNCTION normalize_agent_execution_unknown_cost()"
    )

    op.create_table(
        "provider_call_invocations",
        sa.Column("invocation_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_attempt_id", sa.String(length=64), nullable=False),
        sa.Column("logical_execution_id", sa.String(length=64), nullable=False),
        sa.Column("parent_execution_id", sa.String(length=64), nullable=True),
        sa.Column("agent_role", sa.String(length=32), nullable=False),
        sa.Column("physical_sequence", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("requested_model", sa.String(length=192), nullable=False),
        sa.Column("configured_upstream", sa.String(length=128), nullable=False),
        sa.Column("prompt_version", sa.String(length=64), nullable=False),
        sa.Column("prompt_sha256", sa.String(length=64), nullable=False),
        sa.Column("configuration_set_sha256", sa.String(length=64), nullable=False),
        sa.Column("role_configuration_sha256", sa.String(length=64), nullable=False),
        sa.Column("generation_policy_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "started_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("clock_timestamp()"),
        ),
        sa.PrimaryKeyConstraint(
            "organization_id", "invocation_id", name="pk_provider_call_invocations"
        ),
        sa.UniqueConstraint(
            "organization_id",
            "logical_execution_id",
            "physical_sequence",
            name="uq_provider_invocation_sequence",
        ),
        sa.UniqueConstraint("idempotency_key", name="uq_provider_invocation_idempotency"),
        sa.UniqueConstraint(
            "organization_id",
            "invocation_id",
            "campaign_run_id",
            "campaign_attempt_id",
            "logical_execution_id",
            "agent_role",
            "physical_sequence",
            name="uq_provider_invocation_full_identity",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "logical_execution_id"],
            ["agent_executions.organization_id", "agent_executions.execution_id"],
            name="fk_provider_invocation_logical_execution",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "parent_execution_id"],
            ["agent_executions.organization_id", "agent_executions.execution_id"],
            name="fk_provider_invocation_parent_execution",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "campaign_run_id", "campaign_attempt_id"],
            [
                "campaign_attempts.organization_id",
                "campaign_attempts.run_id",
                "campaign_attempts.attempt_id",
            ],
            name="fk_provider_invocation_campaign_attempt",
        ),
        sa.CheckConstraint(
            "agent_role IN ('orchestrator','red_team','judge','documentation')",
            name="provider_invocation_role",
        ),
        sa.CheckConstraint("physical_sequence > 0", name="provider_invocation_positive_sequence"),
        sa.CheckConstraint(
            "prompt_sha256 ~ '^[0-9a-f]{64}$' AND "
            "configuration_set_sha256 ~ '^[0-9a-f]{64}$' AND "
            "role_configuration_sha256 ~ '^[0-9a-f]{64}$' AND "
            "generation_policy_sha256 ~ '^[0-9a-f]{64}$'",
            name="provider_invocation_hashes",
        ),
    )

    op.create_table(
        "provider_call_events",
        sa.Column("event_id", sa.String(length=64), nullable=False),
        sa.Column("invocation_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_attempt_id", sa.String(length=64), nullable=False),
        sa.Column("logical_execution_id", sa.String(length=64), nullable=False),
        sa.Column("agent_role", sa.String(length=32), nullable=False),
        sa.Column("physical_sequence", sa.Integer(), nullable=False),
        sa.Column(
            "is_final",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("returned_model", sa.String(length=192), nullable=True),
        sa.Column("upstream_provider", sa.String(length=128), nullable=True),
        sa.Column("provider_request_id", sa.String(length=192), nullable=True),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("reasoning_tokens", sa.Integer(), nullable=True),
        sa.Column("cost_measurement_state", sa.String(length=16), nullable=False),
        sa.Column("measured_cost_usd", sa.Numeric(20, 12), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Numeric(14, 3), nullable=False),
        sa.PrimaryKeyConstraint("organization_id", "event_id", name="pk_provider_call_events"),
        sa.UniqueConstraint(
            "organization_id",
            "invocation_id",
            name="uq_provider_event_invocation",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "invocation_id"],
            [
                "provider_call_invocations.organization_id",
                "provider_call_invocations.invocation_id",
            ],
            name="fk_provider_event_invocation",
        ),
        sa.ForeignKeyConstraint(
            [
                "organization_id",
                "invocation_id",
                "campaign_run_id",
                "campaign_attempt_id",
                "logical_execution_id",
                "agent_role",
                "physical_sequence",
            ],
            [
                "provider_call_invocations.organization_id",
                "provider_call_invocations.invocation_id",
                "provider_call_invocations.campaign_run_id",
                "provider_call_invocations.campaign_attempt_id",
                "provider_call_invocations.logical_execution_id",
                "provider_call_invocations.agent_role",
                "provider_call_invocations.physical_sequence",
            ],
            name="fk_provider_event_full_identity",
        ),
        sa.CheckConstraint(
            "agent_role IN ('orchestrator','red_team','judge','documentation')",
            name="provider_event_role",
        ),
        sa.CheckConstraint("physical_sequence > 0", name="provider_event_positive_sequence"),
        sa.CheckConstraint(
            "duration_ms >= 0 AND duration_ms < 'Infinity'::numeric",
            name="provider_event_nonnegative_duration",
        ),
        sa.CheckConstraint(
            "status IN ('succeeded','timeout','retryable_failure','terminal_failure',"
            "'model_mismatch','invalid_usage','invalid_output','outcome_unknown')",
            name="provider_event_status",
        ),
        sa.CheckConstraint(
            "(status = 'succeeded' AND error_code IS NULL) OR "
            "(status = 'timeout' AND error_code = 'provider_timeout') OR "
            "(status = 'retryable_failure' AND error_code = 'provider_retryable') OR "
            "(status = 'terminal_failure' AND error_code = 'provider_terminal') OR "
            "(status = 'model_mismatch' AND error_code = 'returned_model_mismatch') OR "
            "(status = 'invalid_usage' AND error_code = 'invalid_provider_usage') OR "
            "(status = 'invalid_output' AND error_code = 'invalid_structured_output') OR "
            "(status = 'outcome_unknown' AND error_code = 'provider_outcome_unknown')",
            name="provider_event_error_shape",
        ),
        sa.CheckConstraint(
            "(input_tokens IS NULL OR input_tokens >= 0) AND "
            "(output_tokens IS NULL OR output_tokens >= 0) AND "
            "(reasoning_tokens IS NULL OR reasoning_tokens >= 0)",
            name="provider_event_usage",
        ),
        sa.CheckConstraint(
            "cost_measurement_state IN ('measured','partial','not_observed','invalid') AND "
            "((cost_measurement_state IN ('measured','partial') "
            "AND measured_cost_usd IS NOT NULL AND measured_cost_usd >= 0 "
            "AND measured_cost_usd < 'Infinity'::numeric) OR "
            "(cost_measurement_state IN ('not_observed','invalid') "
            "AND measured_cost_usd IS NULL))",
            name="provider_event_cost_measurement",
        ),
        sa.CheckConstraint(
            "status <> 'succeeded' OR "
            "(returned_model IS NOT NULL AND upstream_provider IS NOT NULL "
            "AND provider_request_id IS NOT NULL AND input_tokens IS NOT NULL "
            "AND output_tokens IS NOT NULL AND reasoning_tokens IS NOT NULL "
            "AND cost_measurement_state = 'measured')",
            name="provider_event_success_observations",
        ),
    )
    op.create_index(
        "ix_provider_events_org_role_time",
        "provider_call_events",
        ["organization_id", "agent_role", "finished_at"],
    )
    op.create_index(
        "ix_provider_events_campaign_order",
        "provider_call_events",
        ["organization_id", "campaign_run_id", "physical_sequence"],
    )
    op.create_index(
        "ix_provider_events_provider_request",
        "provider_call_events",
        ["organization_id", "provider_request_id"],
    )
    op.create_index(
        "ix_provider_events_logical_execution",
        "provider_call_events",
        ["organization_id", "logical_execution_id"],
    )
    op.create_index(
        "uq_provider_events_logical_final",
        "provider_call_events",
        ["organization_id", "logical_execution_id"],
        unique=True,
        postgresql_where=sa.text("is_final"),
    )
    for table in ("provider_call_invocations", "provider_call_events"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_append_only "
            f"BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW "
            "EXECUTE FUNCTION m1d_reject_append_only_mutation()"
        )
        op.execute(
            f"REVOKE ALL PRIVILEGES ON TABLE {table} FROM PUBLIC, headshot_web, headshot_runner, "
            "headshot_redteam, headshot_recorder, headshot_judge, headshot_scheduler"
        )
        op.execute(f"GRANT SELECT ON TABLE {table} TO headshot_web, headshot_runner")
        op.execute(f"GRANT INSERT ON TABLE {table} TO headshot_runner")


def downgrade() -> None:
    connection = op.get_bind()
    translated_failures = (
        connection.execute(
            sa.text(
                "SELECT e.event_id, e.invocation_id, e.physical_sequence, e.status, "
                "e.returned_model, e.upstream_provider, e.provider_request_id, "
                "e.input_tokens, e.output_tokens, e.reasoning_tokens, "
                "e.cost_measurement_state, e.measured_cost_usd, e.error_code, e.finished_at, "
                "e.organization_id, e.logical_execution_id "
                "FROM provider_call_events e JOIN agent_executions a "
                "ON a.organization_id = e.organization_id "
                "AND a.execution_id = e.logical_execution_id "
                "WHERE e.is_final AND a.status <> 'running' AND a.output_sha256 IS NULL"
            )
        )
        .mappings()
        .all()
    )
    for row in translated_failures:
        connection.execute(
            sa.text(
                "UPDATE agent_executions SET output_sha256 = :output_hash "
                "WHERE organization_id = :org AND execution_id = :execution "
                "AND output_sha256 IS NULL"
            ),
            {
                "output_hash": _terminal_contract_hash(row),
                "org": row["organization_id"],
                "execution": row["logical_execution_id"],
            },
        )
    for name in (
        "uq_provider_events_logical_final",
        "ix_provider_events_logical_execution",
        "ix_provider_events_provider_request",
        "ix_provider_events_campaign_order",
        "ix_provider_events_org_role_time",
    ):
        op.drop_index(name, table_name="provider_call_events")
    op.drop_table("provider_call_events")
    op.drop_table("provider_call_invocations")
    op.execute("DROP TRIGGER IF EXISTS trg_agent_execution_unknown_cost ON agent_executions")
    op.execute("DROP FUNCTION IF EXISTS normalize_agent_execution_unknown_cost()")
    op.drop_constraint("uq_agent_execution_org_execution", "agent_executions", type_="unique")
    op.drop_constraint("agent_execution_provider_event_ids", "agent_executions", type_="check")
    op.drop_constraint("agent_execution_cost_measurement", "agent_executions", type_="check")
    op.drop_constraint("agent_execution_terminal_shape", "agent_executions", type_="check")
    op.execute("UPDATE agent_executions SET measured_cost = 0 WHERE measured_cost IS NULL")
    op.alter_column(
        "agent_executions",
        "measured_cost",
        nullable=False,
        server_default=sa.text("0"),
    )
    op.create_check_constraint(
        "agent_execution_terminal_shape",
        "agent_executions",
        "(status = 'running' AND finished_at IS NULL AND duration_ms IS NULL "
        "AND output_sha256 IS NULL AND error_code IS NULL) OR "
        "(status <> 'running' AND finished_at IS NOT NULL AND duration_ms IS NOT NULL "
        "AND output_sha256 IS NOT NULL)",
    )
    op.drop_column("agent_executions", "provider_event_ids")
    op.drop_column("agent_executions", "cost_measurement_state")
