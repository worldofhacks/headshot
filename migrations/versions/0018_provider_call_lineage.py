"""Persist append-only physical provider-call lineage.

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-24

Provider invocations/events are authoritative physical network facts. ``agent_executions`` remains
the logical role/Judge projection and is never terminalized by this migration's physical ledger.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_UNSAFE_PROVIDER_IDENTITY_SQL = (
    r"(^|[[:space:]])(Bearer|Basic)[[:space:]]+[A-Za-z0-9._~+/=-]{8,}"
    r"($|[[:space:]])|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{20,}|"
    r"ya29\.[0-9A-Za-z_-]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"[A-Za-z][A-Za-z0-9+.-]*://[^/[:space:]:@]+:[^/[:space:]@]+@|"
    r"(authorization|x-api-key|api-key)[[:space:]]*[:=][[:space:]]*[^[:space:]]+|"
    r"sk-(ant-|or-|proj-)?[A-Za-z0-9_-]{8,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"^[0-9a-f]{40,}$"
)


def upgrade() -> None:
    # The 0017 Runner must be stopped before this migration. Hold an exclusive lock for the
    # complete upgrade so a stale process cannot create a hosted execution between the
    # quiescence assertion and the historical-lineage backfill.
    op.execute("LOCK TABLE agent_executions IN ACCESS EXCLUSIVE MODE")
    op.execute(
        "DO $body$ BEGIN "
        "IF EXISTS (SELECT 1 FROM agent_executions "
        "WHERE execution_mode = 'hosted_advisory' AND status = 'running') THEN "
        "RAISE EXCEPTION '0018 requires zero running hosted agent executions' "
        "USING ERRCODE = '55006'; END IF; "
        "IF EXISTS (SELECT 1 FROM agent_executions "
        "WHERE detail ? 'provider_lineage_state') THEN "
        "RAISE EXCEPTION 'provider_lineage_state is reserved by revision 0018' "
        "USING ERRCODE = '23514'; END IF; END $body$"
    )
    op.alter_column(
        "agent_executions",
        "returned_model",
        existing_type=sa.String(length=160),
        type_=sa.String(length=192),
        existing_nullable=True,
    )
    op.alter_column(
        "agent_executions",
        "upstream_provider",
        existing_type=sa.String(length=64),
        type_=sa.String(length=128),
        existing_nullable=True,
    )
    op.drop_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        type_="check",
    )
    # A failed provider response may expose identity, cost, and each token counter independently.
    # Relax the 0017 all-or-nothing tuple before sanitizing legacy identity so known token facts
    # survive even when credential-shaped identity bytes must be removed.
    op.drop_constraint(
        "agent_execution_hosted_measurement_tuple",
        "agent_executions",
        type_="check",
    )
    op.create_check_constraint(
        "agent_execution_hosted_measurement_tuple",
        "agent_executions",
        "configuration_set_sha256 IS NULL OR physical_attempts IS NOT NULL OR "
        "(returned_model IS NULL AND upstream_provider IS NULL "
        "AND provider_request_id IS NULL AND input_tokens IS NULL "
        "AND output_tokens IS NULL AND reasoning_tokens IS NULL)",
    )
    # Revision 0017 allowed arbitrary bounded provider/model identity text. Never carry
    # credential-shaped bytes into the new lineage surfaces: replace required logical fields with
    # content-free markers, clear the complete response identity tuple atomically, and retain only
    # a durable boolean marker. Cost, token, and physical-call summaries remain.
    op.execute(
        "UPDATE agent_executions SET "
        "provider = CASE WHEN provider ~* "
        f"'{_UNSAFE_PROVIDER_IDENTITY_SQL}' THEN 'redacted' ELSE provider END, "
        "model = CASE WHEN model ~* "
        f"'{_UNSAFE_PROVIDER_IDENTITY_SQL}' "
        "THEN 'unsafe-provider-text-redacted' ELSE model END, "
        "returned_model = NULL, upstream_provider = NULL, "
        "provider_request_id = NULL, "
        "detail = jsonb_set(detail, '{provider_identity_redacted}', 'true'::jsonb, true) "
        "WHERE execution_mode = 'hosted_advisory' AND ("
        f"coalesce(provider, '') ~* '{_UNSAFE_PROVIDER_IDENTITY_SQL}' OR "
        f"coalesce(model, '') ~* '{_UNSAFE_PROVIDER_IDENTITY_SQL}' OR "
        f"coalesce(returned_model, '') ~* '{_UNSAFE_PROVIDER_IDENTITY_SQL}' OR "
        f"coalesce(upstream_provider, '') ~* '{_UNSAFE_PROVIDER_IDENTITY_SQL}' OR "
        f"coalesce(provider_request_id, '') ~* '{_UNSAFE_PROVIDER_IDENTITY_SQL}')"
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
    op.add_column(
        "agent_executions",
        sa.Column("provider_event_status", sa.String(length=32), nullable=True),
    )
    op.drop_constraint("agent_execution_cost", "agent_executions", type_="check")
    op.alter_column(
        "agent_executions",
        "measured_cost",
        existing_type=sa.Numeric(20, 12),
        nullable=True,
        server_default=None,
    )
    # No 0017 row has an authoritative physical event chain. Preserve its logical summaries and
    # call count, but label every historical hosted row explicitly and never fabricate event IDs.
    # Any observed hosted amount is partial even for a single attempt because the event ledger
    # needed to prove completeness did not exist.
    op.execute(
        "UPDATE agent_executions SET detail = detail || "
        '\'{"provider_lineage_state":"historical_not_instrumented"}\'::jsonb '
        "WHERE execution_mode = 'hosted_advisory'"
    )
    op.execute(
        "UPDATE agent_executions SET "
        "cost_measurement_state = CASE "
        "WHEN execution_mode <> 'hosted_advisory' THEN 'measured' "
        "WHEN returned_model IS NULL AND measured_cost = 0 THEN 'not_observed' "
        "ELSE 'partial' END"
    )
    op.execute(
        "UPDATE agent_executions SET measured_cost = NULL "
        "WHERE cost_measurement_state = 'not_observed'"
    )
    op.create_check_constraint(
        "agent_execution_cost_measurement",
        "agent_executions",
        "cost_measurement_state IN "
        "('measured','partial','not_observed','invalid') AND "
        "((cost_measurement_state IN ('measured','partial') "
        "AND measured_cost IS NOT NULL AND measured_cost >= 0 "
        "AND measured_cost < 'Infinity'::numeric) OR "
        "(cost_measurement_state IN ('not_observed','invalid') "
        "AND measured_cost IS NULL))",
    )
    op.create_check_constraint(
        "agent_execution_provider_event_ids",
        "agent_executions",
        "jsonb_typeof(provider_event_ids) = 'array' AND "
        "((jsonb_array_length(provider_event_ids) = 0 AND provider_event_status IS NULL) OR "
        "(jsonb_array_length(provider_event_ids) > 0 AND provider_event_status IS NOT NULL))",
    )
    op.create_check_constraint(
        "agent_execution_provider_event_status",
        "agent_executions",
        "provider_event_status IS NULL OR provider_event_status IN "
        "('succeeded','timeout','retryable_failure','terminal_failure',"
        "'model_mismatch','identity_invalid','route_unauthorized',"
        "'invalid_usage','invalid_output','outcome_unknown')",
    )
    op.create_check_constraint(
        "agent_execution_provider_lineage_state",
        "agent_executions",
        "(execution_mode = 'deterministic' "
        "AND NOT (detail ? 'provider_lineage_state') "
        "AND jsonb_array_length(provider_event_ids) = 0) OR "
        "(execution_mode = 'hosted_advisory' AND "
        "detail ? 'provider_lineage_state' AND "
        "detail->>'provider_lineage_state' IN "
        "('canonical_physical','historical_not_instrumented') AND "
        "(detail->>'provider_lineage_state' <> 'historical_not_instrumented' "
        "OR (status <> 'running' AND jsonb_array_length(provider_event_ids) = 0 "
        "AND cost_measurement_state IN ('partial','not_observed','invalid'))) AND "
        "(detail->>'provider_lineage_state' <> 'canonical_physical' "
        "OR (status = 'running' AND jsonb_array_length(provider_event_ids) "
        "<= COALESCE(physical_attempts, 0)) OR "
        "(status <> 'running' AND jsonb_array_length(provider_event_ids) "
        "= COALESCE(physical_attempts, 0))))",
    )
    op.execute(
        "CREATE FUNCTION agent_execution_protect_provider_lineage_state() RETURNS trigger "
        "LANGUAGE plpgsql AS $body$ BEGIN "
        "IF TG_OP = 'INSERT' AND "
        "NEW.detail->>'provider_lineage_state' = 'historical_not_instrumented' THEN "
        "RAISE EXCEPTION 'historical provider lineage is migration-owned' "
        "USING ERRCODE = '23514'; "
        "ELSIF TG_OP = 'UPDATE' AND "
        "OLD.detail->>'provider_lineage_state' IS DISTINCT FROM "
        "NEW.detail->>'provider_lineage_state' THEN "
        "RAISE EXCEPTION 'provider lineage state is immutable' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $body$"
    )
    op.execute(
        "CREATE TRIGGER trg_agent_execution_provider_lineage_state "
        "BEFORE INSERT OR UPDATE OF detail ON agent_executions FOR EACH ROW "
        "EXECUTE FUNCTION agent_execution_protect_provider_lineage_state()"
    )
    op.create_unique_constraint(
        "uq_agent_execution_org_execution",
        "agent_executions",
        ["organization_id", "execution_id"],
    )

    op.create_table(
        "provider_call_invocations",
        sa.Column("invocation_id", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        # Planner and selecting Red Team calls legitimately precede attempt identity.
        sa.Column("campaign_attempt_id", sa.String(length=64), nullable=True),
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
            "organization_id",
            "invocation_id",
            name="pk_provider_call_invocations",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "logical_execution_id",
            "physical_sequence",
            name="uq_provider_invocation_sequence",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_provider_invocation_idempotency",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "invocation_id",
            "campaign_run_id",
            "logical_execution_id",
            "agent_role",
            "physical_sequence",
            name="uq_provider_invocation_event_identity",
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
        sa.CheckConstraint(
            "physical_sequence > 0",
            name="provider_invocation_positive_sequence",
        ),
        sa.CheckConstraint(
            "invocation_id ~ '^[0-9a-f]{64}$' AND "
            "idempotency_key = 'provider-call:' || invocation_id",
            name="provider_invocation_identity_shape",
        ),
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
        sa.Column("campaign_attempt_id", sa.String(length=64), nullable=True),
        sa.Column("logical_execution_id", sa.String(length=64), nullable=False),
        sa.Column("agent_role", sa.String(length=32), nullable=False),
        sa.Column("physical_sequence", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("returned_model", sa.String(length=192), nullable=True),
        sa.Column("upstream_provider", sa.String(length=128), nullable=True),
        sa.Column("provider_request_id", sa.String(length=256), nullable=True),
        sa.Column("input_tokens", sa.Integer(), nullable=True),
        sa.Column("output_tokens", sa.Integer(), nullable=True),
        sa.Column("reasoning_tokens", sa.Integer(), nullable=True),
        sa.Column("cost_measurement_state", sa.String(length=16), nullable=False),
        sa.Column("measured_cost_usd", sa.Numeric(20, 12), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("duration_ms", sa.Numeric(20, 6), nullable=False),
        sa.PrimaryKeyConstraint(
            "organization_id",
            "event_id",
            name="pk_provider_call_events",
        ),
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
                "logical_execution_id",
                "agent_role",
                "physical_sequence",
            ],
            [
                "provider_call_invocations.organization_id",
                "provider_call_invocations.invocation_id",
                "provider_call_invocations.campaign_run_id",
                "provider_call_invocations.logical_execution_id",
                "provider_call_invocations.agent_role",
                "provider_call_invocations.physical_sequence",
            ],
            name="fk_provider_event_core_identity",
        ),
        sa.CheckConstraint(
            "agent_role IN ('orchestrator','red_team','judge','documentation')",
            name="provider_event_role",
        ),
        sa.CheckConstraint(
            "physical_sequence > 0",
            name="provider_event_positive_sequence",
        ),
        sa.CheckConstraint(
            "duration_ms >= 0 AND duration_ms < 'Infinity'::numeric",
            name="provider_event_nonnegative_duration",
        ),
        sa.CheckConstraint(
            "status IN ('succeeded','timeout','retryable_failure','terminal_failure',"
            "'model_mismatch','identity_invalid','route_unauthorized',"
            "'invalid_usage','invalid_output','outcome_unknown')",
            name="provider_event_status",
        ),
        sa.CheckConstraint(
            "(status = 'succeeded' AND error_code IS NULL) OR "
            "(status = 'timeout' AND error_code = 'provider_timeout') OR "
            "(status = 'retryable_failure' AND error_code = 'provider_retryable') OR "
            "(status = 'terminal_failure' AND error_code = 'provider_terminal') OR "
            "(status = 'model_mismatch' AND error_code = 'returned_model_mismatch') OR "
            "(status = 'identity_invalid' AND error_code = 'provider_identity_invalid') OR "
            "(status = 'route_unauthorized' AND error_code = 'provider_route_unauthorized') OR "
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
            "event_id ~ '^[0-9a-f]{64}$'",
            name="provider_event_id_hash",
        ),
        sa.CheckConstraint(
            "cost_measurement_state IN "
            "('measured','partial','not_observed','invalid') AND "
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
        "ix_provider_invocations_open_recovery",
        "provider_call_invocations",
        ["organization_id", "started_at", "logical_execution_id"],
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
        ["organization_id", "logical_execution_id", "physical_sequence"],
    )
    op.execute(
        "CREATE FUNCTION provider_invocation_validate_logical_identity() RETURNS trigger "
        "LANGUAGE plpgsql AS $body$ BEGIN "
        "PERFORM 1 FROM agent_executions a "
        "WHERE a.organization_id = NEW.organization_id "
        "AND a.execution_id = NEW.logical_execution_id "
        "AND a.campaign_run_id = NEW.campaign_run_id "
        "AND a.attempt_id IS NOT DISTINCT FROM NEW.campaign_attempt_id "
        "AND a.parent_execution_id IS NOT DISTINCT FROM NEW.parent_execution_id "
        "AND a.agent_role = NEW.agent_role "
        "AND a.model = NEW.requested_model "
        "AND a.execution_mode = 'hosted_advisory' "
        "AND a.configuration_set_sha256 = NEW.configuration_set_sha256 "
        "AND a.role_configuration_sha256 = NEW.role_configuration_sha256 "
        "AND a.generation_policy_sha256 = NEW.generation_policy_sha256 "
        "AND a.status = 'running' FOR UPDATE; "
        "IF NOT FOUND THEN "
        "RAISE EXCEPTION 'provider invocation logical identity mismatch' "
        "USING ERRCODE = '23514'; END IF; "
        "IF NEW.physical_sequence <> "
        "(SELECT count(*) + 1 FROM provider_call_invocations i "
        "WHERE i.organization_id = NEW.organization_id "
        "AND i.logical_execution_id = NEW.logical_execution_id) THEN "
        "RAISE EXCEPTION 'provider invocation sequence is not contiguous' "
        "USING ERRCODE = '23514'; END IF; "
        "PERFORM 1 FROM hosted_configuration_sets c, "
        "LATERAL jsonb_array_elements(c.payload->'roles') role "
        "WHERE c.organization_id = NEW.organization_id "
        "AND c.configuration_sha256 = NEW.configuration_set_sha256 "
        "AND role->>'role' = NEW.agent_role "
        "AND role->>'model_id' = NEW.requested_model "
        "AND role->>'upstream_provider' = NEW.configured_upstream "
        "AND role->>'prompt_sha256' = NEW.prompt_sha256; "
        "IF NOT FOUND THEN "
        "RAISE EXCEPTION 'provider invocation differs from hosted role authority' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $body$"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_invocation_logical_identity "
        "BEFORE INSERT ON provider_call_invocations FOR EACH ROW "
        "EXECUTE FUNCTION provider_invocation_validate_logical_identity()"
    )
    op.execute(
        "CREATE FUNCTION provider_invocation_project_attempt_count() RETURNS trigger "
        "LANGUAGE plpgsql AS $body$ BEGIN "
        "UPDATE agent_executions a SET physical_attempts = "
        "(SELECT count(*)::integer FROM provider_call_invocations i "
        "WHERE i.organization_id = NEW.organization_id "
        "AND i.logical_execution_id = NEW.logical_execution_id) "
        "WHERE a.organization_id = NEW.organization_id "
        "AND a.execution_id = NEW.logical_execution_id "
        "AND a.status = 'running'; RETURN NEW; END $body$"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_invocation_attempt_projection "
        "AFTER INSERT ON provider_call_invocations FOR EACH ROW "
        "EXECUTE FUNCTION provider_invocation_project_attempt_count()"
    )
    op.execute(
        "CREATE FUNCTION provider_invocation_protect_logical_attempt_binding() RETURNS trigger "
        "LANGUAGE plpgsql AS $body$ BEGIN "
        "IF OLD.attempt_id IS DISTINCT FROM NEW.attempt_id "
        "AND EXISTS (SELECT 1 FROM provider_call_invocations i "
        "WHERE i.organization_id = OLD.organization_id "
        "AND i.logical_execution_id = OLD.execution_id) THEN "
        "RAISE EXCEPTION 'agent attempt binding follows provider invocation' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $body$"
    )
    op.execute(
        "CREATE TRIGGER trg_agent_execution_provider_attempt_binding "
        "BEFORE UPDATE OF attempt_id ON agent_executions FOR EACH ROW "
        "EXECUTE FUNCTION provider_invocation_protect_logical_attempt_binding()"
    )
    op.execute(
        "CREATE FUNCTION provider_event_validate_attempt_identity() RETURNS trigger "
        "LANGUAGE plpgsql AS $body$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM provider_call_invocations i "
        "WHERE i.organization_id = NEW.organization_id "
        "AND i.invocation_id = NEW.invocation_id "
        "AND i.campaign_attempt_id IS NOT DISTINCT FROM NEW.campaign_attempt_id "
        "AND NEW.finished_at >= i.started_at "
        "AND NEW.duration_ms = "
        "extract(epoch FROM (NEW.finished_at - i.started_at)) * 1000 "
        "AND (NEW.status <> 'succeeded' OR "
        "(NEW.returned_model = i.requested_model AND "
        "CASE split_part(i.configured_upstream, '/', 1) "
        "WHEN 'anthropic' THEN NEW.upstream_provider = 'Anthropic' "
        "WHEN 'together' THEN NEW.upstream_provider = 'Together' "
        "WHEN 'google-vertex' THEN NEW.upstream_provider IN ('Google', 'Google Vertex') "
        "WHEN 'openai' THEN NEW.upstream_provider = 'OpenAI' "
        "WHEN 'atlas-cloud' THEN NEW.upstream_provider = 'AtlasCloud' "
        "ELSE FALSE END))) THEN "
        "RAISE EXCEPTION 'provider event attempt identity mismatch' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $body$"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_event_attempt_identity "
        "BEFORE INSERT ON provider_call_events FOR EACH ROW "
        "EXECUTE FUNCTION provider_event_validate_attempt_identity()"
    )
    # Project only bounded typed facts needed by Web read models. The physical tables stay private
    # to Runner; API queries must never require SELECT on provider_call_events.
    op.execute(
        "CREATE FUNCTION provider_event_project_safe_status() RETURNS trigger "
        "LANGUAGE plpgsql AS $body$ DECLARE projected integer; BEGIN "
        "UPDATE agent_executions SET "
        "provider_event_ids = provider_event_ids || jsonb_build_array(NEW.event_id), "
        "provider_event_status = NEW.status "
        "WHERE organization_id = NEW.organization_id "
        "AND execution_id = NEW.logical_execution_id AND status = 'running'; "
        "GET DIAGNOSTICS projected = ROW_COUNT; "
        "IF projected <> 1 THEN "
        "RAISE EXCEPTION 'provider event could not project safe logical status' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $body$"
    )
    op.execute(
        "CREATE TRIGGER trg_provider_event_safe_status_projection "
        "AFTER INSERT ON provider_call_events FOR EACH ROW "
        "EXECUTE FUNCTION provider_event_project_safe_status()"
    )
    for table in ("provider_call_invocations", "provider_call_events"):
        op.execute(
            f"CREATE TRIGGER trg_{table}_append_only "
            f"BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW "
            "EXECUTE FUNCTION m1d_reject_append_only_mutation()"
        )
        op.execute(
            f"REVOKE ALL PRIVILEGES ON TABLE {table} FROM PUBLIC, headshot_web, "
            "headshot_runner, headshot_redteam, headshot_recorder, headshot_judge, "
            "headshot_scheduler"
        )
        op.execute(f"GRANT SELECT ON TABLE {table} TO headshot_runner")
        op.execute(f"GRANT INSERT ON TABLE {table} TO headshot_runner")


def downgrade() -> None:
    op.drop_constraint(
        "agent_execution_provider_identity",
        "agent_executions",
        type_="check",
    )
    op.execute("DROP TRIGGER trg_agent_execution_provider_attempt_binding ON agent_executions")
    op.execute("DROP FUNCTION provider_invocation_protect_logical_attempt_binding()")
    op.execute("DROP TRIGGER trg_agent_execution_provider_lineage_state ON agent_executions")
    op.execute("DROP FUNCTION agent_execution_protect_provider_lineage_state()")
    # The 0017 logical schema could not represent provider substitution on failed calls.
    op.execute(
        "UPDATE agent_executions SET returned_model = NULL, upstream_provider = NULL, "
        "provider_request_id = NULL, input_tokens = NULL, output_tokens = NULL, "
        "reasoning_tokens = NULL, physical_attempts = NULL "
        "WHERE returned_model IS NOT NULL AND returned_model <> model"
    )
    # Revision 0017 represented provider observations only as an all-or-nothing tuple. Preserve
    # authoritative physical rows, but clear a partial logical projection before restoring that
    # narrower constraint.
    op.execute(
        "UPDATE agent_executions SET returned_model = NULL, upstream_provider = NULL, "
        "provider_request_id = NULL, input_tokens = NULL, output_tokens = NULL, "
        "reasoning_tokens = NULL WHERE configuration_set_sha256 IS NOT NULL AND NOT ("
        "(returned_model IS NULL AND upstream_provider IS NULL "
        "AND provider_request_id IS NULL AND input_tokens IS NULL "
        "AND output_tokens IS NULL AND reasoning_tokens IS NULL) OR "
        "(returned_model IS NOT NULL AND upstream_provider IS NOT NULL "
        "AND provider_request_id IS NOT NULL AND input_tokens IS NOT NULL "
        "AND output_tokens IS NOT NULL AND reasoning_tokens IS NOT NULL "
        "AND physical_attempts IS NOT NULL))"
    )
    op.drop_constraint(
        "agent_execution_hosted_measurement_tuple",
        "agent_executions",
        type_="check",
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
    op.execute("DROP TRIGGER trg_provider_event_safe_status_projection ON provider_call_events")
    op.execute("DROP FUNCTION provider_event_project_safe_status()")
    for name in (
        "ix_provider_events_logical_execution",
        "ix_provider_events_provider_request",
        "ix_provider_events_campaign_order",
        "ix_provider_events_org_role_time",
    ):
        op.drop_index(name, table_name="provider_call_events")
    op.drop_table("provider_call_events")
    op.execute("DROP FUNCTION provider_event_validate_attempt_identity()")
    op.drop_index(
        "ix_provider_invocations_open_recovery",
        table_name="provider_call_invocations",
    )
    op.drop_table("provider_call_invocations")
    op.execute("DROP FUNCTION provider_invocation_project_attempt_count()")
    op.execute("DROP FUNCTION provider_invocation_validate_logical_identity()")
    op.drop_constraint(
        "uq_agent_execution_org_execution",
        "agent_executions",
        type_="unique",
    )
    op.drop_constraint(
        "agent_execution_provider_event_ids",
        "agent_executions",
        type_="check",
    )
    op.drop_constraint(
        "agent_execution_provider_event_status",
        "agent_executions",
        type_="check",
    )
    op.drop_constraint(
        "agent_execution_provider_lineage_state",
        "agent_executions",
        type_="check",
    )
    op.drop_constraint(
        "agent_execution_cost_measurement",
        "agent_executions",
        type_="check",
    )
    op.execute("UPDATE agent_executions SET measured_cost = 0 WHERE measured_cost IS NULL")
    op.execute(
        "UPDATE agent_executions SET detail = detail - 'provider_lineage_state' "
        "WHERE detail ? 'provider_lineage_state'"
    )
    op.alter_column(
        "agent_executions",
        "measured_cost",
        existing_type=sa.Numeric(20, 12),
        nullable=False,
        server_default=sa.text("0"),
    )
    op.create_check_constraint(
        "agent_execution_cost",
        "agent_executions",
        "measured_cost >= 0",
    )
    op.drop_column("agent_executions", "provider_event_status")
    op.drop_column("agent_executions", "provider_event_ids")
    op.drop_column("agent_executions", "cost_measurement_state")
    op.alter_column(
        "agent_executions",
        "upstream_provider",
        existing_type=sa.String(length=128),
        type_=sa.String(length=64),
        existing_nullable=True,
        postgresql_using="left(upstream_provider, 64)",
    )
    op.alter_column(
        "agent_executions",
        "returned_model",
        existing_type=sa.String(length=192),
        type_=sa.String(length=160),
        existing_nullable=True,
        postgresql_using="left(returned_model, 160)",
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
