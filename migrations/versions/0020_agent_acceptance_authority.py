"""Add first-class authority for bounded, no-target hosted-agent acceptance.

Revision ID: 0020
Revises: 0019
Create Date: 2026-07-24

``campaign`` retains the exact two-person authorization branch. ``agent_acceptance`` is a
separate, system-provenanced authority for three provider/Langfuse calls and zero target calls.
Each acceptance run atomically owns one synthetic, target-free campaign attempt so its logical
and physical provider records use the canonical non-null attempt lineage introduced by 0018.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _discriminated_campaign_run_trigger() -> str:
    return (
        "CREATE OR REPLACE FUNCTION m1d_validate_campaign_run() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE persisted_launcher text; persisted_session text; persisted_hash text; "
        "persisted_expiry timestamptz; approved_count integer; BEGIN "
        "IF NEW.run_kind = 'campaign' THEN "
        "SELECT launcher_user_id, launcher_session_id, scope_hash, expires_at "
        "INTO persisted_launcher, persisted_session, persisted_hash, persisted_expiry "
        "FROM campaign_authorization_requests WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id FOR SHARE; "
        "SELECT count(*) INTO approved_count FROM campaign_authorization_decisions "
        "WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id "
        "AND scope_hash = NEW.scope_hash AND decision = 'approved'; "
        "IF persisted_launcher IS NULL OR persisted_launcher <> NEW.launcher_user_id "
        "OR persisted_session <> NEW.launcher_session_id "
        "OR persisted_hash <> NEW.scope_hash OR persisted_expiry <= clock_timestamp() "
        "OR approved_count <> 1 THEN "
        "RAISE EXCEPTION "
        "'campaign run requires one live exact-scope approval for its persisted launcher' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; "
        "ELSIF NEW.run_kind = 'agent_acceptance' THEN "
        "IF NEW.acceptance_expires_at IS NULL "
        "OR NEW.acceptance_expires_at <= clock_timestamp() THEN "
        "RAISE EXCEPTION 'agent acceptance authority expired' "
        "USING ERRCODE = '42501'; END IF; "
        "PERFORM 1 FROM hosted_configuration_sets "
        "WHERE organization_id = NEW.organization_id "
        "AND configuration_sha256 = NEW.acceptance_configuration_sha256 FOR SHARE; "
        "IF NOT FOUND THEN "
        "RAISE EXCEPTION 'agent acceptance configuration is unavailable' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; "
        "ELSE RAISE EXCEPTION 'campaign run kind is unavailable' "
        "USING ERRCODE = '23514'; END IF; END $$"
    )


def _legacy_campaign_run_trigger() -> str:
    return (
        "CREATE OR REPLACE FUNCTION m1d_validate_campaign_run() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE persisted_launcher text; persisted_session text; persisted_hash text; "
        "persisted_expiry timestamptz; approved_count integer; BEGIN "
        "SELECT launcher_user_id, launcher_session_id, scope_hash, expires_at "
        "INTO persisted_launcher, persisted_session, persisted_hash, persisted_expiry "
        "FROM campaign_authorization_requests WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id FOR SHARE; "
        "SELECT count(*) INTO approved_count FROM campaign_authorization_decisions "
        "WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id "
        "AND scope_hash = NEW.scope_hash AND decision = 'approved'; "
        "IF persisted_launcher IS NULL OR persisted_launcher <> NEW.launcher_user_id "
        "OR persisted_session <> NEW.launcher_session_id "
        "OR persisted_hash <> NEW.scope_hash OR persisted_expiry <= clock_timestamp() "
        "OR approved_count <> 1 THEN "
        "RAISE EXCEPTION "
        "'campaign run requires one live exact-scope approval for its persisted launcher' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; END $$"
    )


def _acceptance_attempt_guard() -> str:
    return (
        "CREATE OR REPLACE FUNCTION m1d_validate_agent_acceptance_attempt() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE parent_kind text; expected_attempt text; expected_context text; BEGIN "
        "SELECT run_kind, acceptance_attempt_id, acceptance_context_sha256 "
        "INTO parent_kind, expected_attempt, expected_context "
        "FROM campaign_runs WHERE organization_id = NEW.organization_id "
        "AND run_id = NEW.run_id FOR SHARE; "
        "IF parent_kind = 'agent_acceptance' AND ("
        "NEW.attempt_id IS DISTINCT FROM expected_attempt "
        "OR NEW.ordinal <> 0 "
        "OR NEW.case_id <> 'agentforge-hosted-acceptance-v1' "
        "OR NEW.case_content_hash IS DISTINCT FROM expected_context "
        "OR NEW.category IS NOT NULL "
        "OR NEW.severity IS NOT NULL "
        "OR NEW.attack_class IS NOT NULL "
        "OR NEW.owasp_mappings IS NOT NULL "
        "OR NEW.fixture_provenance IS DISTINCT FROM jsonb_build_object("
        "'classification', 'synthetic', "
        "'contains_real_phi', false, "
        "'schema_version', '1', "
        "'source', 'agentforge.live_acceptance') "
        "OR NEW.source_tool IS NOT NULL "
        "OR NEW.source_technique IS NOT NULL) THEN "
        "RAISE EXCEPTION 'agent acceptance requires its exact synthetic singleton attempt' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $$"
    )


def upgrade() -> None:
    op.add_column(
        "campaign_runs",
        sa.Column(
            "run_kind",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'campaign'"),
        ),
    )
    op.add_column(
        "campaign_runs",
        sa.Column("acceptance_configuration_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "campaign_runs",
        sa.Column("acceptance_generation_policy_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "campaign_runs",
        sa.Column("acceptance_context_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "campaign_runs",
        sa.Column("acceptance_attempt_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "campaign_runs",
        sa.Column(
            "acceptance_limits",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.add_column(
        "campaign_runs",
        sa.Column("acceptance_expires_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "campaign_runs",
        sa.Column("acceptance_actor_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "campaign_runs",
        sa.Column(
            "acceptance_provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )

    for column_name, column_type in (
        ("authorization_request_id", sa.String(length=64)),
        ("scope_hash", sa.String(length=64)),
        ("launcher_user_id", sa.String(length=128)),
        ("launcher_session_id", sa.String(length=128)),
    ):
        op.alter_column(
            "campaign_runs",
            column_name,
            existing_type=column_type,
            nullable=True,
        )

    op.create_foreign_key(
        "fk_campaign_run_acceptance_configuration",
        "campaign_runs",
        "hosted_configuration_sets",
        ["organization_id", "acceptance_configuration_sha256"],
        ["organization_id", "configuration_sha256"],
    )
    op.create_foreign_key(
        "fk_campaign_run_acceptance_attempt",
        "campaign_runs",
        "campaign_attempts",
        ["organization_id", "run_id", "acceptance_attempt_id"],
        ["organization_id", "run_id", "attempt_id"],
        deferrable=True,
        initially="DEFERRED",
    )
    op.create_check_constraint(
        "campaign_run_kind",
        "campaign_runs",
        "run_kind IN ('campaign','agent_acceptance')",
    )
    op.create_check_constraint(
        "campaign_run_authority_shape",
        "campaign_runs",
        "(run_kind = 'campaign' "
        "AND authorization_request_id IS NOT NULL "
        "AND scope_hash IS NOT NULL "
        "AND launcher_user_id IS NOT NULL "
        "AND launcher_session_id IS NOT NULL "
        "AND acceptance_configuration_sha256 IS NULL "
        "AND acceptance_generation_policy_sha256 IS NULL "
        "AND acceptance_context_sha256 IS NULL "
        "AND acceptance_attempt_id IS NULL "
        "AND acceptance_limits IS NULL "
        "AND acceptance_expires_at IS NULL "
        "AND acceptance_actor_id IS NULL "
        "AND acceptance_provenance IS NULL) OR "
        "(run_kind = 'agent_acceptance' "
        "AND authorization_request_id IS NULL "
        "AND scope_hash IS NULL "
        "AND launcher_user_id IS NULL "
        "AND launcher_session_id IS NULL "
        "AND acceptance_configuration_sha256 IS NOT NULL "
        "AND acceptance_generation_policy_sha256 IS NOT NULL "
        "AND acceptance_context_sha256 IS NOT NULL "
        "AND acceptance_attempt_id IS NOT NULL "
        "AND acceptance_limits IS NOT NULL "
        "AND acceptance_expires_at IS NOT NULL "
        "AND acceptance_actor_id IS NOT NULL "
        "AND acceptance_provenance IS NOT NULL)",
    )
    op.create_check_constraint(
        "campaign_run_acceptance_identity",
        "campaign_runs",
        "run_kind <> 'agent_acceptance' OR "
        "(run_id LIKE 'AR-%' "
        "AND acceptance_actor_id ~ '^system:[A-Za-z0-9._:-]+$')",
    )
    op.create_check_constraint(
        "campaign_run_acceptance_hashes",
        "campaign_runs",
        "acceptance_configuration_sha256 IS NULL OR "
        "(acceptance_configuration_sha256 ~ '^[0-9a-f]{64}$' "
        "AND acceptance_generation_policy_sha256 ~ '^[0-9a-f]{64}$' "
        "AND acceptance_context_sha256 ~ '^[0-9a-f]{64}$' "
        "AND acceptance_attempt_id ~ '^[0-9a-f]{64}$')",
    )
    op.create_check_constraint(
        "campaign_run_acceptance_provenance",
        "campaign_runs",
        "acceptance_provenance IS NULL OR "
        "(jsonb_typeof(acceptance_provenance) = 'object' "
        "AND acceptance_provenance - "
        "ARRAY['actor_type','schema_version','source'] = '{}'::jsonb "
        "AND acceptance_provenance->>'actor_type' = 'system' "
        "AND acceptance_provenance->>'schema_version' = '1' "
        "AND acceptance_provenance->>'source' = 'agentforge.live_acceptance')",
    )
    op.create_check_constraint(
        "campaign_run_acceptance_limits",
        "campaign_runs",
        "acceptance_limits IS NULL OR "
        "(jsonb_typeof(acceptance_limits) = 'object' "
        "AND acceptance_limits - "
        "ARRAY['schema_version','network_scope','target_call_limit','allowed_roles',"
        "'role_call_caps','role_usd_caps','global_call_cap','global_usd_cap'] = '{}'::jsonb "
        "AND acceptance_limits->>'schema_version' = '1' "
        "AND acceptance_limits->>'network_scope' = 'openrouter_langfuse_only' "
        "AND jsonb_typeof(acceptance_limits->'target_call_limit') = 'number' "
        "AND (acceptance_limits->>'target_call_limit')::numeric = 0 "
        "AND jsonb_typeof(acceptance_limits->'allowed_roles') = 'array' "
        "AND jsonb_array_length(acceptance_limits->'allowed_roles') = 3 "
        "AND acceptance_limits->'allowed_roles' "
        '@> \'["orchestrator","judge","documentation"]\'::jsonb '
        "AND jsonb_typeof(acceptance_limits->'role_call_caps') = 'object' "
        "AND (acceptance_limits->'role_call_caps') - "
        "ARRAY['orchestrator','judge','documentation'] = '{}'::jsonb "
        "AND jsonb_typeof(acceptance_limits->'role_call_caps'->'orchestrator') = 'number' "
        "AND jsonb_typeof(acceptance_limits->'role_call_caps'->'judge') = 'number' "
        "AND jsonb_typeof(acceptance_limits->'role_call_caps'->'documentation') = 'number' "
        "AND (acceptance_limits->'role_call_caps'->>'orchestrator')::numeric = 1 "
        "AND (acceptance_limits->'role_call_caps'->>'judge')::numeric = 1 "
        "AND (acceptance_limits->'role_call_caps'->>'documentation')::numeric = 1 "
        "AND jsonb_typeof(acceptance_limits->'role_usd_caps') = 'object' "
        "AND (acceptance_limits->'role_usd_caps') - "
        "ARRAY['orchestrator','judge','documentation'] = '{}'::jsonb "
        "AND jsonb_typeof(acceptance_limits->'role_usd_caps'->'orchestrator') = 'string' "
        "AND jsonb_typeof(acceptance_limits->'role_usd_caps'->'judge') = 'string' "
        "AND jsonb_typeof(acceptance_limits->'role_usd_caps'->'documentation') = 'string' "
        "AND acceptance_limits->'role_usd_caps'->>'orchestrator' "
        "~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
        "AND acceptance_limits->'role_usd_caps'->>'judge' "
        "~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
        "AND acceptance_limits->'role_usd_caps'->>'documentation' "
        "~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
        "AND (acceptance_limits->'role_usd_caps'->>'orchestrator')::numeric > 0 "
        "AND (acceptance_limits->'role_usd_caps'->>'orchestrator')::numeric <= 1.5 "
        "AND (acceptance_limits->'role_usd_caps'->>'judge')::numeric > 0 "
        "AND (acceptance_limits->'role_usd_caps'->>'judge')::numeric <= 4 "
        "AND (acceptance_limits->'role_usd_caps'->>'documentation')::numeric > 0 "
        "AND (acceptance_limits->'role_usd_caps'->>'documentation')::numeric <= 1 "
        "AND jsonb_typeof(acceptance_limits->'global_call_cap') = 'number' "
        "AND (acceptance_limits->>'global_call_cap')::numeric = 3 "
        "AND jsonb_typeof(acceptance_limits->'global_usd_cap') = 'string' "
        "AND acceptance_limits->>'global_usd_cap' "
        "~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
        "AND (acceptance_limits->>'global_usd_cap')::numeric > 0 "
        "AND (acceptance_limits->>'global_usd_cap')::numeric <= 10)",
    )
    op.create_index(
        "ix_campaign_runs_acceptance_expiry",
        "campaign_runs",
        ["organization_id", "acceptance_expires_at"],
        postgresql_where=sa.text("run_kind = 'agent_acceptance'"),
    )
    op.execute(_discriminated_campaign_run_trigger())
    op.execute(_acceptance_attempt_guard())
    op.execute(
        "CREATE TRIGGER trg_campaign_attempt_agent_acceptance "
        "BEFORE INSERT ON campaign_attempts FOR EACH ROW "
        "EXECUTE FUNCTION m1d_validate_agent_acceptance_attempt()"
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM campaign_runs "
        "WHERE run_kind = 'agent_acceptance') THEN "
        "RAISE EXCEPTION "
        "'cannot downgrade 0020 while immutable agent acceptance lineage exists' "
        "USING ERRCODE = '55000'; END IF; END $$"
    )
    op.execute("DROP TRIGGER trg_campaign_attempt_agent_acceptance ON campaign_attempts")
    op.execute("DROP FUNCTION m1d_validate_agent_acceptance_attempt()")
    op.execute(_legacy_campaign_run_trigger())
    op.drop_index(
        "ix_campaign_runs_acceptance_expiry",
        table_name="campaign_runs",
    )
    for constraint in (
        "campaign_run_acceptance_limits",
        "campaign_run_acceptance_provenance",
        "campaign_run_acceptance_hashes",
        "campaign_run_acceptance_identity",
        "campaign_run_authority_shape",
        "campaign_run_kind",
    ):
        op.drop_constraint(constraint, "campaign_runs", type_="check")
    op.drop_constraint(
        "fk_campaign_run_acceptance_attempt",
        "campaign_runs",
        type_="foreignkey",
    )
    op.drop_constraint(
        "fk_campaign_run_acceptance_configuration",
        "campaign_runs",
        type_="foreignkey",
    )
    for column_name, column_type in (
        ("authorization_request_id", sa.String(length=64)),
        ("scope_hash", sa.String(length=64)),
        ("launcher_user_id", sa.String(length=128)),
        ("launcher_session_id", sa.String(length=128)),
    ):
        op.alter_column(
            "campaign_runs",
            column_name,
            existing_type=column_type,
            nullable=False,
        )
    for column_name in (
        "acceptance_provenance",
        "acceptance_actor_id",
        "acceptance_expires_at",
        "acceptance_limits",
        "acceptance_attempt_id",
        "acceptance_context_sha256",
        "acceptance_generation_policy_sha256",
        "acceptance_configuration_sha256",
        "run_kind",
    ):
        op.drop_column("campaign_runs", column_name)
