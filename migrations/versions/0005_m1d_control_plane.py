"""M1d organization-scoped control-plane persistence.

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-21

The migration is forward-only/expand-safe for existing evidence tables. New workflow,
definition, decision, idempotency, and audit records are append-only by database trigger.
"""

# SQL and PL/pgSQL literals remain readable as complete statements.
# ruff: noqa: E501

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _id_columns() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )


def _actor_columns() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column("actor_user_id", sa.String(length=128), nullable=False),
        sa.Column("actor_session_id", sa.String(length=128), nullable=False),
    )


def _append_only(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER trg_{table}_append_only "
        f"BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW "
        "EXECUTE FUNCTION m1d_reject_append_only_mutation()"
    )


def upgrade() -> None:
    op.execute(
        "CREATE FUNCTION m1d_reject_append_only_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN "
        "RAISE EXCEPTION 'append-only control-plane record cannot be mutated' "
        "USING ERRCODE = '55000'; END $$"
    )

    op.create_table(
        "target_identities",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "target_id", name="pk_target_identities"),
        sa.CheckConstraint("organization_id ~ '^org_[A-Za-z0-9]+$'", name="target_identity_org_id"),
    )

    op.create_table(
        "target_definitions",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        *_id_columns(),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_actor_columns(),
        sa.ForeignKeyConstraint(
            ["organization_id", "target_id"],
            ["target_identities.organization_id", "target_identities.target_id"],
            name="fk_target_definitions_identity",
        ),
        sa.UniqueConstraint(
            "organization_id", "target_id", "version", name="uq_target_definitions_org_id_version"
        ),
        sa.UniqueConstraint(
            "organization_id",
            "target_id",
            "version",
            "content_hash",
            name="uq_target_definitions_org_id_version_hash",
        ),
        sa.CheckConstraint("content_hash ~ '^[0-9a-f]{64}$'", name="target_definition_hash"),
        sa.CheckConstraint(
            "version ~ '^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$'",
            name="target_definition_semver",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name="target_definition_payload_object"
        ),
    )

    op.create_table(
        "target_lifecycle_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        *_id_columns(),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("target_version", sa.String(length=32), nullable=False),
        sa.Column("from_lifecycle", sa.String(length=16), nullable=True),
        sa.Column("to_lifecycle", sa.String(length=16), nullable=False),
        *_actor_columns(),
        sa.ForeignKeyConstraint(
            ["organization_id", "target_id", "target_version"],
            [
                "target_definitions.organization_id",
                "target_definitions.target_id",
                "target_definitions.version",
            ],
            name="fk_target_lifecycle_definition",
        ),
        sa.CheckConstraint(
            "to_lifecycle IN ('draft','validating','ready','disabled','archived')",
            name="target_lifecycle_to_allowed",
        ),
        sa.CheckConstraint(
            "from_lifecycle IS NULL OR from_lifecycle IN ('draft','validating','ready','disabled','archived')",
            name="target_lifecycle_from_allowed",
        ),
    )
    op.create_index(
        "ix_target_lifecycle_latest",
        "target_lifecycle_events",
        ["organization_id", "target_id", "target_version", "id"],
    )

    op.create_table(
        "surface_identities",
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("surface_id", sa.String(length=64), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("organization_id", "surface_id", name="pk_surface_identities"),
        sa.UniqueConstraint(
            "organization_id",
            "surface_id",
            "target_id",
            name="uq_surface_identities_org_surface_target",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "target_id"],
            ["target_identities.organization_id", "target_identities.target_id"],
            name="fk_surface_identities_target",
        ),
    )

    op.create_table(
        "attack_surface_definitions",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        *_id_columns(),
        sa.Column("surface_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("target_version", sa.String(length=32), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        *_actor_columns(),
        sa.ForeignKeyConstraint(
            ["organization_id", "surface_id", "target_id"],
            [
                "surface_identities.organization_id",
                "surface_identities.surface_id",
                "surface_identities.target_id",
            ],
            name="fk_attack_surface_identity",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "target_id", "target_version"],
            [
                "target_definitions.organization_id",
                "target_definitions.target_id",
                "target_definitions.version",
            ],
            name="fk_attack_surface_target_definition",
        ),
        sa.UniqueConstraint(
            "organization_id", "surface_id", "version", name="uq_attack_surface_org_id_version"
        ),
        sa.UniqueConstraint(
            "organization_id",
            "surface_id",
            "version",
            "target_id",
            name="uq_attack_surface_org_id_version_target",
        ),
        sa.CheckConstraint("content_hash ~ '^[0-9a-f]{64}$'", name="attack_surface_hash"),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name="attack_surface_payload_object"
        ),
    )

    op.create_table(
        "surface_state_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        *_id_columns(),
        sa.Column("surface_id", sa.String(length=64), nullable=False),
        sa.Column("surface_version", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("from_enabled", sa.Boolean(), nullable=True),
        sa.Column("to_enabled", sa.Boolean(), nullable=False),
        *_actor_columns(),
        sa.ForeignKeyConstraint(
            ["organization_id", "surface_id", "surface_version", "target_id"],
            [
                "attack_surface_definitions.organization_id",
                "attack_surface_definitions.surface_id",
                "attack_surface_definitions.version",
                "attack_surface_definitions.target_id",
            ],
            name="fk_surface_state_definition",
        ),
    )
    op.create_index(
        "ix_surface_state_latest",
        "surface_state_events",
        ["organization_id", "surface_id", "surface_version", "id"],
    )

    op.create_table(
        "campaign_authorization_requests",
        sa.Column("request_id", sa.String(length=64), primary_key=True),
        *_id_columns(),
        sa.Column("scope_hash", sa.String(length=64), nullable=False),
        sa.Column("scope_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("launcher_user_id", sa.String(length=128), nullable=False),
        sa.Column("launcher_session_id", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "request_id",
            "scope_hash",
            name="uq_campaign_authorization_request_scope",
        ),
        sa.CheckConstraint(
            "scope_hash ~ '^[0-9a-f]{64}$'", name="campaign_authorization_request_hash"
        ),
        sa.CheckConstraint(
            "jsonb_typeof(scope_payload) = 'object'", name="campaign_authorization_scope_object"
        ),
        sa.CheckConstraint(
            "launcher_user_id ~ '^user_[A-Za-z0-9_-]+$'",
            name="campaign_authorization_launcher_user",
        ),
        sa.CheckConstraint(
            "launcher_session_id ~ '^sess_[A-Za-z0-9_-]+$'",
            name="campaign_authorization_launcher_session",
        ),
    )
    op.create_index(
        "ix_campaign_authorization_requests_org_created",
        "campaign_authorization_requests",
        ["organization_id", "created_at"],
    )

    op.create_table(
        "campaign_authorization_decisions",
        sa.Column("decision_id", sa.String(length=64), primary_key=True),
        *_id_columns(),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("scope_hash", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("approver_user_id", sa.String(length=128), nullable=False),
        sa.Column("approver_session_id", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "request_id", "scope_hash"],
            [
                "campaign_authorization_requests.organization_id",
                "campaign_authorization_requests.request_id",
                "campaign_authorization_requests.scope_hash",
            ],
            name="fk_campaign_authorization_decision_request",
        ),
        sa.UniqueConstraint(
            "organization_id", "request_id", name="uq_campaign_authorization_decision_request"
        ),
        sa.CheckConstraint(
            "decision IN ('approved','rejected')", name="campaign_authorization_decision_allowed"
        ),
        sa.CheckConstraint(
            "scope_hash ~ '^[0-9a-f]{64}$'", name="campaign_authorization_decision_hash"
        ),
        sa.CheckConstraint(
            "approver_user_id ~ '^user_[A-Za-z0-9_-]+$'",
            name="campaign_authorization_approver_user",
        ),
        sa.CheckConstraint(
            "approver_session_id ~ '^sess_[A-Za-z0-9_-]+$'",
            name="campaign_authorization_approver_session",
        ),
    )

    op.execute(
        "CREATE FUNCTION m1d_validate_authorization_decision() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE persisted_launcher text; persisted_hash text; persisted_expiry timestamptz; BEGIN "
        "SELECT launcher_user_id, scope_hash, expires_at INTO persisted_launcher, persisted_hash, persisted_expiry "
        "FROM campaign_authorization_requests WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.request_id FOR SHARE; "
        "IF NOT FOUND OR persisted_hash <> NEW.scope_hash THEN "
        "RAISE EXCEPTION 'authorization request scope is unavailable' USING ERRCODE = '42501'; END IF; "
        "IF NEW.decision = 'approved' AND NEW.approver_user_id = persisted_launcher THEN "
        "RAISE EXCEPTION 'launcher cannot approve own authorization request' USING ERRCODE = '42501'; END IF; "
        "IF NEW.decision = 'approved' AND persisted_expiry <= clock_timestamp() THEN "
        "RAISE EXCEPTION 'authorization request expired' USING ERRCODE = '42501'; END IF; "
        "RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER trg_campaign_authorization_decision_validate "
        "BEFORE INSERT ON campaign_authorization_decisions FOR EACH ROW "
        "EXECUTE FUNCTION m1d_validate_authorization_decision()"
    )

    op.create_table(
        "campaign_runs",
        sa.Column("run_id", sa.String(length=64), primary_key=True),
        *_id_columns(),
        sa.Column("authorization_request_id", sa.String(length=64), nullable=False),
        sa.Column("scope_hash", sa.String(length=64), nullable=False),
        sa.Column("launcher_user_id", sa.String(length=128), nullable=False),
        sa.Column("launcher_session_id", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "authorization_request_id", "scope_hash"],
            [
                "campaign_authorization_requests.organization_id",
                "campaign_authorization_requests.request_id",
                "campaign_authorization_requests.scope_hash",
            ],
            name="fk_campaign_run_authorization_request",
        ),
        sa.UniqueConstraint(
            "organization_id", "authorization_request_id", name="uq_campaign_run_authorization_once"
        ),
        sa.UniqueConstraint("organization_id", "run_id", name="uq_campaign_runs_org_run"),
        sa.CheckConstraint("scope_hash ~ '^[0-9a-f]{64}$'", name="campaign_run_scope_hash"),
    )

    op.execute(
        "CREATE FUNCTION m1d_validate_campaign_run() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE persisted_launcher text; persisted_session text; persisted_hash text; "
        "persisted_expiry timestamptz; approved_count integer; BEGIN "
        "SELECT launcher_user_id, launcher_session_id, scope_hash, expires_at "
        "INTO persisted_launcher, persisted_session, persisted_hash, persisted_expiry "
        "FROM campaign_authorization_requests WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id FOR SHARE; "
        "SELECT count(*) INTO approved_count FROM campaign_authorization_decisions "
        "WHERE organization_id = NEW.organization_id AND request_id = NEW.authorization_request_id "
        "AND scope_hash = NEW.scope_hash AND decision = 'approved'; "
        "IF persisted_launcher IS NULL OR persisted_launcher <> NEW.launcher_user_id "
        "OR persisted_session <> NEW.launcher_session_id "
        "OR persisted_hash <> NEW.scope_hash OR persisted_expiry <= clock_timestamp() OR approved_count <> 1 THEN "
        "RAISE EXCEPTION 'campaign run requires one live exact-scope approval for its persisted launcher' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER trg_campaign_run_validate BEFORE INSERT ON campaign_runs FOR EACH ROW "
        "EXECUTE FUNCTION m1d_validate_campaign_run()"
    )

    op.create_table(
        "campaign_run_events",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        *_id_columns(),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("actor_user_id", sa.String(length=128), nullable=True),
        sa.Column("actor_session_id", sa.String(length=128), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id", "run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_campaign_run_event_run",
        ),
        sa.CheckConstraint(
            "state IN ('queued','running','complete','aborted','failed')",
            name="campaign_run_event_state_allowed",
        ),
    )
    op.create_index(
        "ix_campaign_run_events_latest", "campaign_run_events", ["organization_id", "run_id", "id"]
    )

    op.create_table(
        "campaign_attempts",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        *_id_columns(),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.String(length=128), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id", "run_id"],
            ["campaign_runs.organization_id", "campaign_runs.run_id"],
            name="fk_campaign_attempt_run",
        ),
        sa.UniqueConstraint(
            "organization_id", "run_id", "attempt_id", name="uq_campaign_attempt_identity"
        ),
        sa.UniqueConstraint(
            "organization_id", "run_id", "ordinal", name="uq_campaign_attempt_ordinal"
        ),
        sa.CheckConstraint("ordinal >= 0", name="campaign_attempt_ordinal_nonnegative"),
    )

    op.create_table(
        "command_idempotency",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        *_id_columns(),
        sa.Column("actor_user_id", sa.String(length=128), nullable=False),
        sa.Column("command_type", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("response_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.UniqueConstraint(
            "organization_id",
            "actor_user_id",
            "command_type",
            "idempotency_key",
            name="uq_command_idempotency_scope",
        ),
        sa.CheckConstraint(
            "request_hash ~ '^[0-9a-f]{64}$'", name="command_idempotency_request_hash"
        ),
        sa.CheckConstraint(
            "jsonb_typeof(response_payload) = 'object'", name="command_idempotency_response_object"
        ),
    )

    op.create_table(
        "audit_events",
        sa.Column("cursor", sa.BigInteger(), primary_key=True, autoincrement=True),
        *_id_columns(),
        sa.Column("event_type", sa.String(length=96), nullable=False),
        sa.Column("aggregate_type", sa.String(length=64), nullable=False),
        sa.Column("aggregate_id", sa.String(length=128), nullable=False),
        sa.Column("actor_user_id", sa.String(length=128), nullable=True),
        sa.Column("actor_session_id", sa.String(length=128), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint("jsonb_typeof(payload) = 'object'", name="audit_event_payload_object"),
    )
    op.create_index("ix_audit_events_org_cursor", "audit_events", ["organization_id", "cursor"])

    op.create_table(
        "finding_decision_events",
        sa.Column("decision_id", sa.String(length=64), primary_key=True),
        *_id_columns(),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=24), nullable=False),
        sa.Column("actor_user_id", sa.String(length=128), nullable=False),
        sa.Column("actor_session_id", sa.String(length=128), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "decision IN ('approved','rejected','resolved')", name="finding_decision_allowed"
        ),
        sa.CheckConstraint(
            "char_length(rationale) BETWEEN 1 AND 2000",
            name="finding_decision_rationale_length",
        ),
    )
    op.create_index(
        "ix_finding_decision_history",
        "finding_decision_events",
        ["organization_id", "finding_id", "created_at"],
    )

    op.add_column(
        "attempt_result", sa.Column("organization_id", sa.String(length=64), nullable=True)
    )
    op.add_column("attempt_result", sa.Column("surface_id", sa.String(length=64), nullable=True))
    op.add_column(
        "attempt_result", sa.Column("surface_version", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "attempt_result", sa.Column("authorization_scope_hash", sa.String(length=64), nullable=True)
    )
    op.create_index(
        "ix_attempt_result_org_run", "attempt_result", ["organization_id", "campaign_run_id"]
    )
    op.add_column("verdict", sa.Column("organization_id", sa.String(length=64), nullable=True))
    op.create_index("ix_verdict_org_run", "verdict", ["organization_id", "campaign_run_id"])
    op.add_column("finding", sa.Column("organization_id", sa.String(length=64), nullable=True))
    op.create_unique_constraint(
        "uq_finding_org_finding_id",
        "finding",
        ["organization_id", "finding_id"],
    )
    op.create_foreign_key(
        "fk_finding_decision_finding",
        "finding_decision_events",
        "finding",
        ["organization_id", "finding_id"],
        ["organization_id", "finding_id"],
    )
    op.create_index("ix_finding_org_state", "finding", ["organization_id", "state"])

    append_only_tables = (
        "target_identities",
        "target_definitions",
        "target_lifecycle_events",
        "surface_identities",
        "attack_surface_definitions",
        "surface_state_events",
        "campaign_authorization_requests",
        "campaign_authorization_decisions",
        "campaign_runs",
        "campaign_run_events",
        "campaign_attempts",
        "command_idempotency",
        "audit_events",
        "finding_decision_events",
    )
    for table in append_only_tables:
        _append_only(table)

    op.execute(
        "CREATE FUNCTION m1d_cancel_queued_campaign_jobs(p_org text, p_run text) "
        "RETURNS integer LANGUAGE plpgsql SECURITY DEFINER "
        "SET search_path = pg_catalog, public AS $$ DECLARE cancelled integer; BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM public.campaign_runs "
        "WHERE organization_id = p_org AND run_id = p_run) THEN "
        "RAISE EXCEPTION 'campaign run is unavailable' USING ERRCODE = '42501'; END IF; "
        "UPDATE public.jobs SET status = 'cancelled'::public.job_status, "
        "cancelled_at = clock_timestamp(), updated_at = clock_timestamp() "
        "WHERE campaign_run_id = p_run AND status = 'queued'::public.job_status; "
        "GET DIAGNOSTICS cancelled = ROW_COUNT; RETURN cancelled; END $$"
    )
    op.execute("REVOKE ALL ON FUNCTION m1d_cancel_queued_campaign_jobs(text, text) FROM PUBLIC")

    op.execute(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'headshot_web') THEN CREATE ROLE headshot_web NOLOGIN; END IF; "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'headshot_runner') THEN CREATE ROLE headshot_runner NOLOGIN; END IF; "
        "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'headshot_scheduler') THEN CREATE ROLE headshot_scheduler NOLOGIN; END IF; "
        "END $$"
    )
    tables = ", ".join(append_only_tables)
    op.execute(
        f"REVOKE ALL PRIVILEGES ON TABLE {tables} FROM PUBLIC, headshot_redteam, headshot_recorder, headshot_judge"
    )
    op.execute("GRANT USAGE ON SCHEMA public TO headshot_web, headshot_runner, headshot_scheduler")
    op.execute(f"GRANT SELECT ON TABLE {tables} TO headshot_web, headshot_runner")
    op.execute(
        "GRANT INSERT ON TABLE target_identities, target_definitions, target_lifecycle_events, "
        "surface_identities, attack_surface_definitions, surface_state_events, "
        "campaign_authorization_requests, campaign_authorization_decisions, campaign_runs, "
        "campaign_run_events, campaign_attempts, command_idempotency, audit_events, "
        "finding_decision_events TO headshot_web"
    )
    op.execute(
        "GRANT INSERT ON TABLE campaign_run_events, campaign_attempts, audit_events "
        "TO headshot_runner"
    )
    op.execute("GRANT SELECT ON TABLE campaign_runs, campaign_run_events TO headshot_scheduler")
    op.execute("GRANT SELECT, INSERT ON TABLE jobs TO headshot_web, headshot_scheduler")
    op.execute("GRANT SELECT, UPDATE ON TABLE jobs TO headshot_runner")
    op.execute(
        "GRANT EXECUTE ON FUNCTION m1d_cancel_queued_campaign_jobs(text, text) TO headshot_web"
    )
    op.execute(
        "GRANT USAGE, SELECT ON SEQUENCE target_definitions_id_seq, "
        "target_lifecycle_events_id_seq, attack_surface_definitions_id_seq, "
        "surface_state_events_id_seq, campaign_run_events_id_seq, campaign_attempts_id_seq, "
        "command_idempotency_id_seq, audit_events_cursor_seq, jobs_id_seq TO headshot_web"
    )
    op.execute(
        "GRANT USAGE, SELECT ON SEQUENCE campaign_run_events_id_seq, "
        "campaign_attempts_id_seq, audit_events_cursor_seq, jobs_id_seq TO headshot_runner"
    )
    op.execute("GRANT USAGE, SELECT ON SEQUENCE jobs_id_seq TO headshot_scheduler")


def downgrade() -> None:
    op.execute("DROP FUNCTION m1d_cancel_queued_campaign_jobs(text, text)")
    for table in (
        "finding_decision_events",
        "audit_events",
        "command_idempotency",
        "campaign_attempts",
        "campaign_run_events",
        "campaign_runs",
        "campaign_authorization_decisions",
        "campaign_authorization_requests",
        "surface_state_events",
        "attack_surface_definitions",
        "surface_identities",
        "target_lifecycle_events",
        "target_definitions",
        "target_identities",
    ):
        op.drop_table(table)

    op.drop_index("ix_finding_org_state", table_name="finding")
    op.drop_constraint("uq_finding_org_finding_id", "finding", type_="unique")
    op.drop_column("finding", "organization_id")
    op.drop_index("ix_verdict_org_run", table_name="verdict")
    op.drop_column("verdict", "organization_id")
    op.drop_index("ix_attempt_result_org_run", table_name="attempt_result")
    op.drop_column("attempt_result", "authorization_scope_hash")
    op.drop_column("attempt_result", "surface_version")
    op.drop_column("attempt_result", "surface_id")
    op.drop_column("attempt_result", "organization_id")

    op.execute("DROP FUNCTION m1d_validate_campaign_run()")
    op.execute("DROP FUNCTION m1d_validate_authorization_decision()")
    op.execute("DROP FUNCTION m1d_reject_append_only_mutation()")
