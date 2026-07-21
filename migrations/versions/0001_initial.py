"""0001 initial — exploit-DB tables + enums + indexes + S3 UNIQUE + per-agent roles/grants.

Creates the full M2 storage surface (ARCHITECTURE.md §6, PRESEARCH.md §5.2/§5.3):

  * the nine Postgres native ENUM types (state machines + taxonomies);
  * the eight business tables (campaign, attack_case, attempt, red_team_staging,
    attempt_result, verdict, finding, regression_case), with tz-aware timestamps;
  * the PRD-OPT-16 indexes on finding(severity, category, target_version) +
    attempt_result(target_version);
  * the S3 replay-defense UNIQUE(campaign_run_id, attempt_id) on attempt_result; and
  * the per-agent DB ROLES + GRANTs, by executing the canonical SQL in
    src/agentforge/storage/roles.sql (loaded via importlib.resources so the migration is
    the single apply path and roles.sql stays the DRY source of the grant matrix).

Roles are created IDEMPOTENTLY inside roles.sql (a DO block guards on pg_roles), because
roles are cluster-global and may already exist from a prior throwaway-DB run.

downgrade() drops the objects (tables, enums; grants vanish with the tables). Cluster-global
roles are intentionally NOT dropped on downgrade — other databases in the same cluster may
rely on them, and re-running 0001 re-converges the grants idempotently.

Revision ID: 0001
Revises:
Create Date: 2026-07-21

"""

from __future__ import annotations

from collections.abc import Sequence
from importlib.resources import files

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# ---------------------------------------------------------------------------
# Enum type definitions. create_type=False on the *column* references below; these ENUM
# objects create/drop the pg types explicitly so ordering is deterministic. The label sets
# are the frozen contract (tests/test_models.py::EXPECTED_ENUMS).
# ---------------------------------------------------------------------------
_CAMPAIGN_STATE = postgresql.ENUM(
    "queued", "running", "complete", "halted", "aborted", name="campaign_state"
)
_ATTACK_CASE_STATE = postgresql.ENUM("draft", "active", "retired", name="attack_case_state")
_ATTACK_CLASS = postgresql.ENUM("boundary", "invariant", "regression", name="attack_class")
_ATTEMPT_STATE = postgresql.ENUM(
    "queued", "running", "success", "fail", "partial", "error", name="attempt_state"
)
_ATTEMPT_TYPED_ERROR = postgresql.ENUM(
    "target_unreachable",
    "budget_exceeded",
    "judge_timeout",
    "rate_limited",
    "adapter_error",
    name="attempt_typed_error",
)
_VERDICT_STATE = postgresql.ENUM(
    "EXPLOIT_CONFIRMED",
    "EXPLOIT_LIKELY",
    "NO_EXPLOIT_OBSERVED",
    "INDETERMINATE",
    "ERROR",
    name="verdict_state",
)
_FINDING_STATE = postgresql.ENUM(
    "candidate",
    "judged",
    "documented",
    "approved",
    "published",
    "remediated",
    "validated",
    "resolved",
    "regressed",
    name="finding_state",
)
_FINDING_SEVERITY = postgresql.ENUM("low", "medium", "high", "critical", name="finding_severity")
_REGRESSION_CASE_STATE = postgresql.ENUM(
    "admitted", "passing", "failing", name="regression_case_state"
)

_ALL_ENUMS = (
    _CAMPAIGN_STATE,
    _ATTACK_CASE_STATE,
    _ATTACK_CLASS,
    _ATTEMPT_STATE,
    _ATTEMPT_TYPED_ERROR,
    _VERDICT_STATE,
    _FINDING_STATE,
    _FINDING_SEVERITY,
    _REGRESSION_CASE_STATE,
)


def _enum_ref(enum: postgresql.ENUM) -> postgresql.ENUM:
    """A column-side reference to an already-created enum (never re-CREATEs the type)."""
    return postgresql.ENUM(name=enum.name, create_type=False)


def upgrade() -> None:
    bind = op.get_bind()

    # 1. Enum types first (tables reference them).
    for enum in _ALL_ENUMS:
        enum.create(bind, checkfirst=True)

    # 2. campaign — queued → running → {complete | halted | aborted}.
    op.create_table(
        "campaign",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("campaign_id", sa.String(length=64), nullable=False),
        sa.Column("state", _enum_ref(_CAMPAIGN_STATE), nullable=False, server_default="queued"),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("campaign_id", name="uq_campaign_campaign_id"),
    )

    # 3. attack_case — draft → active → retired; carries attack_class + owasp_tags(jsonb).
    op.create_table(
        "attack_case",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.String(length=64), nullable=False),
        sa.Column("state", _enum_ref(_ATTACK_CASE_STATE), nullable=False, server_default="draft"),
        sa.Column("attack_class", _enum_ref(_ATTACK_CLASS), nullable=False),
        sa.Column(
            "owasp_tags",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("case_id", name="uq_attack_case_case_id"),
    )

    # 4. attempt — queued → running → {success | fail | partial} | error(typed).
    op.create_table(
        "attempt",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_id", sa.Integer(), nullable=False),
        sa.Column("state", _enum_ref(_ATTEMPT_STATE), nullable=False, server_default="queued"),
        sa.Column("typed_error", _enum_ref(_ATTEMPT_TYPED_ERROR), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["campaign_id"],
            ["campaign.id"],
            name="fk_attempt_campaign_id_campaign",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("attempt_id", name="uq_attempt_attempt_id"),
    )

    # 5. red_team_staging — Red Team INSERT-only staging it cannot read back (S1).
    op.create_table(
        "red_team_staging",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # 6. attempt_result — authoritative, APPEND-ONLY, hashed evidence (D14). S3 UNIQUE pair.
    op.create_table(
        "attempt_result",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("schema_version", sa.String(length=32), nullable=False, server_default="1"),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("campaign_id", sa.String(length=64), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column("target_version", sa.String(length=128), nullable=True),
        sa.Column("attack_attempt", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("request_transcript", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("response_transcript", sa.Text(), nullable=True),
        sa.Column("policy_decision_id", sa.String(length=64), nullable=True),
        sa.Column("executed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("trace_id", sa.String(length=64), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("recorder_identity", sa.String(length=128), nullable=True),
        sa.Column("recorder_version", sa.String(length=64), nullable=True),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("campaign_run_id", "attempt_id", name="uq_attempt_result_run_attempt"),
    )
    op.create_index("ix_attempt_result_target_version", "attempt_result", ["target_version"])

    # 7. verdict — the Judge's enumerated verdict over an attempt_result pair. The
    #    (campaign_run_id, attempt_id) pair is a FK onto attempt_result's UNIQUE pair, so a
    #    verdict can never reference non-existent evidence (referential integrity, §5.3 #6).
    op.create_table(
        "verdict",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("state", _enum_ref(_VERDICT_STATE), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("campaign_run_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["campaign_run_id", "attempt_id"],
            ["attempt_result.campaign_run_id", "attempt_result.attempt_id"],
            name="fk_verdict_run_attempt_attempt_result",
        ),
    )

    # 8. finding — candidate → … → {resolved | regressed}; PRD-OPT-16 indexes.
    op.create_table(
        "finding",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("state", _enum_ref(_FINDING_STATE), nullable=False, server_default="candidate"),
        sa.Column("severity", _enum_ref(_FINDING_SEVERITY), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("target_version", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("finding_id", name="uq_finding_finding_id"),
    )
    op.create_index("ix_finding_severity", "finding", ["severity"])
    op.create_index("ix_finding_category", "finding", ["category"])
    op.create_index("ix_finding_target_version", "finding", ["target_version"])

    # 9. regression_case — admitted → passing → {failing}.
    op.create_table(
        "regression_case",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("regression_case_id", sa.String(length=64), nullable=False),
        sa.Column(
            "state",
            _enum_ref(_REGRESSION_CASE_STATE),
            nullable=False,
            server_default="admitted",
        ),
        sa.Column("finding_id", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["finding.finding_id"],
            name="fk_regression_case_finding_id_finding",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("regression_case_id", name="uq_regression_case_regression_case_id"),
    )

    # 10. Per-agent DB roles + grants — the S1/S2 append-only-by-permission invariant.
    #     roles.sql is the DRY canonical source; the migration is the single apply path.
    _apply_roles_sql()


def _apply_roles_sql() -> None:
    """Execute the canonical per-agent role/grant SQL shipped in the storage package."""
    sql = files("agentforge.storage").joinpath("roles.sql").read_text(encoding="utf-8")
    op.get_bind().exec_driver_sql(sql)


def downgrade() -> None:
    # Drop tables in reverse dependency order (FKs: attempt→campaign, regression_case→finding).
    op.drop_index("ix_finding_target_version", table_name="finding")
    op.drop_index("ix_finding_category", table_name="finding")
    op.drop_index("ix_finding_severity", table_name="finding")
    op.drop_index("ix_attempt_result_target_version", table_name="attempt_result")

    op.drop_table("regression_case")
    op.drop_table("finding")
    op.drop_table("verdict")
    op.drop_table("attempt_result")
    op.drop_table("red_team_staging")
    op.drop_table("attempt")
    op.drop_table("attack_case")
    op.drop_table("campaign")

    bind = op.get_bind()
    for enum in reversed(_ALL_ENUMS):
        enum.drop(bind, checkfirst=True)

    # Cluster-global roles are intentionally left in place (see module docstring).
