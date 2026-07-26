"""Admit the six supported case categories and record reviewed-workload provenance.

Revision ID: 0025
Revises: 0024
Create Date: 2026-07-26

Two independent problems made the reviewed ``headshot-live-100-v1`` workload inadmissible, and
both had to be fixed in the database as well as at runtime or the two layers would disagree.

First, category. The workload is authored across six categories, but the control plane only ever
accepted three, so every ``state_corruption``, ``denial_of_service`` and
``identity_role_exploitation`` case was rejected the moment an attempt was created. This revision
records the supported six as a CHECK so the database and
``agentforge.case_taxonomy.SUPPORTED_CASE_CATEGORIES`` cannot drift. The MVP coverage FLOOR is a
separate concept, lives only in application code, and is unchanged at three categories.

Second, provenance. ``source_tool``/``source_technique`` describe a genuine security-tool
execution, and the loader was previously writing the producer kind ``hosted_red_team`` into
``source_tool``. That both misreported tool coverage and, for the nine hand-authored seed cases,
left ``source_technique`` populated with no tool at all. Producer lineage now has its own columns
so the two kinds of provenance can never be conflated again:

``source_kind``               how the case was produced (m11_seed / reviewed_full_scan /
                              hosted_red_team) — NOT a security tool
``workload_instance_id``      the reviewed workload instance the case was admitted under
``review_record_sha256``      the immutable review record that approved it
``source_generation_sha256``  the immutable generation record it derives from

All additions are nullable and every CHECK is NULL-tolerant, because legacy attempts predate
reviewed workloads and legitimately carry none of this lineage. What the constraints do forbid is
PARTIAL provenance: a case may not claim review without naming the record that reviewed it.

The agent-acceptance attempt guard from 0020 is re-created here (never edited in place) so a
target-free acceptance attempt also cannot smuggle any of the new provenance fields.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Mirrors agentforge.case_taxonomy.SUPPORTED_CASE_CATEGORIES. Held literally so this revision stays
# a stable historical record; a regression test asserts the two lists remain identical.
_SUPPORTED_CATEGORIES = (
    "prompt_injection",
    "data_exfiltration",
    "tool_misuse",
    "state_corruption",
    "denial_of_service",
    "identity_role_exploitation",
)

# Mirrors agentforge.case_taxonomy.REVIEWED_WORKLOAD_SOURCE_KINDS.
_SOURCE_KINDS = ("m11_seed", "reviewed_full_scan", "hosted_red_team")
_WORKLOAD_INSTANCE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"

# Mirrors the tool_id values in agentforge.security_tools.catalog.SECURITY_TOOL_CATALOG. Only a
# tool the platform can actually execute may be recorded as having produced a case, so
# ``hosted_red_team`` is deliberately absent: it is a producer kind, not a scanner.
_CATALOG_TOOL_IDS = (
    "garak",
    "giskard",
    "headshot-llm-workbench",
    "promptfoo",
    "pyrit",
    "semgrep",
    "zap",
)


def _sql_in_list(values: Sequence[str]) -> str:
    return ",".join(f"'{value}'" for value in values)


def _acceptance_attempt_guard(*, include_workload_provenance: bool) -> str:
    """Return the agent-acceptance attempt guard.

    ``include_workload_provenance`` adds the 0025 requirement that a target-free acceptance
    attempt carries none of the reviewed-workload lineage columns. With it False the function body
    is byte-identical to the 0020 definition, which is what ``downgrade`` restores.
    """

    workload_clause = (
        "OR NEW.source_kind IS NOT NULL "
        "OR NEW.workload_instance_id IS NOT NULL "
        "OR NEW.review_record_sha256 IS NOT NULL "
        "OR NEW.source_generation_sha256 IS NOT NULL "
        if include_workload_provenance
        else ""
    )
    return (
        "CREATE OR REPLACE FUNCTION public.m1d_validate_agent_acceptance_attempt() "
        "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER "
        "SET search_path = pg_catalog, pg_temp AS $$ "
        "DECLARE parent_kind text; expected_attempt text; expected_context text; BEGIN "
        "SELECT run_kind, acceptance_attempt_id, acceptance_context_sha256 "
        "INTO parent_kind, expected_attempt, expected_context "
        "FROM public.campaign_runs WHERE organization_id = NEW.organization_id "
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
        f"OR NEW.source_technique IS NOT NULL {workload_clause}) THEN "
        "RAISE EXCEPTION 'agent acceptance requires its exact synthetic singleton attempt' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $$"
    )


def upgrade() -> None:
    op.add_column(
        "campaign_attempts", sa.Column("source_kind", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "campaign_attempts",
        sa.Column("workload_instance_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "campaign_attempts",
        sa.Column("review_record_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "campaign_attempts",
        sa.Column("source_generation_sha256", sa.String(length=64), nullable=True),
    )

    # Category: NULL (agent-acceptance and legacy rows) or one of the supported six.
    op.create_check_constraint(
        "campaign_attempt_category",
        "campaign_attempts",
        f"category IS NULL OR category IN ({_sql_in_list(_SUPPORTED_CATEGORIES)})",
    )
    # Tool lineage is a complete pair or absent entirely — never half-recorded.
    op.create_check_constraint(
        "campaign_attempt_tool_pair",
        "campaign_attempts",
        "(source_tool IS NULL) = (source_technique IS NULL)",
    )
    # Only a genuine catalog security tool may be named as the producer of a case.
    op.create_check_constraint(
        "campaign_attempt_source_tool_catalog",
        "campaign_attempts",
        f"source_tool IS NULL OR source_tool IN ({_sql_in_list(_CATALOG_TOOL_IDS)})",
    )
    op.create_check_constraint(
        "campaign_attempt_source_kind",
        "campaign_attempts",
        f"source_kind IS NULL OR source_kind IN ({_sql_in_list(_SOURCE_KINDS)})",
    )
    op.create_check_constraint(
        "campaign_attempt_review_record_sha",
        "campaign_attempts",
        "review_record_sha256 IS NULL OR review_record_sha256 ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "campaign_attempt_source_generation_sha",
        "campaign_attempts",
        "source_generation_sha256 IS NULL OR source_generation_sha256 ~ '^[0-9a-f]{64}$'",
    )
    # Tuple integrity: the reviewed-workload lineage is present in full or not at all. Legacy
    # attempts carry none of it (0 non-null) and remain valid.
    op.create_check_constraint(
        "campaign_attempt_workload_lineage",
        "campaign_attempts",
        "num_nonnulls(source_kind, workload_instance_id, review_record_sha256, "
        "source_generation_sha256) IN (0, 4)",
    )
    op.create_check_constraint(
        "campaign_attempt_workload_instance_id",
        "campaign_attempts",
        f"workload_instance_id IS NULL OR workload_instance_id ~ '{_WORKLOAD_INSTANCE_ID_PATTERN}'",
    )
    # A reviewed-workload claim is meaningful only on a fully described immutable case.
    op.create_check_constraint(
        "campaign_attempt_workload_case_metadata",
        "campaign_attempts",
        "source_kind IS NULL OR (case_content_hash IS NOT NULL AND category IS NOT NULL "
        "AND severity IS NOT NULL AND attack_class IS NOT NULL AND owasp_mappings IS NOT NULL "
        "AND fixture_provenance IS NOT NULL)",
    )
    # The current reviewed_full_scan members are exactly the five hash-joined security-tool
    # candidates. Hand-authored seeds and hosted Red Team variants must never borrow that lineage.
    # Legacy attempts with no source_kind may still carry their pre-0025 tool pair.
    op.create_check_constraint(
        "campaign_attempt_workload_tool_consistency",
        "campaign_attempts",
        "source_kind IS NULL OR "
        "(source_kind = 'reviewed_full_scan' AND source_tool IS NOT NULL) OR "
        "(source_kind IN ('m11_seed','hosted_red_team') AND source_tool IS NULL)",
    )
    op.create_index(
        "ix_campaign_attempts_source_kind",
        "campaign_attempts",
        ["organization_id", "source_kind", "created_at"],
    )

    op.execute(_acceptance_attempt_guard(include_workload_provenance=True))


def downgrade() -> None:
    # Restore the 0020 guard body exactly, then remove only what 0025 added.
    op.execute(_acceptance_attempt_guard(include_workload_provenance=False))

    op.drop_index("ix_campaign_attempts_source_kind", table_name="campaign_attempts")
    op.drop_constraint(
        "campaign_attempt_workload_tool_consistency", "campaign_attempts", type_="check"
    )
    op.drop_constraint(
        "campaign_attempt_workload_case_metadata", "campaign_attempts", type_="check"
    )
    op.drop_constraint("campaign_attempt_workload_instance_id", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_workload_lineage", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_source_generation_sha", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_review_record_sha", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_source_kind", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_source_tool_catalog", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_tool_pair", "campaign_attempts", type_="check")
    op.drop_constraint("campaign_attempt_category", "campaign_attempts", type_="check")

    op.drop_column("campaign_attempts", "source_generation_sha256")
    op.drop_column("campaign_attempts", "review_record_sha256")
    op.drop_column("campaign_attempts", "workload_instance_id")
    op.drop_column("campaign_attempts", "source_kind")
