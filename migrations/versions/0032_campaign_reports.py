"""One report per campaign run, so a reviewer reads a run rather than a pile of findings.

Revision ID: 0032
Revises: 0031
Create Date: 2026-07-28

Revision 0031 made an unconfirmed finding reviewable by giving it a VulnReport. That report is
per finding, which is correct for the regression lifecycle — admission, reproduction planning and
fix validation are all statements about one vulnerability — but it is the wrong unit for the
question an operator actually asks after a campaign: *what did this run find?* Answering it meant
opening N separate reports and reconstructing the run by hand, with nothing durable that named the
run as a whole.

This revision adds `campaign_reports`: exactly one row per run, listing every finding that run
opened alongside the run's own totals. It does not replace the per-finding report and does not
touch it; `vuln_reports` remains the unit the regression machinery consumes, reachable by drilling
in from a row here.

Three properties are enforced in the schema rather than left to the writer:

* `uq_campaign_report_org_run` — one report per run. Composition is idempotent, so a retried or
  re-entered terminal transition updates nothing and duplicates nothing.
* `ck_campaign_reports_candidate_is_never_published` — a run containing any candidate finding is
  permanently `blocked_pending_human_approval`, mirroring 0031's rule one level up. A run report
  cannot become publishable by aggregating findings that individually could not.
* `ck_campaign_reports_incomplete_run_is_never_published` — a run that aborted or failed is
  likewise blocked. Such a run examined only part of its corpus, and a publishable report would
  present partial coverage as if it were the whole.

The payload is composed purely from durable rows — verdicts, findings and the run summary — so it
carries no narrative the platform invented and recomposing it from unchanged state yields identical
bytes. Nothing is backfilled: runs that ended before this revision have no report and acquire no
retrospective one.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "campaign_reports"


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("organization_id", sa.String(length=64), nullable=False),
        sa.Column("report_id", sa.String(length=80), nullable=False),
        sa.Column("campaign_run_id", sa.String(length=128), nullable=False),
        sa.Column("run_state", sa.String(length=16), nullable=False),
        sa.Column("publication_state", sa.String(length=40), nullable=False),
        sa.Column("candidate_finding_count", sa.Integer(), nullable=False),
        sa.Column("confirmed_finding_count", sa.Integer(), nullable=False),
        sa.Column("contract_payload", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
    )
    op.create_unique_constraint(
        "uq_campaign_report_org_run", _TABLE, ["organization_id", "campaign_run_id"]
    )
    op.create_unique_constraint(
        "uq_campaign_report_org_report", _TABLE, ["organization_id", "report_id"]
    )
    op.create_check_constraint(
        "campaign_report_run_state",
        _TABLE,
        "run_state IN ('complete', 'aborted', 'failed')",
    )
    op.create_check_constraint(
        "campaign_report_publication_state",
        _TABLE,
        "publication_state IN ('draft_unpublished', 'blocked_pending_human_approval')",
    )
    op.create_check_constraint(
        "campaign_report_counts_non_negative",
        _TABLE,
        "candidate_finding_count >= 0 AND confirmed_finding_count >= 0",
    )
    # Aggregation must not launder a candidate into something publishable.
    op.create_check_constraint(
        "candidate_is_never_published",
        _TABLE,
        "candidate_finding_count = 0 OR publication_state = 'blocked_pending_human_approval'",
    )
    # Nor may partial coverage be presented as a finished assessment.
    op.create_check_constraint(
        "incomplete_run_is_never_published",
        _TABLE,
        "run_state = 'complete' OR publication_state = 'blocked_pending_human_approval'",
    )
    # The stored columns and the payload must agree, so a reader of either sees the same run.
    op.create_check_constraint(
        "payload_projection",
        _TABLE,
        "contract_payload->>'report_id' = report_id "
        "AND contract_payload->>'campaign_run_id' = campaign_run_id "
        "AND contract_payload->>'run_state' = run_state "
        "AND contract_payload->>'publication_state' = publication_state",
    )
    op.create_index("ix_campaign_reports_org_created", _TABLE, ["organization_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_campaign_reports_org_created", table_name=_TABLE)
    op.drop_table(_TABLE)
