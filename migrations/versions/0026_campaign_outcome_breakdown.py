"""Record decisive / indeterminate / operational-error counts on the campaign summary.

Revision ID: 0026
Revises: 0025
Create Date: 2026-07-27

``campaign_run_summaries`` could previously say how many attempts ran, how many requests were
made and how many findings were confirmed — but not how many cases were actually *adjudicated*.
That gap matters now that a campaign survives an isolated model failure: a run that completed
with operational errors would otherwise be indistinguishable from a run that evaluated every
case, which is precisely the claim the platform must never make.

Three counts are added, and they partition the verdicts of a completed run:

``decisive_verdict_count``      EXPLOIT_CONFIRMED / EXPLOIT_LIKELY / NO_EXPLOIT_OBSERVED — the
                                Judge reached a security conclusion
``indeterminate_verdict_count`` INDETERMINATE — evidence was adjudicated but inconclusive
``operational_error_count``     ERROR — adjudication itself failed; NOT a security signal

They are computed from the durable ``verdict`` rows inside the same transaction that writes the
summary, so the numbers are a projection of persisted evidence rather than a process-local
counter that a restart would silently reset.

Additive and forward-only. Existing rows get 0 rather than NULL: every summary already written
belongs to a run that predates per-case isolation, and such a run either completed with every
case adjudicated or never produced a summary at all, so zero operational errors is the truthful
backfill. The columns are NOT NULL with a server default so the append-only trigger on this table
never sees an UPDATE.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

_COUNTS = (
    "decisive_verdict_count",
    "indeterminate_verdict_count",
    "operational_error_count",
)


def upgrade() -> None:
    for column in _COUNTS:
        op.add_column(
            "campaign_run_summaries",
            sa.Column(column, sa.Integer(), nullable=False, server_default="0"),
        )
        # A count is never negative; the database enforces that independently of the writer.
        op.create_check_constraint(
            f"campaign_run_summary_{column}_non_negative",
            "campaign_run_summaries",
            f"{column} >= 0",
        )

    # The three counts partition adjudicated cases, so together they can never exceed the
    # attempts the run actually made. This is the invariant that stops a summary from claiming
    # more evaluation than the evidence supports.
    op.create_check_constraint(
        "campaign_run_summary_outcomes_within_attempts",
        "campaign_run_summaries",
        "decisive_verdict_count + indeterminate_verdict_count + operational_error_count "
        "<= attempt_count",
    )


def downgrade() -> None:
    op.drop_constraint(
        "campaign_run_summary_outcomes_within_attempts",
        "campaign_run_summaries",
        type_="check",
    )
    for column in _COUNTS:
        op.drop_constraint(
            f"campaign_run_summary_{column}_non_negative",
            "campaign_run_summaries",
            type_="check",
        )
        op.drop_column("campaign_run_summaries", column)
