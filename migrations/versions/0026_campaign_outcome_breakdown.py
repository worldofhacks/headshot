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

Historical rows are BACKFILLED from their own durable verdicts, not defaulted to zero. Defaulting
would assert that every pre-0026 completed run adjudicated nothing decisively, which is false and
worse than saying nothing: a reader cannot tell a genuinely all-indeterminate run from a run whose
counts were never computed. Where the verdicts still exist the true counts are recovered; where a
summary has no verdict rows at all the counts are left NULL, meaning "not available for this
historical run" rather than "zero".

That is why the columns are NULLABLE. New summaries always populate them —
``complete_campaign_job`` computes them in the same transaction that writes the row — and a
NULL-tolerant CHECK enforces that any row carrying counts has them sum to exactly
``attempt_count``. A new summary therefore cannot claim more evaluation than it performed, nor
silently drop an un-adjudicated case. Historical NULL rows are exempt, because their accounting
predates these columns and cannot be reconstructed.

The backfill is a one-time UPDATE against rows that predate the columns. ``campaign_run_summaries``
carries an append-only trigger that refuses every UPDATE, including this one, so the migration
disables that single trigger for the duration of the backfill and re-enables it immediately
afterwards. That is narrow and deliberate: it is the only statement in the platform permitted to
write these columns on an existing row, it runs once, and the append-only guarantee is restored
before the transaction ends. Nothing at runtime can take the same route.

Forward-only and additive otherwise.
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
        op.add_column("campaign_run_summaries", sa.Column(column, sa.Integer(), nullable=True))
        # A count is never negative; the database enforces that independently of the writer.
        # NULL-tolerant, because a historical row legitimately has no count at all.
        op.create_check_constraint(
            f"campaign_run_summary_{column}_non_negative",
            "campaign_run_summaries",
            f"{column} IS NULL OR {column} >= 0",
        )

    # Recover the true counts for every historical summary whose verdicts still exist. Rows with
    # no verdicts keep NULL — "not available", which is honest — instead of 0, which would assert
    # that the run adjudicated nothing.
    #
    # The append-only trigger refuses every UPDATE to this table, so it is suspended for exactly
    # this statement and restored on the next line.
    op.execute(
        "ALTER TABLE campaign_run_summaries DISABLE TRIGGER trg_campaign_run_summaries_append_only"
    )
    op.execute(
        """
        UPDATE campaign_run_summaries AS s
        SET decisive_verdict_count = c.decisive,
            indeterminate_verdict_count = c.indeterminate,
            operational_error_count = c.operational_errors
        FROM (
            SELECT organization_id,
                   campaign_run_id,
                   count(*) FILTER (
                       WHERE state IN
                           ('EXPLOIT_CONFIRMED', 'EXPLOIT_LIKELY', 'NO_EXPLOIT_OBSERVED')
                   ) AS decisive,
                   count(*) FILTER (WHERE state = 'INDETERMINATE') AS indeterminate,
                   count(*) FILTER (WHERE state = 'ERROR') AS operational_errors
            FROM verdict
            GROUP BY organization_id, campaign_run_id
        ) AS c
        WHERE c.organization_id = s.organization_id
          AND c.campaign_run_id = s.run_id
        """
    )
    op.execute(
        "ALTER TABLE campaign_run_summaries ENABLE TRIGGER trg_campaign_run_summaries_append_only"
    )

    # The three counts partition adjudicated cases, so a row that HAS them must account for
    # exactly the attempts it made — no more (claiming more evaluation than evidence supports)
    # and no fewer (silently dropping an un-adjudicated case). Historical rows left NULL by the
    # backfill are exempt: their accounting predates these columns and cannot be reconstructed.
    op.create_check_constraint(
        "campaign_run_summary_outcomes_account_for_attempts",
        "campaign_run_summaries",
        "decisive_verdict_count IS NULL "
        "OR indeterminate_verdict_count IS NULL "
        "OR operational_error_count IS NULL "
        "OR decisive_verdict_count + indeterminate_verdict_count + operational_error_count "
        "= attempt_count",
    )


def downgrade() -> None:
    op.drop_constraint(
        "campaign_run_summary_outcomes_account_for_attempts",
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
