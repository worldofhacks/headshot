"""Let an unconfirmed finding be reviewed, without letting it pass as a confirmed one.

Revision ID: 0031
Revises: 0030
Create Date: 2026-07-27

A finding was opened only for `EXPLOIT_CONFIRMED`, and a vulnerability report only for a finding.
`EXPLOIT_CONFIRMED` requires a deterministic oracle or canary hit. No oracle has ever fired, so
across every campaign to date — 20 model-authored findings, including a completed 34/34 run — the
`finding` table stayed empty, the Documentation agent never executed, and `vuln_reports` had zero
rows. The human review loop was not merely unused; it was unreachable. A reviewer was asked to
approve findings they had no artifact to read.

The fix is not to lower the confirmation bar. It is to admit that *reviewing* and *confirming* are
different acts, and that the first must happen before the second. `EXPLOIT_LIKELY` now opens a
finding in the `candidate` state — the first state of the lifecycle, already defined in the enum
and until now never written — and that candidate is documented like any other so a human has
something concrete to read before deciding.

What this revision must therefore guarantee is that a candidate can never be mistaken for, or
silently become, a confirmed finding:

* `vuln_reports.confirmation_status` is NOT NULL and names which kind of report this is. It is a
  stored column rather than a payload key so the database itself can constrain it, and it is also
  projected into `contract_payload` so the marker survives being read as raw JSON, exported, or
  pasted into another document — the same reasoning 0030 applied to the advisory assessment.
* `ck_vuln_reports_candidate_is_never_published` binds that column to `publication_state`: a
  candidate report may only ever be `blocked_pending_human_approval`. It cannot be drafted as
  publishable, and no code path can make it so without failing this constraint.
* `ck_finding_candidate_is_never_published` says the same thing one table up: a finding still in
  `candidate` may not carry `published = true`. Promotion out of `candidate` is a human decision
  recorded through `record_finding_decision`; nothing promotes itself.

Existing rows are backfilled to `confirmed`, which is exact rather than assumed: every report that
exists today was necessarily generated from an `EXPLOIT_CONFIRMED` verdict, because no other path
could produce one. In practice the backfill touches nothing, since the table is empty.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_REPORTS = "vuln_reports"
_FINDING = "finding"
_CANDIDATE_UNPUBLISHED = "ck_vuln_reports_candidate_is_never_published"
_STATUS_VALUES = "ck_vuln_reports_confirmation_status_values"
_STATUS_PROJECTED = "ck_vuln_reports_confirmation_status_projected"
_FINDING_UNPUBLISHED = "ck_finding_candidate_is_never_published"


def upgrade() -> None:
    # Added nullable, backfilled, then made NOT NULL: the three-step form never rewrites the table
    # under an exclusive lock the way a defaulted NOT NULL add would on older servers.
    op.add_column(
        _REPORTS,
        sa.Column("confirmation_status", sa.String(length=32), nullable=True),
    )
    # Exact, not assumed. Before this revision a report could only be produced from an
    # EXPLOIT_CONFIRMED verdict, so every pre-existing row is confirmed by construction.
    op.execute(f"UPDATE {_REPORTS} SET confirmation_status = 'confirmed'")
    op.alter_column(_REPORTS, "confirmation_status", nullable=False)

    op.create_check_constraint(
        _STATUS_VALUES,
        _REPORTS,
        "confirmation_status IN ('confirmed', 'candidate_unconfirmed')",
    )
    # The stored column and the payload must agree, so a reader of either sees the same fact.
    op.create_check_constraint(
        _STATUS_PROJECTED,
        _REPORTS,
        "contract_payload->>'confirmation_status' = confirmation_status",
    )
    # The load-bearing one: a candidate is reviewable, never publishable.
    op.create_check_constraint(
        _CANDIDATE_UNPUBLISHED,
        _REPORTS,
        "confirmation_status = 'confirmed' OR publication_state = 'blocked_pending_human_approval'",
    )
    op.create_check_constraint(
        _FINDING_UNPUBLISHED,
        _FINDING,
        "state <> 'candidate'::finding_state OR published = false",
    )


def downgrade() -> None:
    op.drop_constraint(_FINDING_UNPUBLISHED, _FINDING, type_="check")
    op.drop_constraint(_CANDIDATE_UNPUBLISHED, _REPORTS, type_="check")
    op.drop_constraint(_STATUS_PROJECTED, _REPORTS, type_="check")
    op.drop_constraint(_STATUS_VALUES, _REPORTS, type_="check")
    # Contracting to a schema that cannot express "unconfirmed" must not leave candidate reports
    # behind indistinguishable from confirmed ones. Remove them, and return their findings to the
    # state the pre-0031 code would have left them in: no finding row at all, since only
    # EXPLOIT_CONFIRMED opened one. The verdicts themselves are untouched and remain authoritative,
    # so re-upgrading regenerates the candidates from the same evidence.
    op.execute(f"DELETE FROM {_REPORTS} WHERE confirmation_status = 'candidate_unconfirmed'")
    op.execute(
        "DELETE FROM finding_evidence_links WHERE finding_id IN "
        f"(SELECT finding_id FROM {_FINDING} WHERE state = 'candidate'::finding_state)"
    )
    op.execute(f"DELETE FROM {_FINDING} WHERE state = 'candidate'::finding_state")
    op.drop_column(_REPORTS, "confirmation_status")
