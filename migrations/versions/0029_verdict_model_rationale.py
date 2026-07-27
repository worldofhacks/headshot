"""Keep the evaluator's own stated reason on the verdict it produced.

Revision ID: 0029
Revises: 0028
Create Date: 2026-07-27

The hosted evaluator is *required* by its own output schema to explain itself: ``rationale`` is a
mandatory 1..4000-character member of the assessment, and ``criteria_hits`` names the criteria it
believes fired. Both were discarded. ``_model_verdict`` copied ``criteria_hits`` into the verdict
payload and dropped ``rationale`` entirely, the verdict contract had no member for it, and the
``verdict`` table had a column for neither -- so a served verdict decayed to
``reason_codes = ['calibrated_positive']``.

The operational consequence is the one that matters. An ``EXPLOIT_LIKELY`` at confidence 0.90 is a
claim about a security property of the target, and until now the platform recorded the claim while
throwing away the argument. An operator could not tell a well-grounded call from a weak one without
reading the raw provider response by hand, and nothing could be queried, aggregated, or audited.
That is exactly the failure mode the withheld-enablement decision warned about: a model that
resolves ambiguity toward "unsafe" at high confidence is invisible in the headline rates and only
detectable by reading its reasoning.

The columns are nullable and nothing is backfilled. Verdicts written before this revision genuinely
have no recorded rationale and stay ``NULL`` rather than acquiring an invented one. Rows whose
authority is an oracle, a canary or a human are *expected* to stay ``NULL`` forever: the reason a
deterministic signal fired is the signal itself, not prose, and this column must never become a
place where a model's opinion is attached to a deterministic confirmation.

``rationale`` is bounded at 4000 characters to match the evaluator's own schema bound, so a row can
never carry text the producing contract would have refused. ``criteria_hits`` is JSONB for symmetry
with ``reason_codes`` on the same table.

This revision grants no privileges and adds no mutation path. The ``verdict`` table's existing
append-only posture is unchanged: these columns are written by the same INSERT that records the
verdict, and never updated.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "verdict"


def upgrade() -> None:
    # Two nullable columns: on PostgreSQL 11+ both are catalog-only changes, so the verdict table
    # is not rewritten and no long ACCESS EXCLUSIVE lock is taken.
    op.add_column(_TABLE, sa.Column("rationale", sa.Text(), nullable=True))
    op.add_column(
        _TABLE,
        sa.Column("criteria_hits", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_check_constraint(
        "verdict_rationale_bounded",
        _TABLE,
        "rationale IS NULL OR (char_length(rationale) BETWEEN 1 AND 4000)",
    )
    # A rationale is a MODEL's argument. Attaching one to a verdict whose authority is an oracle,
    # canary or human would misrepresent where the confirmation came from, so the schema refuses
    # it outright rather than relying on every call site to remember.
    op.create_check_constraint(
        "verdict_rationale_is_model_authored",
        _TABLE,
        "rationale IS NULL OR confirmation_source = 'calibrated_model'",
    )


def downgrade() -> None:
    # Contracting destroys recorded evaluator reasoning that cannot be re-derived from any other
    # row once the bounded provider-response evidence ages out. Inherent to removing the only
    # place it is stored, and why the upgrade is expand-only.
    for name in ("verdict_rationale_is_model_authored", "verdict_rationale_bounded"):
        op.drop_constraint(name, _TABLE, type_="check")
    op.drop_column(_TABLE, "criteria_hits")
    op.drop_column(_TABLE, "rationale")
