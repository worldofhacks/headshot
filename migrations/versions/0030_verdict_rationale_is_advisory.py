"""Record the evaluator's assessment on every verdict, not only the ones it decided.

Revision ID: 0030
Revises: 0029
Create Date: 2026-07-27

Revision 0029 added `verdict.rationale` and confined it with
`rationale IS NULL OR confirmation_source = 'calibrated_model'`. The intent was sound — a
deterministic oracle, canary or human confirmation must never carry model prose that reads as the
reason it was confirmed. The implementation drew the line in the wrong place.

The model evaluator runs on EVERY adjudicated case. `reconcile_judge_assessment` receives its
assessment alongside the deterministic verdict and, when an oracle or canary fired, returns the
ground truth and discards the model's reasoning entirely. So the assessment exists for confirmed
exploits too; 0029 simply made it unstorable, and vulnerability reports — which are generated ONLY
from `EXPLOIT_CONFIRMED` — could therefore never carry one.

This revision separates two things 0029 conflated:

* **Who decided.** `confirmation_source` remains the sole statement of authority and is unchanged.
  An oracle-confirmed verdict still reads `confirmation_source = 'oracle'`.
* **What the model said.** `rationale` now means "the evaluator's advisory assessment of this
  attempt", recorded whatever decided the verdict. It is never an authority claim.

The protection that mattered is kept and strengthened at the point where a human actually reads it:
the payload labels the assessment advisory in the data itself, so the marker survives being read as
raw JSON, and the report's `observed_behavior` continues to state the confirming source. What is
dropped is only the storage-level prohibition, which bought a guarantee about a column while
costing the operator the reasoning on precisely the verdicts that matter most.

The bound is untouched. `rationale_bounded` still holds at the evaluator's own 4,000-character
limit, and nothing is backfilled: verdicts written before an assessment was recorded stay NULL
rather than acquiring an invented one.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "verdict"
_CONSTRAINT = "verdict_rationale_is_model_authored"


def upgrade() -> None:
    # Catalog-only: dropping a CHECK takes a brief lock and rewrites nothing.
    op.drop_constraint(_CONSTRAINT, _TABLE, type_="check")


def downgrade() -> None:
    # Restoring the constraint would reject any row recorded under 0030 whose verdict was
    # oracle/canary/human confirmed AND carries an assessment — which is the normal shape after
    # this revision. Clear those first so the contraction cannot fail on real data; the
    # authority of every affected verdict is unchanged because `confirmation_source` is untouched.
    op.execute(
        "UPDATE verdict SET rationale = NULL, criteria_hits = NULL "
        "WHERE rationale IS NOT NULL AND confirmation_source IS DISTINCT FROM 'calibrated_model'"
    )
    op.create_check_constraint(
        _CONSTRAINT,
        _TABLE,
        "rationale IS NULL OR confirmation_source = 'calibrated_model'",
    )
