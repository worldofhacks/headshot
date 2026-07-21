"""0003 coverage view — create the S6 System-of-Record `coverage_metric` VIEW.

A VIEW-only, scope-legal change (ARCHITECTURE.md §9 S6, O3/O7). It adds NO base-table column
and touches NO existing row — it defines a read-only VIEW over the frozen M2 tables
(``attempt_result`` JOIN ``verdict``) that computes coverage from HASH-VERIFIED, NONCE-DEDUPED
verdicts only, NEVER from raw spans (S6). The verdict→attempt_result FK guarantees a verdict
cannot exist without its authoritative content-hashed evidence, so the join can never count an
evidenceless record; COUNT(DISTINCT (campaign_run_id, attempt_id)) collapses a replay-shaped
duplicate to one. `covered` is the S6 sanity gate: ≥2 distinct verified attempts AND ≥1
decisive/oracle verdict (EXPLOIT_CONFIRMED).

The view body lives in ``src/agentforge/observability/coverage_view.sql`` — the DRY source —
and is loaded via ``importlib.resources`` so THIS migration is the single apply path and the
SQL ships in the wheel (see [tool.setuptools.package-data] "agentforge.observability"). The O7
fallback (agentforge.observability.tracing.derive_coverage_fallback) reads this same view.

Because a VIEW is not data, upgrade()/downgrade() are a lossless round-trip with no row
migration: upgrade() creates the view; downgrade() drops it. Nothing in 0001/0002 is touched.

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-21

"""

from __future__ import annotations

from collections.abc import Sequence
from importlib.resources import files

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _coverage_view_sql() -> str:
    """The canonical CREATE VIEW SQL shipped in the observability package (DRY, wheel-safe)."""
    return (
        files("agentforge.observability").joinpath("coverage_view.sql").read_text(encoding="utf-8")
    )


def upgrade() -> None:
    # Create the coverage_metric VIEW from the DRY .sql source (the single apply path).
    op.get_bind().exec_driver_sql(_coverage_view_sql())


def downgrade() -> None:
    # A VIEW carries no data — dropping it is a clean, lossless contraction.
    op.get_bind().exec_driver_sql("DROP VIEW IF EXISTS coverage_metric")
