"""Persist the MEASURED consumption trio on the append-only attempt_result evidence row.

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-25

A black-box ``POST /chat`` exposes only the response body, the HTTP status, and OUR OWN timing.
This expand-only migration adds a single JSONB column, ``resource_measurements``, carrying ONLY
the dimensions the platform actually MEASURES for an attempt — the gateway's wall-clock
``elapsed_ms``, the physical ``request_count`` (incl. retries), and the response-body
``response_size``. Target-internal input/output tokens, tool-calls, and target LLM cost are NOT
observable from ``/chat`` and are deliberately NOT modeled here — they are never fabricated onto
the evidence.

The column is part of the hashed D14 field set (folded into ``content_hash`` by the gateway/
recorder), so a tamper of any measured dimension diverges the reread hash and fails closed. It is
additive and nullable — legacy rows stay readable, and ``attempt_result`` remains APPEND-ONLY (no
UPDATE/DELETE grant is added anywhere).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "attempt_result",
        sa.Column(
            "resource_measurements",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("attempt_result", "resource_measurements")
