"""Retain the exact provider response for one physical call as bounded, append-only evidence.

Revision ID: 0028
Revises: 0027
Create Date: 2026-07-27

Revision 0027 made the *sent* side of a hosted call provable: an operator can read the exact
package-owned system prompt and the ordered provider messages behind one logical execution.  The
*received* side was still unprovable.  ``provider_call_events`` recorded only measurements — model,
route, tokens, cost, status — so the console could say a physical call happened and what it cost,
but never what the provider actually said.  Reconstructing that after the fact is impossible and
guessing at it would be fabrication, so the bytes have to be kept at the moment they are observed
or not at all.

This expand-only revision adds three nullable/bounded columns to the existing table.  Nothing is
backfilled: rows written before this revision genuinely have no observed response, and they stay
``NULL`` forever rather than acquiring an invented one.

Why the columns are shaped this way:

* ``response_text`` is **nullable**.  ``NULL`` is the honest representation of "no response was
  observed" — a timeout, a transport failure, or a crash-recovered ``outcome_unknown`` row.  It is
  distinct from ``''``, which means the provider genuinely returned an empty body.
* ``response_text`` is **bounded to 65536 bytes** by ``provider_event_response_bounded``.  The
  value is provider-controlled input on the physical hot path: it is written once per network
  attempt, inside the same transaction that settles cost and refreshes the logical projection.  An
  unbounded TEXT column there lets a hostile or malfunctioning upstream drive transaction size,
  WAL volume, and evidence-read latency from outside the trust boundary.  The bound is a ceiling
  on that blast radius, not a display limit.
* Truncation is recorded explicitly in ``response_truncated`` instead of being inferred from the
  length.  An operator reading evidence must be able to tell "this is everything the provider
  said" apart from "this is the first 64 KiB of what the provider said" without knowing the bound
  in force when the row was written.
* ``response_sha256`` digests the stored text — after truncation, never before.  A digest of bytes
  that are not the bytes on the row would be worse than no digest: it would look like integrity.
  ``provider_event_response_digest_paired`` therefore forces text and digest to appear and vanish
  together, so a row can never carry an unverifiable body or a digest with nothing to verify.

Why there is no UPDATE path: ``provider_call_events`` is append-only, enforced by the
``trg_provider_call_events_append_only`` trigger installed in revision 0018.  These columns are
populated by the same single INSERT that records the terminal facts of the physical call.  This
revision deliberately adds no mutation path and disables no trigger — evidence that can be edited
after the fact is not evidence.

Grants are unchanged on purpose.  The columns inherit the table's existing privilege posture, and
whether the authenticated Web service may read them is an authorization question settled at the
API boundary (``org:evidence:read``), not a question this revision may quietly answer.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "provider_call_events"


def upgrade() -> None:
    # Nullable TEXT and a defaulted BOOLEAN: on PostgreSQL 11+ both are catalog-only changes, so
    # the physical hot-path table is not rewritten and no long ACCESS EXCLUSIVE lock is taken.
    op.add_column(_TABLE, sa.Column("response_text", sa.Text(), nullable=True))
    op.add_column(
        _TABLE,
        sa.Column(
            "response_truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(_TABLE, sa.Column("response_sha256", sa.String(length=64), nullable=True))

    op.create_check_constraint(
        "provider_event_response_bounded",
        _TABLE,
        "response_text IS NULL OR octet_length(response_text) <= 65536",
    )
    op.create_check_constraint(
        "provider_event_response_sha256_shape",
        _TABLE,
        "response_sha256 IS NULL OR response_sha256 ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        "provider_event_response_digest_paired",
        _TABLE,
        "(response_text IS NULL) = (response_sha256 IS NULL)",
    )


def downgrade() -> None:
    # Contracting here destroys observed provider evidence that cannot be re-derived from any
    # other row. That is inherent to removing the only place it is stored, and is why the upgrade
    # is expand-only: nothing else in the schema depends on these columns existing.
    for name in (
        "provider_event_response_digest_paired",
        "provider_event_response_sha256_shape",
        "provider_event_response_bounded",
    ):
        op.drop_constraint(name, _TABLE, type_="check")
    op.drop_column(_TABLE, "response_sha256")
    op.drop_column(_TABLE, "response_truncated")
    op.drop_column(_TABLE, "response_text")
