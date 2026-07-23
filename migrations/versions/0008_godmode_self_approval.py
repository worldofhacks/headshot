"""Audited godmode exception for demo campaign self-approval.

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-22

The ordinary operator/approver path remains strict two-person control. A verified godmode
principal may explicitly approve its own demo campaign, and that exception is stored on the
decision row so the database, API, Runner, and audit projection can all revalidate it.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _decision_trigger(*, allow_override: bool) -> str:
    override_guard = (
        "IF NEW.self_approval_override AND NEW.approver_user_id <> persisted_launcher THEN "
        "RAISE EXCEPTION 'self-approval override requires the persisted launcher' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.decision = 'approved' AND NEW.approver_user_id = persisted_launcher "
        "AND NOT NEW.self_approval_override THEN "
        if allow_override
        else "IF NEW.decision = 'approved' AND NEW.approver_user_id = persisted_launcher THEN "
    )
    return (
        "CREATE OR REPLACE FUNCTION m1d_validate_authorization_decision() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE persisted_launcher text; persisted_hash text; persisted_expiry timestamptz; "
        "BEGIN SELECT launcher_user_id, scope_hash, expires_at "
        "INTO persisted_launcher, persisted_hash, persisted_expiry "
        "FROM campaign_authorization_requests WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.request_id FOR SHARE; "
        "IF NOT FOUND OR persisted_hash <> NEW.scope_hash THEN "
        "RAISE EXCEPTION 'authorization request scope is unavailable' "
        "USING ERRCODE = '42501'; END IF; "
        + override_guard
        + "RAISE EXCEPTION 'launcher cannot approve own authorization request' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.decision = 'approved' AND persisted_expiry <= clock_timestamp() THEN "
        "RAISE EXCEPTION 'authorization request expired' USING ERRCODE = '42501'; END IF; "
        "RETURN NEW; END $$"
    )


def upgrade() -> None:
    op.add_column(
        "campaign_authorization_decisions",
        sa.Column(
            "self_approval_override",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.execute(_decision_trigger(allow_override=True))


def downgrade() -> None:
    op.execute(_decision_trigger(allow_override=False))
    op.drop_column("campaign_authorization_decisions", "self_approval_override")
