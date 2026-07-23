"""Enforce the two-role Clerk model and unconditional two-person authorization.

Revision ID: 0012
Revises: 0011
Create Date: 2026-07-23

The legacy self_approval_override column is retained for expand-only compatibility and
historical audit readability, but new overrides are rejected at the database boundary.
Application authentication accepts only org:operator and org:approver.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _strict_decision_trigger() -> str:
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
        "IF NEW.self_approval_override THEN "
        "RAISE EXCEPTION 'self-approval override is disabled' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.decision = 'approved' AND NEW.approver_user_id = persisted_launcher THEN "
        "RAISE EXCEPTION 'launcher cannot approve own authorization request' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.decision = 'approved' AND persisted_expiry <= clock_timestamp() THEN "
        "RAISE EXCEPTION 'authorization request expired' USING ERRCODE = '42501'; END IF; "
        "RETURN NEW; END $$"
    )


def _legacy_decision_trigger() -> str:
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
        "IF NEW.self_approval_override AND NEW.approver_user_id <> persisted_launcher THEN "
        "RAISE EXCEPTION 'self-approval override requires the persisted launcher' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.decision = 'approved' AND NEW.approver_user_id = persisted_launcher "
        "AND NOT NEW.self_approval_override THEN "
        "RAISE EXCEPTION 'launcher cannot approve own authorization request' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.decision = 'approved' AND persisted_expiry <= clock_timestamp() THEN "
        "RAISE EXCEPTION 'authorization request expired' USING ERRCODE = '42501'; END IF; "
        "RETURN NEW; END $$"
    )


def upgrade() -> None:
    op.execute(_strict_decision_trigger())


def downgrade() -> None:
    op.execute(_legacy_decision_trigger())
