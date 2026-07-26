"""Authorize Chutes as a canonical OpenRouter upstream observation.

Revision ID: 0024
Revises: 0023
Create Date: 2026-07-26

The provider-call trigger introduced in 0018 validates the observed OpenRouter endpoint
against the configured upstream. Chutes was later admitted by the hosted configuration
allowlist, but the database trigger still fell through to ``ELSE FALSE``. Successful Chutes
responses were therefore rejected before their terminal event could be persisted, causing the
Runner to fail closed with ``provider event attempt identity mismatch``.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _provider_event_validation(*, include_chutes: bool) -> str:
    chutes = "WHEN 'chutes' THEN NEW.upstream_provider = 'Chutes' " if include_chutes else ""
    return (
        "CREATE OR REPLACE FUNCTION provider_event_validate_attempt_identity() "
        "RETURNS trigger LANGUAGE plpgsql AS $body$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM provider_call_invocations i "
        "WHERE i.organization_id = NEW.organization_id "
        "AND i.invocation_id = NEW.invocation_id "
        "AND i.campaign_attempt_id IS NOT DISTINCT FROM NEW.campaign_attempt_id "
        "AND NEW.finished_at >= i.started_at "
        "AND NEW.duration_ms = "
        "extract(epoch FROM (NEW.finished_at - i.started_at)) * 1000 "
        "AND (NEW.status <> 'succeeded' OR "
        "(NEW.returned_model = i.requested_model AND "
        "CASE split_part(i.configured_upstream, '/', 1) "
        "WHEN 'anthropic' THEN NEW.upstream_provider = 'Anthropic' "
        "WHEN 'together' THEN NEW.upstream_provider = 'Together' "
        "WHEN 'google-vertex' THEN NEW.upstream_provider IN ('Google', 'Google Vertex') "
        "WHEN 'openai' THEN NEW.upstream_provider = 'OpenAI' "
        "WHEN 'atlas-cloud' THEN NEW.upstream_provider = 'AtlasCloud' "
        f"{chutes}"
        "ELSE FALSE END))) THEN "
        "RAISE EXCEPTION 'provider event attempt identity mismatch' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $body$"
    )


def upgrade() -> None:
    op.execute(_provider_event_validation(include_chutes=True))


def downgrade() -> None:
    op.execute(_provider_event_validation(include_chutes=False))
