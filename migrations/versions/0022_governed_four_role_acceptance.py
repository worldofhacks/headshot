"""Add governed, target-BOUND four-role acceptance authority.

Revision ID: 0022
Revises: 0021
Create Date: 2026-07-25

0020/0021 authorize the target-FREE acceptance (``agent_acceptance``: system-provenanced, zero
target calls, quarantined Red Team). Governed 0022 adds a THIRD run kind, ``governed_acceptance``:
a real four-role attack over the EXISTING reviewed/authorized corpus, dispatched through the Policy
Gateway to the live target. It combines the ``campaign`` two-person authorization branch (a live
target dispatch is never system-provenanced) with the four-role agent lineage of the v2 acceptance
guard (Orchestrator -> Red Team -> Judge -> Documentation), and permits exactly the bounded target
dispatch the reviewed seed-replay requires. No unreviewed generation: the dispatched bytes are the
reviewed corpus case (seed-replay), so the corpus-hash authorization invariant holds.

The v1/v2 target-free acceptance envelopes and every ``campaign`` run remain valid and unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GOVERNED = "governed_acceptance"
_GOVERNED_ROLES = ("orchestrator", "red_team", "judge", "documentation")


# --- acceptance_limits: keep v1 + v2 target-free, add v3 governed (target-bound) ---


def _target_free_limits_sql(
    *, version: str, roles: tuple[str, ...], usd_caps: tuple[str, ...]
) -> str:
    cap_operator = "=" if version == "2" else "<="
    role_array = ",".join(f"'{role}'" for role in roles)
    role_json = ",".join(f'"{role}"' for role in roles)
    call_types = " AND ".join(
        f"jsonb_typeof(acceptance_limits->'role_call_caps'->'{role}') = 'number'" for role in roles
    )
    call_values = " AND ".join(
        f"(acceptance_limits->'role_call_caps'->>'{role}')::numeric = 1" for role in roles
    )
    usd_types = " AND ".join(
        f"jsonb_typeof(acceptance_limits->'role_usd_caps'->'{role}') = 'string'" for role in roles
    )
    usd_values = " AND ".join(
        (
            f"acceptance_limits->'role_usd_caps'->>'{role}' "
            "~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
            f"AND (acceptance_limits->'role_usd_caps'->>'{role}')::numeric > 0 "
            f"AND (acceptance_limits->'role_usd_caps'->>'{role}')::numeric {cap_operator} {cap}"
        )
        for role, cap in zip(roles, usd_caps, strict=True)
    )
    return (
        "(acceptance_limits->>'network_scope' = 'openrouter_langfuse_only' "
        "AND (acceptance_limits->>'target_call_limit')::numeric = 0 "
        f"AND acceptance_limits->>'schema_version' = '{version}' "
        f"AND jsonb_array_length(acceptance_limits->'allowed_roles') = {len(roles)} "
        f"AND acceptance_limits->'allowed_roles' @> '[{role_json}]'::jsonb "
        "AND jsonb_typeof(acceptance_limits->'role_call_caps') = 'object' "
        f"AND (acceptance_limits->'role_call_caps') - ARRAY[{role_array}] = '{{}}'::jsonb "
        f"AND {call_types} AND {call_values} "
        "AND jsonb_typeof(acceptance_limits->'role_usd_caps') = 'object' "
        f"AND (acceptance_limits->'role_usd_caps') - ARRAY[{role_array}] = '{{}}'::jsonb "
        f"AND {usd_types} AND {usd_values} "
        "AND jsonb_typeof(acceptance_limits->'global_call_cap') = 'number' "
        f"AND (acceptance_limits->>'global_call_cap')::numeric = {len(roles)} "
        + ("AND (acceptance_limits->>'global_usd_cap')::numeric = 10)" if version == "2" else ")")
    )


def _governed_limits_sql() -> str:
    """v3 governed limits: target-BOUND (target_call_limit=1), four roles, one call each."""
    roles = _GOVERNED_ROLES
    usd_caps = ("1.5", "1", "4", "1")
    role_array = ",".join(f"'{role}'" for role in roles)
    role_json = ",".join(f'"{role}"' for role in roles)
    call_types = " AND ".join(
        f"jsonb_typeof(acceptance_limits->'role_call_caps'->'{role}') = 'number'" for role in roles
    )
    call_values = " AND ".join(
        f"(acceptance_limits->'role_call_caps'->>'{role}')::numeric = 1" for role in roles
    )
    usd_types = " AND ".join(
        f"jsonb_typeof(acceptance_limits->'role_usd_caps'->'{role}') = 'string'" for role in roles
    )
    usd_values = " AND ".join(
        (
            f"acceptance_limits->'role_usd_caps'->>'{role}' "
            "~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
            f"AND (acceptance_limits->'role_usd_caps'->>'{role}')::numeric > 0 "
            f"AND (acceptance_limits->'role_usd_caps'->>'{role}')::numeric = {cap}"
        )
        for role, cap in zip(roles, usd_caps, strict=True)
    )
    return (
        "(acceptance_limits->>'network_scope' = 'policy_gateway_target' "
        "AND jsonb_typeof(acceptance_limits->'target_call_limit') = 'number' "
        "AND (acceptance_limits->>'target_call_limit')::numeric = 1 "
        "AND acceptance_limits->>'schema_version' = '3' "
        f"AND jsonb_array_length(acceptance_limits->'allowed_roles') = {len(roles)} "
        f"AND acceptance_limits->'allowed_roles' @> '[{role_json}]'::jsonb "
        "AND jsonb_typeof(acceptance_limits->'role_call_caps') = 'object' "
        f"AND (acceptance_limits->'role_call_caps') - ARRAY[{role_array}] = '{{}}'::jsonb "
        f"AND {call_types} AND {call_values} "
        "AND jsonb_typeof(acceptance_limits->'role_usd_caps') = 'object' "
        f"AND (acceptance_limits->'role_usd_caps') - ARRAY[{role_array}] = '{{}}'::jsonb "
        f"AND {usd_types} AND {usd_values} "
        "AND jsonb_typeof(acceptance_limits->'global_call_cap') = 'number' "
        f"AND (acceptance_limits->>'global_call_cap')::numeric = {len(roles)} "
        "AND (acceptance_limits->>'global_usd_cap')::numeric = 10)"
    )


def _acceptance_limits_constraint(*, include_governed: bool) -> str:
    v1 = _target_free_limits_sql(
        version="1", roles=("orchestrator", "judge", "documentation"), usd_caps=("1.5", "4", "1")
    )
    v2 = _target_free_limits_sql(
        version="2",
        roles=("orchestrator", "red_team", "judge", "documentation"),
        usd_caps=("1.5", "1", "4", "1"),
    )
    versions = f"({v1} OR {v2})"
    if include_governed:
        versions = f"({v1} OR {v2} OR {_governed_limits_sql()})"
    return (
        "acceptance_limits IS NULL OR "
        "(jsonb_typeof(acceptance_limits) = 'object' "
        "AND acceptance_limits - "
        "ARRAY['schema_version','network_scope','target_call_limit','allowed_roles',"
        "'role_call_caps','role_usd_caps','global_call_cap','global_usd_cap'] = '{}'::jsonb "
        "AND jsonb_typeof(acceptance_limits->'target_call_limit') = 'number' "
        "AND jsonb_typeof(acceptance_limits->'allowed_roles') = 'array' "
        "AND jsonb_typeof(acceptance_limits->'global_usd_cap') = 'string' "
        "AND acceptance_limits->>'global_usd_cap' ~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
        "AND (acceptance_limits->>'global_usd_cap')::numeric > 0 "
        "AND (acceptance_limits->>'global_usd_cap')::numeric <= 10 "
        f"AND {versions})"
    )


# --- authority shape: campaign XOR target-free-acceptance XOR governed (two-person + four-role) ---


def _authority_shape_constraint(*, include_governed: bool) -> str:
    campaign = (
        "(run_kind = 'campaign' "
        "AND authorization_request_id IS NOT NULL AND scope_hash IS NOT NULL "
        "AND launcher_user_id IS NOT NULL AND launcher_session_id IS NOT NULL "
        "AND acceptance_configuration_sha256 IS NULL "
        "AND acceptance_generation_policy_sha256 IS NULL "
        "AND acceptance_context_sha256 IS NULL AND acceptance_attempt_id IS NULL "
        "AND acceptance_limits IS NULL AND acceptance_expires_at IS NULL "
        "AND acceptance_actor_id IS NULL AND acceptance_provenance IS NULL)"
    )
    target_free = (
        "(run_kind = 'agent_acceptance' "
        "AND authorization_request_id IS NULL AND scope_hash IS NULL "
        "AND launcher_user_id IS NULL AND launcher_session_id IS NULL "
        "AND acceptance_configuration_sha256 IS NOT NULL "
        "AND acceptance_generation_policy_sha256 IS NOT NULL "
        "AND acceptance_context_sha256 IS NOT NULL AND acceptance_attempt_id IS NOT NULL "
        "AND acceptance_limits IS NOT NULL AND acceptance_expires_at IS NOT NULL "
        "AND acceptance_actor_id IS NOT NULL AND acceptance_provenance IS NOT NULL)"
    )
    shapes = f"{campaign} OR {target_free}"
    if include_governed:
        # Governed: two-person authorization (campaign-style) AND the four-role hosted config +
        # target-bound limits (acceptance-style). Human-launched, so NO system actor/provenance.
        governed = (
            f"(run_kind = '{_GOVERNED}' "
            "AND authorization_request_id IS NOT NULL AND scope_hash IS NOT NULL "
            "AND launcher_user_id IS NOT NULL AND launcher_session_id IS NOT NULL "
            "AND acceptance_configuration_sha256 IS NOT NULL "
            "AND acceptance_generation_policy_sha256 IS NOT NULL "
            "AND acceptance_limits IS NOT NULL AND acceptance_expires_at IS NOT NULL "
            "AND acceptance_actor_id IS NULL AND acceptance_provenance IS NULL)"
        )
        shapes = f"{campaign} OR {target_free} OR {governed}"
    return shapes


# --- campaign_run trigger: campaign + governed both require two-person approval ---


def _campaign_run_trigger(*, include_governed: bool) -> str:
    governed_branch = (
        f"ELSIF NEW.run_kind = '{_GOVERNED}' THEN "
        "SELECT launcher_user_id, launcher_session_id, scope_hash, expires_at "
        "INTO persisted_launcher, persisted_session, persisted_hash, persisted_expiry "
        "FROM campaign_authorization_requests WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id FOR SHARE; "
        "SELECT count(*) INTO approved_count FROM campaign_authorization_decisions "
        "WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id "
        "AND scope_hash = NEW.scope_hash AND decision = 'approved'; "
        "IF persisted_launcher IS NULL OR persisted_launcher <> NEW.launcher_user_id "
        "OR persisted_session <> NEW.launcher_session_id "
        "OR persisted_hash <> NEW.scope_hash OR persisted_expiry <= clock_timestamp() "
        "OR approved_count <> 1 THEN "
        "RAISE EXCEPTION "
        "'governed acceptance run requires one live exact-scope approval for its launcher' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.acceptance_expires_at IS NULL "
        "OR NEW.acceptance_expires_at <= clock_timestamp() THEN "
        "RAISE EXCEPTION 'governed acceptance authority expired' "
        "USING ERRCODE = '42501'; END IF; "
        "PERFORM 1 FROM hosted_configuration_sets "
        "WHERE organization_id = NEW.organization_id "
        "AND configuration_sha256 = NEW.acceptance_configuration_sha256 FOR SHARE; "
        "IF NOT FOUND THEN "
        "RAISE EXCEPTION 'governed acceptance configuration is unavailable' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; "
        if include_governed
        else ""
    )
    return (
        "CREATE OR REPLACE FUNCTION m1d_validate_campaign_run() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE persisted_launcher text; persisted_session text; persisted_hash text; "
        "persisted_expiry timestamptz; approved_count integer; BEGIN "
        "IF NEW.run_kind = 'campaign' THEN "
        "SELECT launcher_user_id, launcher_session_id, scope_hash, expires_at "
        "INTO persisted_launcher, persisted_session, persisted_hash, persisted_expiry "
        "FROM campaign_authorization_requests WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id FOR SHARE; "
        "SELECT count(*) INTO approved_count FROM campaign_authorization_decisions "
        "WHERE organization_id = NEW.organization_id "
        "AND request_id = NEW.authorization_request_id "
        "AND scope_hash = NEW.scope_hash AND decision = 'approved'; "
        "IF persisted_launcher IS NULL OR persisted_launcher <> NEW.launcher_user_id "
        "OR persisted_session <> NEW.launcher_session_id "
        "OR persisted_hash <> NEW.scope_hash OR persisted_expiry <= clock_timestamp() "
        "OR approved_count <> 1 THEN "
        "RAISE EXCEPTION "
        "'campaign run requires one live exact-scope approval for its persisted launcher' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; "
        "ELSIF NEW.run_kind = 'agent_acceptance' THEN "
        "IF NEW.acceptance_expires_at IS NULL "
        "OR NEW.acceptance_expires_at <= clock_timestamp() THEN "
        "RAISE EXCEPTION 'agent acceptance authority expired' "
        "USING ERRCODE = '42501'; END IF; "
        "PERFORM 1 FROM hosted_configuration_sets "
        "WHERE organization_id = NEW.organization_id "
        "AND configuration_sha256 = NEW.acceptance_configuration_sha256 FOR SHARE; "
        "IF NOT FOUND THEN "
        "RAISE EXCEPTION 'agent acceptance configuration is unavailable' "
        "USING ERRCODE = '42501'; END IF; RETURN NEW; "
        f"{governed_branch}"
        "ELSE RAISE EXCEPTION 'campaign run kind is unavailable' "
        "USING ERRCODE = '23514'; END IF; END $$"
    )


def upgrade() -> None:
    op.drop_constraint("campaign_run_kind", "campaign_runs", type_="check")
    op.create_check_constraint(
        "campaign_run_kind",
        "campaign_runs",
        f"run_kind IN ('campaign','agent_acceptance','{_GOVERNED}')",
    )
    op.drop_constraint("campaign_run_authority_shape", "campaign_runs", type_="check")
    op.create_check_constraint(
        "campaign_run_authority_shape",
        "campaign_runs",
        _authority_shape_constraint(include_governed=True),
    )
    op.drop_constraint("campaign_run_acceptance_limits", "campaign_runs", type_="check")
    op.create_check_constraint(
        "campaign_run_acceptance_limits",
        "campaign_runs",
        _acceptance_limits_constraint(include_governed=True),
    )
    op.execute(_campaign_run_trigger(include_governed=True))


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        f"IF EXISTS (SELECT 1 FROM campaign_runs WHERE run_kind = '{_GOVERNED}') THEN "
        "RAISE EXCEPTION "
        "'cannot downgrade 0022 while immutable governed acceptance lineage exists' "
        "USING ERRCODE = '55000'; END IF; END $$"
    )
    op.execute(_campaign_run_trigger(include_governed=False))
    op.drop_constraint("campaign_run_acceptance_limits", "campaign_runs", type_="check")
    op.create_check_constraint(
        "campaign_run_acceptance_limits",
        "campaign_runs",
        _acceptance_limits_constraint(include_governed=False),
    )
    op.drop_constraint("campaign_run_authority_shape", "campaign_runs", type_="check")
    op.create_check_constraint(
        "campaign_run_authority_shape",
        "campaign_runs",
        _authority_shape_constraint(include_governed=False),
    )
    op.drop_constraint("campaign_run_kind", "campaign_runs", type_="check")
    op.create_check_constraint(
        "campaign_run_kind",
        "campaign_runs",
        "run_kind IN ('campaign','agent_acceptance')",
    )
