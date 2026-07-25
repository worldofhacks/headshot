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
    """v3 governed limits: STRUCTURAL — the four-role shape + the ABSOLUTE one-dispatch invariant.

    target_call_limit=1 and network_scope=policy_gateway_target are pinned here (never derived),
    so a relaxed budget can never relax the dispatch ceiling. The per-role/global call+spend BUDGET
    is config-DERIVED and validated for positivity/shape only (global calls bounded by the 56
    platform ceiling; global spend by the outer <=10 bound); its exact values are matched to the
    staged, content-hashed config by the store. This accepts the closed 4-call harness config AND
    the 56-call production config alike, while the one-dispatch guarantee stays absolute.
    """
    roles = _GOVERNED_ROLES
    role_array = ",".join(f"'{role}'" for role in roles)
    role_json = ",".join(f'"{role}"' for role in roles)
    call_types = " AND ".join(
        f"jsonb_typeof(acceptance_limits->'role_call_caps'->'{role}') = 'number'" for role in roles
    )
    call_values = " AND ".join(
        f"(acceptance_limits->'role_call_caps'->>'{role}')::numeric >= 1" for role in roles
    )
    usd_types = " AND ".join(
        f"jsonb_typeof(acceptance_limits->'role_usd_caps'->'{role}') = 'string'" for role in roles
    )
    usd_values = " AND ".join(
        (
            f"acceptance_limits->'role_usd_caps'->>'{role}' "
            "~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
            f"AND (acceptance_limits->'role_usd_caps'->>'{role}')::numeric > 0"
        )
        for role in roles
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
        f"AND (acceptance_limits->>'global_call_cap')::numeric >= {len(roles)} "
        "AND (acceptance_limits->>'global_call_cap')::numeric <= 56)"
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
            "AND acceptance_context_sha256 IS NOT NULL "
            "AND acceptance_attempt_id IS NOT NULL "
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


# --- governed execution + provider guards: ISOLATED from the agent_acceptance guards ---
#
# The 0020/0021 agent_acceptance guards enforce an ABSOLUTE zero-target-traffic invariant and stay
# untouched here. Governed acceptance gets its OWN guards so each kind's invariant stays absolute
# and separately verifiable: a governed run has its four-role lineage + calibrated independent Judge
# enforced at the DB level, AND its single bounded target dispatch is anchored by the existing
# attempt_result UNIQUE(campaign_run_id, attempt_id) (a governed run has exactly one attempt, so at
# most one recorded dispatch can ever exist). Each guard body is gated on its own run kind, so on a
# governed row the agent_acceptance guard is a no-op and vice versa; on a campaign row both are.


def _governed_execution_guard() -> str:
    """Enforce the four-role lineage + calibrated independent Judge for a governed execution.

    Unlike the target-free acceptance Judge (deliberately failed-calibration advisory), the governed
    Judge is the real calibrated, human-enabled independent model Judge required to construct
    ``HostedFourRoleRuntime`` — so it must be calibration-bound and carry an explicit decision
    authority on success, while the deterministic oracle keeps precedence in composition code.
    """

    return (
        "CREATE OR REPLACE FUNCTION public.m1d_validate_governed_acceptance_execution() "
        "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER "
        "SET search_path = pg_catalog, pg_temp AS $$ "
        "DECLARE parent_run_kind text; old_parent_run_kind text; expected_attempt text; "
        "observed_parent_role text; BEGIN "
        "SELECT run_kind, acceptance_attempt_id INTO parent_run_kind, expected_attempt "
        "FROM public.campaign_runs WHERE organization_id = NEW.organization_id "
        "AND run_id = NEW.campaign_run_id FOR SHARE; "
        "IF TG_OP = 'UPDATE' THEN "
        "SELECT run_kind INTO old_parent_run_kind "
        "FROM public.campaign_runs WHERE organization_id = OLD.organization_id "
        "AND run_id = OLD.campaign_run_id FOR SHARE; "
        f"IF (old_parent_run_kind = '{_GOVERNED}' "
        f"OR parent_run_kind = '{_GOVERNED}') AND ("
        "NEW.id IS DISTINCT FROM OLD.id "
        "OR NEW.execution_id IS DISTINCT FROM OLD.execution_id "
        "OR NEW.organization_id IS DISTINCT FROM OLD.organization_id "
        "OR NEW.campaign_run_id IS DISTINCT FROM OLD.campaign_run_id "
        "OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id "
        "OR NEW.agent_role IS DISTINCT FROM OLD.agent_role "
        "OR NEW.parent_execution_id IS DISTINCT FROM OLD.parent_execution_id "
        "OR NEW.provider IS DISTINCT FROM OLD.provider "
        "OR NEW.model IS DISTINCT FROM OLD.model "
        "OR NEW.execution_mode IS DISTINCT FROM OLD.execution_mode "
        "OR NEW.configuration_version IS DISTINCT FROM OLD.configuration_version "
        "OR NEW.input_sha256 IS DISTINCT FROM OLD.input_sha256 "
        "OR NEW.trace_id IS DISTINCT FROM OLD.trace_id "
        "OR NEW.configuration_set_sha256 IS DISTINCT FROM OLD.configuration_set_sha256 "
        "OR NEW.role_configuration_sha256 IS DISTINCT FROM OLD.role_configuration_sha256 "
        "OR NEW.generation_policy_sha256 IS DISTINCT FROM OLD.generation_policy_sha256 "
        "OR NEW.judge_calibration_id IS DISTINCT FROM OLD.judge_calibration_id "
        "OR NEW.judge_calibration_state IS DISTINCT FROM OLD.judge_calibration_state "
        "OR NEW.currency IS DISTINCT FROM OLD.currency "
        "OR NEW.started_at IS DISTINCT FROM OLD.started_at) THEN "
        "RAISE EXCEPTION 'governed acceptance execution identity is immutable' "
        "USING ERRCODE = '55000'; END IF; END IF; "
        f"IF parent_run_kind = '{_GOVERNED}' THEN "
        "IF NEW.agent_role NOT IN ('orchestrator','red_team','judge','documentation') "
        "OR NEW.attempt_id IS DISTINCT FROM expected_attempt THEN "
        "RAISE EXCEPTION "
        "'governed acceptance execution is outside its role or attempt authority' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.agent_role = 'orchestrator' THEN "
        "IF NEW.parent_execution_id IS NOT NULL THEN "
        "RAISE EXCEPTION 'governed acceptance planner must be the lineage root' "
        "USING ERRCODE = '23514'; END IF; "
        "ELSIF NEW.parent_execution_id IS NULL THEN "
        "RAISE EXCEPTION 'governed acceptance child requires its exact parent' "
        "USING ERRCODE = '23514'; "
        "ELSE "
        "SELECT agent_role INTO observed_parent_role FROM public.agent_executions "
        "WHERE organization_id = NEW.organization_id "
        "AND campaign_run_id = NEW.campaign_run_id "
        "AND attempt_id = NEW.attempt_id "
        "AND execution_id = NEW.parent_execution_id; "
        "IF (NEW.agent_role = 'red_team' "
        "AND observed_parent_role IS DISTINCT FROM 'orchestrator') "
        "OR (NEW.agent_role = 'judge' "
        "AND observed_parent_role IS DISTINCT FROM 'red_team') "
        "OR (NEW.agent_role = 'documentation' "
        "AND observed_parent_role IS DISTINCT FROM 'judge') THEN "
        "RAISE EXCEPTION 'governed acceptance child requires its exact parent' "
        "USING ERRCODE = '23514'; END IF; "
        "END IF; "
        "IF NEW.agent_role = 'judge' THEN "
        "IF NEW.judge_calibration_id IS NULL THEN "
        "RAISE EXCEPTION 'governed acceptance Judge must be calibration-bound' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.status = 'succeeded' AND NEW.decision_authority IS NULL THEN "
        "RAISE EXCEPTION "
        "'governed acceptance Judge requires an explicit decision authority' "
        "USING ERRCODE = '42501'; END IF; "
        "END IF; "
        "END IF; RETURN NEW; END $$"
    )


def _governed_provider_invocation_guard() -> str:
    """Bind a governed provider invocation to the exact identity of its logical execution."""

    return (
        "CREATE OR REPLACE FUNCTION "
        "public.m1d_validate_governed_acceptance_provider_invocation() "
        "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER "
        "SET search_path = pg_catalog, pg_temp AS $$ "
        "DECLARE requested_run_kind text; logical_run_kind text; "
        "logical_run_id text; logical_attempt_id text; logical_parent_id text; "
        "logical_role text; logical_model text; logical_configuration text; "
        "logical_role_configuration text; logical_generation_policy text; BEGIN "
        "SELECT run_kind INTO requested_run_kind FROM public.campaign_runs "
        "WHERE organization_id = NEW.organization_id "
        "AND run_id = NEW.campaign_run_id FOR SHARE; "
        "SELECT r.run_kind, e.campaign_run_id, e.attempt_id, e.parent_execution_id, "
        "e.agent_role, e.model, e.configuration_set_sha256, "
        "e.role_configuration_sha256, e.generation_policy_sha256 "
        "INTO logical_run_kind, logical_run_id, logical_attempt_id, logical_parent_id, "
        "logical_role, logical_model, logical_configuration, "
        "logical_role_configuration, logical_generation_policy "
        "FROM public.agent_executions e JOIN public.campaign_runs r "
        "ON r.organization_id = e.organization_id "
        "AND r.run_id = e.campaign_run_id "
        "WHERE e.organization_id = NEW.organization_id "
        "AND e.execution_id = NEW.logical_execution_id FOR SHARE OF e, r; "
        f"IF requested_run_kind = '{_GOVERNED}' "
        f"OR logical_run_kind = '{_GOVERNED}' THEN "
        f"IF requested_run_kind IS DISTINCT FROM '{_GOVERNED}' "
        f"OR logical_run_kind IS DISTINCT FROM '{_GOVERNED}' "
        "OR NEW.campaign_run_id IS DISTINCT FROM logical_run_id "
        "OR NEW.campaign_attempt_id IS DISTINCT FROM logical_attempt_id "
        "OR NEW.parent_execution_id IS DISTINCT FROM logical_parent_id "
        "OR NEW.agent_role IS DISTINCT FROM logical_role "
        "OR NEW.requested_model IS DISTINCT FROM logical_model "
        "OR NEW.configuration_set_sha256 IS DISTINCT FROM logical_configuration "
        "OR NEW.role_configuration_sha256 IS DISTINCT FROM logical_role_configuration "
        "OR NEW.generation_policy_sha256 IS DISTINCT FROM logical_generation_policy THEN "
        "RAISE EXCEPTION "
        "'governed acceptance provider invocation differs from its logical execution' "
        "USING ERRCODE = '42501'; END IF; END IF; RETURN NEW; END $$"
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
    op.execute(_governed_execution_guard())
    op.execute(
        "REVOKE ALL ON FUNCTION public.m1d_validate_governed_acceptance_execution() FROM PUBLIC"
    )
    op.execute(
        "CREATE TRIGGER trg_governed_acceptance_execution_guard "
        "BEFORE INSERT OR UPDATE ON agent_executions FOR EACH ROW "
        "EXECUTE FUNCTION public.m1d_validate_governed_acceptance_execution()"
    )
    op.execute(_governed_provider_invocation_guard())
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "public.m1d_validate_governed_acceptance_provider_invocation() FROM PUBLIC"
    )
    op.execute(
        "CREATE TRIGGER trg_governed_acceptance_provider_invocation_guard "
        "BEFORE INSERT ON provider_call_invocations FOR EACH ROW "
        "EXECUTE FUNCTION public.m1d_validate_governed_acceptance_provider_invocation()"
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        f"IF EXISTS (SELECT 1 FROM campaign_runs WHERE run_kind = '{_GOVERNED}') THEN "
        "RAISE EXCEPTION "
        "'cannot downgrade 0022 while immutable governed acceptance lineage exists' "
        "USING ERRCODE = '55000'; END IF; END $$"
    )
    op.execute(
        "DROP TRIGGER trg_governed_acceptance_provider_invocation_guard "
        "ON provider_call_invocations"
    )
    op.execute("DROP FUNCTION public.m1d_validate_governed_acceptance_provider_invocation()")
    op.execute("DROP TRIGGER trg_governed_acceptance_execution_guard ON agent_executions")
    op.execute("DROP FUNCTION public.m1d_validate_governed_acceptance_execution()")
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
