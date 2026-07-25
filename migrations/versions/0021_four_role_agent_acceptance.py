"""Add a populated-safe four-role hosted-agent acceptance authority.

Revision ID: 0021
Revises: 0020
Create Date: 2026-07-25

The v1 three-role acceptance envelope remains valid for immutable historical and in-flight rows.
New v2 authority adds one bounded Red Team call without changing target authority: target calls
remain zero, each role remains single-call, and the canonical provider lineage stays unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _limits_version_sql(
    *,
    version: str,
    roles: tuple[str, ...],
    usd_caps: tuple[str, ...],
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
            f"AND (acceptance_limits->'role_usd_caps'->>'{role}')::numeric "
            f"{cap_operator} {cap}"
        )
        for role, cap in zip(roles, usd_caps, strict=True)
    )
    return (
        f"(acceptance_limits->>'schema_version' = '{version}' "
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


def _acceptance_limits_constraint(*, include_v2: bool) -> str:
    v1 = _limits_version_sql(
        version="1",
        roles=("orchestrator", "judge", "documentation"),
        usd_caps=("1.5", "4", "1"),
    )
    versions = v1
    if include_v2:
        v2 = _limits_version_sql(
            version="2",
            roles=("orchestrator", "red_team", "judge", "documentation"),
            usd_caps=("1.5", "1", "4", "1"),
        )
        versions = f"({v1} OR {v2})"
    return (
        "acceptance_limits IS NULL OR "
        "(jsonb_typeof(acceptance_limits) = 'object' "
        "AND acceptance_limits - "
        "ARRAY['schema_version','network_scope','target_call_limit','allowed_roles',"
        "'role_call_caps','role_usd_caps','global_call_cap','global_usd_cap'] = '{}'::jsonb "
        "AND acceptance_limits->>'network_scope' = 'openrouter_langfuse_only' "
        "AND jsonb_typeof(acceptance_limits->'target_call_limit') = 'number' "
        "AND (acceptance_limits->>'target_call_limit')::numeric = 0 "
        "AND jsonb_typeof(acceptance_limits->'allowed_roles') = 'array' "
        "AND jsonb_typeof(acceptance_limits->'global_usd_cap') = 'string' "
        "AND acceptance_limits->>'global_usd_cap' ~ '^(0|[1-9][0-9]*)(\\.[0-9]+)?$' "
        "AND (acceptance_limits->>'global_usd_cap')::numeric > 0 "
        "AND (acceptance_limits->>'global_usd_cap')::numeric <= 10 "
        f"AND {versions})"
    )


def _versioned_acceptance_execution_guard() -> str:
    return (
        "CREATE OR REPLACE FUNCTION public.m1d_validate_agent_acceptance_execution() "
        "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER "
        "SET search_path = pg_catalog, pg_temp AS $$ "
        "DECLARE parent_run_kind text; old_parent_run_kind text; expected_attempt text; "
        "acceptance_version text; observed_parent_role text; BEGIN "
        "SELECT run_kind, acceptance_attempt_id, acceptance_limits->>'schema_version' "
        "INTO parent_run_kind, expected_attempt, acceptance_version "
        "FROM public.campaign_runs WHERE organization_id = NEW.organization_id "
        "AND run_id = NEW.campaign_run_id FOR SHARE; "
        "IF TG_OP = 'UPDATE' THEN "
        "SELECT run_kind INTO old_parent_run_kind "
        "FROM public.campaign_runs WHERE organization_id = OLD.organization_id "
        "AND run_id = OLD.campaign_run_id FOR SHARE; "
        "IF (old_parent_run_kind = 'agent_acceptance' "
        "OR parent_run_kind = 'agent_acceptance') AND ("
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
        "RAISE EXCEPTION 'agent acceptance execution identity is immutable' "
        "USING ERRCODE = '55000'; END IF; END IF; "
        "IF parent_run_kind = 'agent_acceptance' THEN "
        "IF acceptance_version = '1' THEN "
        "IF NEW.agent_role NOT IN ('orchestrator','judge','documentation') THEN "
        "RAISE EXCEPTION 'agent acceptance execution is outside its role or attempt authority' "
        "USING ERRCODE = '42501'; END IF; "
        "ELSIF acceptance_version = '2' THEN "
        "IF NEW.agent_role NOT IN ('orchestrator','red_team','judge','documentation') THEN "
        "RAISE EXCEPTION 'agent acceptance execution is outside its role or attempt authority' "
        "USING ERRCODE = '42501'; END IF; "
        "ELSE RAISE EXCEPTION 'agent acceptance limits version is unavailable' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.attempt_id IS DISTINCT FROM expected_attempt THEN "
        "RAISE EXCEPTION 'agent acceptance execution is outside its role or attempt authority' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.agent_role = 'orchestrator' THEN "
        "IF NEW.parent_execution_id IS NOT NULL THEN "
        "RAISE EXCEPTION 'agent acceptance planner must be the lineage root' "
        "USING ERRCODE = '23514'; END IF; "
        "ELSIF NEW.parent_execution_id IS NULL THEN "
        "RAISE EXCEPTION 'agent acceptance child requires its exact parent' "
        "USING ERRCODE = '23514'; "
        "ELSE "
        "SELECT agent_role INTO observed_parent_role FROM public.agent_executions "
        "WHERE organization_id = NEW.organization_id "
        "AND campaign_run_id = NEW.campaign_run_id "
        "AND attempt_id = NEW.attempt_id "
        "AND execution_id = NEW.parent_execution_id; "
        "IF acceptance_version = '1' AND ("
        "(NEW.agent_role = 'judge' "
        "AND observed_parent_role IS DISTINCT FROM 'orchestrator') "
        "OR (NEW.agent_role = 'documentation' "
        "AND observed_parent_role IS DISTINCT FROM 'judge')) THEN "
        "RAISE EXCEPTION 'agent acceptance child requires its exact parent' "
        "USING ERRCODE = '23514'; "
        "ELSIF acceptance_version = '2' AND ("
        "(NEW.agent_role = 'red_team' "
        "AND observed_parent_role IS DISTINCT FROM 'orchestrator') "
        "OR (NEW.agent_role = 'judge' "
        "AND observed_parent_role IS DISTINCT FROM 'red_team') "
        "OR (NEW.agent_role = 'documentation' "
        "AND observed_parent_role IS DISTINCT FROM 'judge')) THEN "
        "RAISE EXCEPTION 'agent acceptance child requires its exact parent' "
        "USING ERRCODE = '23514'; END IF; "
        "END IF; "
        "IF NEW.agent_role = 'judge' THEN "
        "IF NEW.judge_calibration_state IS DISTINCT FROM 'failed' "
        "OR NEW.judge_calibration_id IS NULL THEN "
        "RAISE EXCEPTION 'agent acceptance Judge must remain failed-calibration advisory' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.status = 'succeeded' "
        "AND (NEW.decision_authority IS DISTINCT FROM 'oracle' "
        "OR NEW.oracle_agreement IS NULL) THEN "
        "RAISE EXCEPTION "
        "'agent acceptance Judge requires explicit oracle reconciliation' "
        "USING ERRCODE = '42501'; END IF; "
        "END IF; "
        "END IF; RETURN NEW; END $$"
    )


def _v1_acceptance_execution_guard() -> str:
    return (
        "CREATE OR REPLACE FUNCTION public.m1d_validate_agent_acceptance_execution() "
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
        "IF (old_parent_run_kind = 'agent_acceptance' "
        "OR parent_run_kind = 'agent_acceptance') AND ("
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
        "RAISE EXCEPTION 'agent acceptance execution identity is immutable' "
        "USING ERRCODE = '55000'; END IF; END IF; "
        "IF parent_run_kind = 'agent_acceptance' THEN "
        "IF NEW.agent_role NOT IN ('orchestrator','judge','documentation') "
        "OR NEW.attempt_id IS DISTINCT FROM expected_attempt THEN "
        "RAISE EXCEPTION 'agent acceptance execution is outside its role or attempt authority' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.agent_role = 'orchestrator' THEN "
        "IF NEW.parent_execution_id IS NOT NULL THEN "
        "RAISE EXCEPTION 'agent acceptance planner must be the lineage root' "
        "USING ERRCODE = '23514'; END IF; "
        "ELSIF NEW.parent_execution_id IS NULL THEN "
        "RAISE EXCEPTION 'agent acceptance child requires its exact parent' "
        "USING ERRCODE = '23514'; "
        "ELSE "
        "SELECT agent_role INTO observed_parent_role FROM public.agent_executions "
        "WHERE organization_id = NEW.organization_id "
        "AND campaign_run_id = NEW.campaign_run_id "
        "AND attempt_id = NEW.attempt_id "
        "AND execution_id = NEW.parent_execution_id; "
        "IF (NEW.agent_role = 'judge' "
        "AND observed_parent_role IS DISTINCT FROM 'orchestrator') "
        "OR (NEW.agent_role = 'documentation' "
        "AND observed_parent_role IS DISTINCT FROM 'judge') THEN "
        "RAISE EXCEPTION 'agent acceptance child requires its exact parent' "
        "USING ERRCODE = '23514'; END IF; "
        "END IF; "
        "IF NEW.agent_role = 'judge' THEN "
        "IF NEW.judge_calibration_state IS DISTINCT FROM 'failed' "
        "OR NEW.judge_calibration_id IS NULL THEN "
        "RAISE EXCEPTION 'agent acceptance Judge must remain failed-calibration advisory' "
        "USING ERRCODE = '42501'; END IF; "
        "IF NEW.status = 'succeeded' "
        "AND (NEW.decision_authority IS DISTINCT FROM 'oracle' "
        "OR NEW.oracle_agreement IS NULL) THEN "
        "RAISE EXCEPTION "
        "'agent acceptance Judge requires explicit oracle reconciliation' "
        "USING ERRCODE = '42501'; END IF; "
        "END IF; "
        "END IF; RETURN NEW; END $$"
    )


def upgrade() -> None:
    op.drop_constraint(
        "campaign_run_acceptance_limits",
        "campaign_runs",
        type_="check",
    )
    op.create_check_constraint(
        "campaign_run_acceptance_limits",
        "campaign_runs",
        _acceptance_limits_constraint(include_v2=True),
    )
    op.execute(_versioned_acceptance_execution_guard())
    op.execute(
        "REVOKE ALL ON FUNCTION public.m1d_validate_agent_acceptance_execution() FROM PUBLIC"
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM public.campaign_runs "
        "WHERE run_kind = 'agent_acceptance' "
        "AND acceptance_limits->>'schema_version' = '2') THEN "
        "RAISE EXCEPTION "
        "'cannot downgrade 0021 while immutable four-role acceptance lineage exists' "
        "USING ERRCODE = '55000'; END IF; END $$"
    )
    op.execute(_v1_acceptance_execution_guard())
    op.execute(
        "REVOKE ALL ON FUNCTION public.m1d_validate_agent_acceptance_execution() FROM PUBLIC"
    )
    op.drop_constraint(
        "campaign_run_acceptance_limits",
        "campaign_runs",
        type_="check",
    )
    op.create_check_constraint(
        "campaign_run_acceptance_limits",
        "campaign_runs",
        _acceptance_limits_constraint(include_v2=False),
    )
