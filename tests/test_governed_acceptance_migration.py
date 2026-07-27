"""Database authority for the governed, target-BOUND four-role acceptance run (0022).

0020/0021 authorize the target-free acceptance (agent_acceptance). Governed 0022 adds a third run
kind, governed_acceptance: two-person authorization (campaign-style) + the four-role hosted config +
exactly one bounded target dispatch, so a real reviewed-corpus attack flows through the Policy
Gateway to the target. These tests pin that 0022 is the single head on 0018->0021, applies + round-
trips cleanly, and adds the governed run kind + governed limits without weakening campaign or the
target-free acceptance envelopes.
"""

from __future__ import annotations

import json
import uuid

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

import _db

_ORG = "org_GovernedAcceptance"
_CONFIG_SHA = "a" * 64
_GEN_POLICY_SHA = "b" * 64
_CONTEXT_SHA = "c" * 64
_ATTEMPT_ID = "d" * 64
_SCOPE_HASH = "e" * 64
_GOVERNED_LIMITS = {
    "schema_version": "3",
    "network_scope": "policy_gateway_target",
    "target_call_limit": 1,
    "allowed_roles": ["orchestrator", "red_team", "judge", "documentation"],
    "role_call_caps": {"orchestrator": 1, "red_team": 1, "judge": 1, "documentation": 1},
    "role_usd_caps": {"orchestrator": "1.5", "red_team": "1", "judge": "4", "documentation": "1"},
    "global_call_cap": 4,
    "global_usd_cap": "10",
}
_FIXTURE = {
    "classification": "synthetic",
    "contains_real_phi": False,
    "schema_version": "1",
    "source": "agentforge.live_acceptance",
}


def _seed_config_and_auth(engine: Engine, suffix: str) -> tuple[str, str]:
    """Seed the hosted config + a live, exact-scope, approved two-person authorization."""
    request_id = f"gov-request-{suffix}"
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO hosted_configuration_sets "
                "(organization_id, configuration_sha256, schema_version, release_sha256, "
                "payload, rationale, actor_user_id, actor_session_id) VALUES "
                "(:org, :cfg, '1', :release, '{}'::jsonb, 'governed acceptance fixture', "
                "'user_AcceptanceOwner', 'sess_AcceptanceOwner')"
            ),
            {"org": _ORG, "cfg": _CONFIG_SHA, "release": uuid.uuid4().hex + uuid.uuid4().hex},
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:req, :org, :scope, '{}'::jsonb, 'user_GovLauncher', 'sess_GovLauncher', "
                "clock_timestamp() + interval '15 minutes')"
            ),
            {"req": request_id, "org": _ORG, "scope": _SCOPE_HASH},
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) VALUES "
                "(:dec, :org, :req, :scope, 'approved', 'user_GovApprover', 'sess_GovApprover')"
            ),
            {"dec": f"gov-decision-{suffix}", "org": _ORG, "req": request_id, "scope": _SCOPE_HASH},
        )
    return request_id, _SCOPE_HASH


_PRODUCTION_LIMITS = {
    "schema_version": "3",
    "network_scope": "policy_gateway_target",
    "target_call_limit": 1,
    "allowed_roles": ["orchestrator", "red_team", "judge", "documentation"],
    "role_call_caps": {"orchestrator": 9, "red_team": 19, "judge": 19, "documentation": 9},
    "role_usd_caps": {
        "orchestrator": "0.75",
        "red_team": "1",
        "judge": "2.50",
        "documentation": "0.50",
    },
    "global_call_cap": 56,
    "global_usd_cap": "5",
}


def _insert_governed_run(
    engine: Engine,
    request_id: str,
    scope_hash: str,
    *,
    context_sha: str | None = _CONTEXT_SHA,
    attempt_id: str | None = _ATTEMPT_ID,
    insert_attempt: bool = True,
    limits: dict | None = None,
) -> str:
    """Insert one governed_acceptance run (+ its reviewed-corpus attempt via the deferred FK)."""
    run_id = f"GOV-{uuid.uuid4().hex[:12]}"
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, run_kind, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id, acceptance_configuration_sha256, "
                "acceptance_generation_policy_sha256, acceptance_context_sha256, "
                "acceptance_attempt_id, acceptance_limits, acceptance_expires_at) VALUES "
                "(:run, :org, 'governed_acceptance', :req, :scope, "
                "'user_GovLauncher', 'sess_GovLauncher', :cfg, :gen, :ctx, :att, "
                "CAST(:limits AS jsonb), clock_timestamp() + interval '15 minutes')"
            ),
            {
                "run": run_id,
                "org": _ORG,
                "req": request_id,
                "scope": scope_hash,
                "cfg": _CONFIG_SHA,
                "gen": _GEN_POLICY_SHA,
                "ctx": context_sha,
                "att": attempt_id,
                "limits": json.dumps(limits if limits is not None else _GOVERNED_LIMITS),
            },
        )
        if insert_attempt and attempt_id is not None:
            connection.execute(
                text(
                    "INSERT INTO campaign_attempts "
                    "(organization_id, run_id, attempt_id, ordinal, case_id, "
                    "case_content_hash, fixture_provenance) VALUES "
                    "(:org, :run, :att, 0, 'AF-M11-PI-001', :ctx, CAST(:fixture AS jsonb))"
                ),
                {
                    "org": _ORG,
                    "run": run_id,
                    "att": attempt_id,
                    "ctx": context_sha or _CONTEXT_SHA,
                    "fixture": json.dumps(_FIXTURE),
                },
            )
    return run_id


_MODELS = {
    "orchestrator": "anthropic/claude-opus-4.8",
    "red_team": "qwen/qwen3.5-397b-a17b",
    "judge": "google/gemini-2.5-pro",
    "documentation": "openai/gpt-5.4",
}


def _insert_governed_execution(
    engine: Engine,
    *,
    run_id: str,
    role: str,
    parent_execution_id: str | None,
    attempt_id: str = _ATTEMPT_ID,
    judge_calibration_id: str | None = None,
    judge_calibration_state: str | None = None,
) -> str:
    """Raw-insert one governed agent_execution to exercise the isolated governed DB guard."""
    execution_id = uuid.uuid4().hex
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, attempt_id, "
                "parent_execution_id, agent_role, provider, model, execution_mode, "
                "configuration_version, input_sha256, trace_id, detail, "
                "configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, judge_calibration_id, "
                "judge_calibration_state) VALUES "
                "(:execution, :org, :run, :attempt, :parent, :role, 'openrouter', "
                ":model, 'hosted_advisory', 1, :input_hash, :trace_id, "
                '\'{"provider_lineage_state":"canonical_physical"}\'::jsonb, '
                ":configuration, :role_configuration, :generation_policy, "
                ":calibration, :calibration_state)"
            ),
            {
                "execution": execution_id,
                "org": _ORG,
                "run": run_id,
                "attempt": attempt_id,
                "parent": parent_execution_id,
                "role": role,
                "model": _MODELS[role],
                "input_hash": "1" * 64,
                "trace_id": uuid.uuid4().hex,
                "configuration": _CONFIG_SHA,
                "role_configuration": "2" * 64,
                "generation_policy": _GEN_POLICY_SHA,
                "calibration": judge_calibration_id,
                "calibration_state": judge_calibration_state,
            },
        )
    return execution_id


def _insert_governed_chain(engine: Engine, run_id: str) -> dict[str, str]:
    """Insert the exact valid four-role governed lineage; return role -> execution_id."""
    orchestrator = _insert_governed_execution(
        engine, run_id=run_id, role="orchestrator", parent_execution_id=None
    )
    red_team = _insert_governed_execution(
        engine, run_id=run_id, role="red_team", parent_execution_id=orchestrator
    )
    judge = _insert_governed_execution(
        engine,
        run_id=run_id,
        role="judge",
        parent_execution_id=red_team,
        judge_calibration_id=f"JC-{'3' * 64}",
        judge_calibration_state="enabled",
    )
    documentation = _insert_governed_execution(
        engine, run_id=run_id, role="documentation", parent_execution_id=judge
    )
    return {
        "orchestrator": orchestrator,
        "red_team": red_team,
        "judge": judge,
        "documentation": documentation,
    }


def _fresh_upgraded(admin_url: str) -> tuple[str, Engine, str]:
    database_name = f"agentforge_governed_row_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    _db.alembic_upgrade(database_url, "head")
    return database_url, _db.build_engine(database_url), database_name


def _constraint_def(engine: Engine, name: str) -> str:
    # Alembic's naming convention prefixes campaign_runs check constraints with ck_campaign_runs_.
    with engine.connect() as connection:
        return connection.execute(
            text(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conname = :name AND conrelid = 'campaign_runs'::regclass"
            ),
            {"name": f"ck_campaign_runs_{name}"},
        ).scalar_one()


def test_governed_migration_chain_has_one_prompt_snapshot_head() -> None:
    script = ScriptDirectory.from_config(_db.alembic_config(_db.admin_url()))
    assert script.get_heads() == ["0026"]
    assert script.get_revision("0026").down_revision == "0025"
    assert script.get_revision("0025").down_revision == "0024"
    assert script.get_revision("0024").down_revision == "0023"
    assert script.get_revision("0023").down_revision == "0022"


def test_0022_adds_governed_run_kind_and_round_trips(admin_url: str) -> None:
    database_name = f"agentforge_governed_acceptance_{uuid.uuid4().hex[:12]}"
    base, _ = _db.split_db(admin_url)
    database_url = f"{base}/{database_name}"
    _db.create_fresh_database(admin_url, database_name)
    engine: Engine | None = None
    try:
        _db.alembic_upgrade(database_url, "head")
        engine = _db.build_engine(database_url)

        # The governed run kind is authorized, alongside campaign + the target-free acceptance.
        kind = _constraint_def(engine, "campaign_run_kind")
        assert "governed_acceptance" in kind
        assert "campaign" in kind and "agent_acceptance" in kind

        # Governed limits are target-BOUND (one policy-gateway dispatch) — never target-free.
        limits = _constraint_def(engine, "campaign_run_acceptance_limits")
        assert "policy_gateway_target" in limits
        assert "'3'" in limits  # v3 governed schema_version
        assert "openrouter_langfuse_only" in limits  # v1/v2 target-free still present

        # Governed authority is two-person (launcher) AND four-role config — not system-provenanced.
        shape = _constraint_def(engine, "campaign_run_authority_shape")
        assert "governed_acceptance" in shape

        # Downgrade retires only the governed additions; campaign + acceptance stay intact.
        _db.alembic_downgrade(database_url, "0021")
        kind_after = _constraint_def(engine, "campaign_run_kind")
        assert "governed_acceptance" not in kind_after
        assert "campaign" in kind_after and "agent_acceptance" in kind_after

        # Round-trip is clean.
        _db.alembic_upgrade(database_url, "head")
        assert "governed_acceptance" in _constraint_def(engine, "campaign_run_kind")
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_valid_governed_row_inserts(admin_url: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, "valid")
        run_id = _insert_governed_run(engine, request_id, scope_hash)
        with engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        "SELECT run_kind, acceptance_context_sha256, acceptance_attempt_id "
                        "FROM campaign_runs WHERE run_id = :run"
                    ),
                    {"run": run_id},
                )
                .mappings()
                .one()
            )
        assert row["run_kind"] == "governed_acceptance"
        assert row["acceptance_context_sha256"] == _CONTEXT_SHA
        assert row["acceptance_attempt_id"] == _ATTEMPT_ID
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


@pytest.mark.parametrize("field", ["context_sha", "attempt_id"])
def test_governed_row_requires_context_and_attempt(admin_url: str, field: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, f"null-{field}")
        kwargs = {field: None, "insert_attempt": False}
        with pytest.raises(DBAPIError):  # authority-shape check rejects a null governed identity
            _insert_governed_run(engine, request_id, scope_hash, **kwargs)
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_downgrade_refuses_while_a_governed_row_exists(admin_url: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, "downgrade")
        _insert_governed_run(engine, request_id, scope_hash)
        with pytest.raises(Exception, match="governed acceptance lineage"):
            _db.alembic_downgrade(database_url, "0021")
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_production_shaped_governed_limits_insert(admin_url: str) -> None:
    # The config-derived envelope accepts the 56-call production budget (item 3), not only the
    # closed 4-call harness budget — the constraint is structural, the budget is derived.
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, "prod-budget")
        run_id = _insert_governed_run(engine, request_id, scope_hash, limits=_PRODUCTION_LIMITS)
        with engine.connect() as connection:
            stored = connection.execute(
                text("SELECT acceptance_limits FROM campaign_runs WHERE run_id = :run"),
                {"run": run_id},
            ).scalar_one()
        assert stored["global_call_cap"] == 56
        assert stored["role_call_caps"]["judge"] == 19
        assert stored["target_call_limit"] == 1
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ({"target_call_limit": 2}, "campaign_run_acceptance_limits"),
        ({"global_call_cap": 100}, "campaign_run_acceptance_limits"),
        ({"network_scope": "openrouter_langfuse_only"}, "campaign_run_acceptance_limits"),
    ],
)
def test_governed_limits_reject_a_relaxed_dispatch_or_over_ceiling_budget(
    admin_url: str, mutation: dict, match: str
) -> None:
    # The one-dispatch invariant + the 56 platform ceiling are ABSOLUTE: a second dispatch, an
    # over-ceiling budget, or a target-free scope are all rejected by the acceptance-limits check.
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, f"bad-{'-'.join(mutation)}")
        bad = {**_PRODUCTION_LIMITS, **mutation}
        with pytest.raises(DBAPIError, match=match):
            _insert_governed_run(engine, request_id, scope_hash, limits=bad)
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_valid_governed_four_role_lineage_inserts(admin_url: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, "chain-ok")
        run_id = _insert_governed_run(engine, request_id, scope_hash)
        chain = _insert_governed_chain(engine, run_id)
        with engine.connect() as connection:
            roles = (
                connection.execute(
                    text(
                        "SELECT agent_role FROM agent_executions "
                        "WHERE campaign_run_id = :run ORDER BY id"
                    ),
                    {"run": run_id},
                )
                .scalars()
                .all()
            )
        assert roles == ["orchestrator", "red_team", "judge", "documentation"]
        assert len(set(chain.values())) == 4
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_governed_execution_guard_refuses_wrong_parent_chain(admin_url: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, "wrong-parent")
        run_id = _insert_governed_run(engine, request_id, scope_hash)
        orchestrator = _insert_governed_execution(
            engine, run_id=run_id, role="orchestrator", parent_execution_id=None
        )
        # Judge parented directly to the orchestrator skips the mandatory Red Team link.
        with pytest.raises(DBAPIError, match="child requires its exact parent"):
            _insert_governed_execution(
                engine, run_id=run_id, role="judge", parent_execution_id=orchestrator
            )
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_governed_execution_guard_refuses_orchestrator_with_a_parent(admin_url: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, "planner-parent")
        run_id = _insert_governed_run(engine, request_id, scope_hash)
        root = _insert_governed_execution(
            engine, run_id=run_id, role="orchestrator", parent_execution_id=None
        )
        with pytest.raises(DBAPIError, match="planner must be the lineage root"):
            _insert_governed_execution(
                engine, run_id=run_id, role="orchestrator", parent_execution_id=root
            )
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_governed_execution_guard_refuses_uncalibrated_judge(admin_url: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, "judge-uncal")
        run_id = _insert_governed_run(engine, request_id, scope_hash)
        orchestrator = _insert_governed_execution(
            engine, run_id=run_id, role="orchestrator", parent_execution_id=None
        )
        red_team = _insert_governed_execution(
            engine, run_id=run_id, role="red_team", parent_execution_id=orchestrator
        )
        # An all-null-calibration Judge is permitted by the global 0017 reconciliation constraint
        # (its first branch), so ONLY the governed guard closes this hole for a governed run.
        with pytest.raises(DBAPIError, match="Judge must be calibration-bound"):
            _insert_governed_execution(
                engine,
                run_id=run_id,
                role="judge",
                parent_execution_id=red_team,
                judge_calibration_id=None,
                judge_calibration_state=None,
            )
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_governed_execution_guard_refuses_foreign_attempt(admin_url: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        request_id, scope_hash = _seed_config_and_auth(engine, "foreign-attempt")
        run_id = _insert_governed_run(engine, request_id, scope_hash)
        with pytest.raises(DBAPIError, match="outside its role or attempt authority"):
            _insert_governed_execution(
                engine,
                run_id=run_id,
                role="orchestrator",
                parent_execution_id=None,
                attempt_id="f" * 64,
            )
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)


def test_governed_guards_dropped_on_downgrade(admin_url: str) -> None:
    database_url, engine, database_name = _fresh_upgraded(admin_url)
    try:
        with engine.connect() as connection:
            present = connection.execute(
                text(
                    "SELECT count(*) FROM pg_proc "
                    "WHERE proname IN ('m1d_validate_governed_acceptance_execution', "
                    "'m1d_validate_governed_acceptance_provider_invocation')"
                )
            ).scalar_one()
        assert present == 2
        _db.alembic_downgrade(database_url, "0021")
        with engine.connect() as connection:
            remaining = connection.execute(
                text(
                    "SELECT count(*) FROM pg_proc "
                    "WHERE proname IN ('m1d_validate_governed_acceptance_execution', "
                    "'m1d_validate_governed_acceptance_provider_invocation')"
                )
            ).scalar_one()
        assert remaining == 0
        _db.alembic_upgrade(database_url, "head")
    finally:
        engine.dispose()
        _db.drop_database(admin_url, database_name)
