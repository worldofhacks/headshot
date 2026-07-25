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


def _insert_governed_run(
    engine: Engine,
    request_id: str,
    scope_hash: str,
    *,
    context_sha: str | None = _CONTEXT_SHA,
    attempt_id: str | None = _ATTEMPT_ID,
    insert_attempt: bool = True,
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
                "limits": json.dumps(_GOVERNED_LIMITS),
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


def test_0022_governed_is_the_only_head() -> None:
    script = ScriptDirectory.from_config(_db.alembic_config(_db.admin_url()))
    assert script.get_heads() == ["0022"]
    assert script.get_revision("0022").down_revision == "0021"


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
