"""Database authority for the governed, target-BOUND four-role acceptance run (0022).

0020/0021 authorize the target-free acceptance (agent_acceptance). Governed 0022 adds a third run
kind, governed_acceptance: two-person authorization (campaign-style) + the four-role hosted config +
exactly one bounded target dispatch, so a real reviewed-corpus attack flows through the Policy
Gateway to the target. These tests pin that 0022 is the single head on 0018->0021, applies + round-
trips cleanly, and adds the governed run kind + governed limits without weakening campaign or the
target-free acceptance envelopes.
"""

from __future__ import annotations

import uuid

from alembic.script import ScriptDirectory
from sqlalchemy import Engine, text

import _db


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
