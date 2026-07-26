"""PostgreSQL must enforce the same case taxonomy and provenance rules the runtime does.

Runtime validation alone is not enough: anything that writes ``campaign_attempts`` outside
``ensure_campaign_attempt`` would otherwise be able to record a category the platform does not
support, a producer kind masquerading as a security tool, or a case that claims review without
naming the record that reviewed it. Every rule asserted in
``tests/test_reviewed_workload_provenance.py`` is therefore asserted again here against a real
database, plus the 0024 -> 0025 -> 0024 -> 0025 migration cycle.

Legacy attempts predate reviewed workloads and legitimately carry none of this lineage, so the
NULL-tolerant half of each constraint is asserted as explicitly as the rejecting half.
"""

from __future__ import annotations

import datetime
import json
import uuid

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import DBAPIError

import _db
from agentforge.campaign.corpus import load_live_100_corpus, verified_case_payload
from agentforge.case_taxonomy import (
    REVIEWED_WORKLOAD_SOURCE_KINDS,
    SUPPORTED_CASE_CATEGORIES,
    WORKLOAD_INSTANCE_ID_PATTERN,
)
from agentforge.control_plane import ControlPlaneStore
from agentforge.control_plane.errors import (
    InvalidControlPlaneInput,
    RecordConflictError,
)
from agentforge.security_tools.catalog import SECURITY_TOOL_CATALOG

_ORGANIZATION_ID = "org_ReviewedProvenance"
_SHA = "a" * 64
_REVIEW_SHA = "b" * 64
_GENERATION_SHA = "c" * 64
_LIVE_100_MANIFEST_SHA256 = "07d649d482dd1f59a70e2b7238506e59eacddb8f39b56c419ccc6aab52ca252d"
_FIXTURE = {
    "classification": "synthetic",
    "contains_real_phi": False,
    "schema_version": "1",
    "source": "agentforge.tests",
}
_OWASP = [{"framework": "OWASP LLM", "version": "2025", "id": "LLM01", "name": "Prompt Injection"}]

_NEW_COLUMNS = (
    "source_kind",
    "workload_instance_id",
    "review_record_sha256",
    "source_generation_sha256",
)


def _campaign_run(engine: Engine) -> str:
    """Create a genuine two-person-approved campaign run.

    ``m1d_validate_campaign_run`` requires a live authorization request for the persisted launcher
    plus exactly one approved decision at the same scope hash, so the prerequisites are inserted
    rather than bypassed — these tests must not weaken the two-person control they run beneath.
    """

    run_id = uuid.uuid4().hex
    request_id = uuid.uuid4().hex
    scope_hash = uuid.uuid4().hex + uuid.uuid4().hex
    launcher, session = "user_launcher", "sess_launcher"
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:request_id, :org, :scope_hash, CAST(:scope AS jsonb), :launcher, :session, "
                ":expires)"
            ),
            {
                "request_id": request_id,
                "org": _ORGANIZATION_ID,
                "scope_hash": scope_hash,
                "scope": json.dumps({"schema_version": "1"}),
                "launcher": launcher,
                "session": session,
                "expires": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=3),
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id, self_approval_override) VALUES "
                "(:decision_id, :org, :request_id, :scope_hash, 'approved', :approver, "
                ":approver_session, false)"
            ),
            {
                "decision_id": uuid.uuid4().hex,
                "org": _ORGANIZATION_ID,
                "request_id": request_id,
                "scope_hash": scope_hash,
                # A DIFFERENT principal from the launcher: the two-person rule still holds here.
                "approver": "user_approver",
                "approver_session": "sess_approver",
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, run_kind, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run_id, :org, 'campaign', :request_id, :scope_hash, :launcher, :session)"
            ),
            {
                "run_id": run_id,
                "org": _ORGANIZATION_ID,
                "request_id": request_id,
                "scope_hash": scope_hash,
                "launcher": launcher,
                "session": session,
            },
        )
    return run_id


def _insert_attempt(engine: Engine, run_id: str, *, ordinal: int = 0, **columns) -> None:
    payload = {
        "org": _ORGANIZATION_ID,
        "run_id": run_id,
        "attempt_id": uuid.uuid4().hex + uuid.uuid4().hex[:0].ljust(0, "0"),
        "ordinal": ordinal,
        "case_id": f"AF-TEST-{ordinal:03d}",
        "case_hash": _SHA,
        "category": "prompt_injection",
        "severity": "high",
        "attack_class": "boundary",
        "owasp": json.dumps(_OWASP),
        "fixture": json.dumps(_FIXTURE),
        "source_tool": None,
        "source_technique": None,
        "source_kind": None,
        "workload_instance_id": None,
        "review_record_sha256": None,
        "source_generation_sha256": None,
    }
    payload.update(columns)
    payload["attempt_id"] = uuid.uuid4().hex + uuid.uuid4().hex
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_attempts "
                "(organization_id, run_id, attempt_id, ordinal, case_id, case_content_hash, "
                "category, severity, attack_class, owasp_mappings, fixture_provenance, "
                "source_tool, source_technique, source_kind, workload_instance_id, "
                "review_record_sha256, source_generation_sha256) VALUES "
                "(:org, :run_id, :attempt_id, :ordinal, :case_id, :case_hash, :category, "
                ":severity, :attack_class, CAST(:owasp AS jsonb), CAST(:fixture AS jsonb), "
                ":source_tool, :source_technique, :source_kind, :workload_instance_id, "
                ":review_record_sha256, :source_generation_sha256)"
            ),
            payload,
        )


# --------------------------------------------------------------------------------------
# Schema shape and migration cycle.
# --------------------------------------------------------------------------------------


def test_0025_is_the_single_head() -> None:
    script = ScriptDirectory.from_config(_db.alembic_config(_db.admin_url()))
    assert script.get_heads() == ["0025"]
    assert script.get_revision("0025").down_revision == "0024"


def test_new_provenance_columns_exist(migrated_db: Engine) -> None:
    columns = {column["name"] for column in inspect(migrated_db).get_columns("campaign_attempts")}
    assert set(_NEW_COLUMNS).issubset(columns)


def test_migration_upgrade_downgrade_and_reupgrade(admin_url: str) -> None:
    """0025 must be reversible: downgrade removes only its own additions, re-upgrade restores."""

    dbname = _db.throwaway_db_name() + "_0025"
    _db.create_fresh_database(admin_url, dbname)
    base, _ = _db.split_db(admin_url)
    url = f"{base}/{dbname}"
    engine = None
    try:
        _db.alembic_upgrade(url, "0025")
        engine = _db.build_engine(url)
        columns = {c["name"] for c in inspect(engine).get_columns("campaign_attempts")}
        assert set(_NEW_COLUMNS).issubset(columns)

        _db.alembic_downgrade(url, "0024")
        columns = {c["name"] for c in inspect(engine).get_columns("campaign_attempts")}
        assert not (set(_NEW_COLUMNS) & columns), "downgrade must remove only the 0025 columns"
        # Pre-existing columns survive the downgrade untouched.
        assert {"category", "source_tool", "source_technique"}.issubset(columns)

        _db.alembic_upgrade(url, "0025")
        columns = {c["name"] for c in inspect(engine).get_columns("campaign_attempts")}
        assert set(_NEW_COLUMNS).issubset(columns)
    finally:
        if engine is not None:
            engine.dispose()
        _db.drop_database(admin_url, dbname)


def test_migration_constant_lists_match_the_application() -> None:
    """The literal SQL lists in 0025 must not drift from the modules they mirror.

    0025 holds its category / source-kind / tool-id lists literally so the revision stays a stable
    historical record. That is only safe while this test proves the literals still equal the
    runtime sets they enforce.
    """

    import importlib.util  # noqa: PLC0415 - local: the revision filename is not an identifier
    from pathlib import Path  # noqa: PLC0415

    revision_path = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "0025_reviewed_workload_provenance.py"
    )
    spec = importlib.util.spec_from_file_location("_revision_0025", revision_path)
    assert spec is not None and spec.loader is not None
    revision = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(revision)

    assert set(revision._SUPPORTED_CATEGORIES) == SUPPORTED_CASE_CATEGORIES
    assert set(revision._SOURCE_KINDS) == REVIEWED_WORKLOAD_SOURCE_KINDS
    assert set(revision._CATALOG_TOOL_IDS) == {tool.tool_id for tool in SECURITY_TOOL_CATALOG}
    assert f"^{WORKLOAD_INSTANCE_ID_PATTERN}$" == revision._WORKLOAD_INSTANCE_ID_PATTERN


# --------------------------------------------------------------------------------------
# Category: all six accepted, a seventh rejected.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("category", sorted(SUPPORTED_CASE_CATEGORIES))
def test_every_supported_category_is_accepted(migrated_db: Engine, category: str) -> None:
    run_id = _campaign_run(migrated_db)
    _insert_attempt(migrated_db, run_id, category=category)


def test_an_unknown_category_is_rejected_by_postgres(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(migrated_db, run_id, category="cryptomining")


# --------------------------------------------------------------------------------------
# Tool lineage: complete pair, catalog-only.
# --------------------------------------------------------------------------------------


def test_partial_tool_provenance_is_rejected_by_postgres(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(migrated_db, run_id, source_tool="garak", source_technique=None)
    with pytest.raises(DBAPIError):
        _insert_attempt(migrated_db, run_id, source_tool=None, source_technique="dan.Dan_11_0")


def test_a_non_catalog_source_tool_is_rejected_by_postgres(migrated_db: Engine) -> None:
    """``hosted_red_team`` is a producer kind; it may never be recorded as a tool."""

    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(
            migrated_db,
            run_id,
            source_tool="hosted_red_team",
            source_technique="hosted_red_team",
        )


def test_a_catalog_tool_pair_is_accepted(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    _insert_attempt(migrated_db, run_id, source_tool="pyrit", source_technique="Base64Converter")


@pytest.mark.parametrize("source_kind", ["m11_seed", "hosted_red_team"])
def test_non_tool_source_kind_cannot_borrow_tool_provenance_in_postgres(
    migrated_db: Engine, source_kind: str
) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(
            migrated_db,
            run_id,
            source_tool="garak",
            source_technique="dan.Dan_11_0",
            source_kind=source_kind,
            workload_instance_id="HOSTED-001",
            review_record_sha256=_REVIEW_SHA,
            source_generation_sha256=_GENERATION_SHA,
        )


def test_reviewed_full_scan_requires_tool_provenance_in_postgres(
    migrated_db: Engine,
) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(
            migrated_db,
            run_id,
            source_kind="reviewed_full_scan",
            workload_instance_id="BASE-009",
            review_record_sha256=_REVIEW_SHA,
            source_generation_sha256=_GENERATION_SHA,
        )


# --------------------------------------------------------------------------------------
# Reviewed-workload lineage: all four or none.
# --------------------------------------------------------------------------------------


def test_complete_reviewed_lineage_is_accepted(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    _insert_attempt(
        migrated_db,
        run_id,
        source_kind="hosted_red_team",
        workload_instance_id="HOSTED-042",
        review_record_sha256=_REVIEW_SHA,
        source_generation_sha256=_GENERATION_SHA,
    )


def test_legacy_attempts_without_any_reviewed_lineage_remain_valid(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    _insert_attempt(migrated_db, run_id)


@pytest.mark.parametrize("present", sorted(_NEW_COLUMNS))
def test_partial_reviewed_lineage_is_rejected_by_postgres(
    migrated_db: Engine, present: str
) -> None:
    """Any single field on its own is partial provenance and must fail closed."""

    values = {
        "source_kind": "hosted_red_team",
        "workload_instance_id": "HOSTED-042",
        "review_record_sha256": _REVIEW_SHA,
        "source_generation_sha256": _GENERATION_SHA,
    }
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(migrated_db, run_id, **{present: values[present]})


def test_an_unknown_source_kind_is_rejected_by_postgres(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(
            migrated_db,
            run_id,
            source_kind="autonomous_swarm",
            workload_instance_id="HOSTED-042",
            review_record_sha256=_REVIEW_SHA,
            source_generation_sha256=_GENERATION_SHA,
        )


def test_a_malformed_lineage_hash_is_rejected_by_postgres(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(
            migrated_db,
            run_id,
            source_kind="hosted_red_team",
            workload_instance_id="HOSTED-042",
            review_record_sha256="NOT-A-SHA",
            source_generation_sha256=_GENERATION_SHA,
        )


def test_an_uppercase_lineage_hash_is_rejected_by_postgres(migrated_db: Engine) -> None:
    """Hashes are lowercase hex; accepting mixed case would break content-addressed comparison."""

    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(
            migrated_db,
            run_id,
            source_kind="hosted_red_team",
            workload_instance_id="HOSTED-042",
            review_record_sha256=_REVIEW_SHA.upper(),
            source_generation_sha256=_GENERATION_SHA,
        )


def test_empty_workload_instance_id_is_rejected_by_postgres(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError):
        _insert_attempt(
            migrated_db,
            run_id,
            source_kind="hosted_red_team",
            workload_instance_id="",
            review_record_sha256=_REVIEW_SHA,
            source_generation_sha256=_GENERATION_SHA,
        )


def test_reviewed_lineage_requires_complete_case_metadata_in_postgres(
    migrated_db: Engine,
) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(DBAPIError), migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_attempts "
                "(organization_id, run_id, attempt_id, ordinal, case_id, source_kind, "
                "workload_instance_id, review_record_sha256, source_generation_sha256) VALUES "
                "(:org, :run_id, :attempt_id, 0, 'AF-BARE-REVIEWED', 'hosted_red_team', "
                "'HOSTED-001', :review, :generation)"
            ),
            {
                "org": _ORGANIZATION_ID,
                "run_id": run_id,
                "attempt_id": uuid.uuid4().hex + uuid.uuid4().hex,
                "review": _REVIEW_SHA,
                "generation": _GENERATION_SHA,
            },
        )


# --------------------------------------------------------------------------------------
# Agent acceptance may not smuggle workload provenance.
# --------------------------------------------------------------------------------------


def _acceptance_run_with_attempt(engine: Engine, **attempt_columns) -> None:
    """Insert an acceptance run and its singleton attempt in ONE transaction.

    ``fk_campaign_run_acceptance_attempt`` is deferred: the run references its attempt and the
    attempt references its run, so neither can be committed alone.
    """

    run_id = f"AR-{uuid.uuid4().hex}"
    attempt_id = uuid.uuid4().hex + uuid.uuid4().hex
    with engine.begin() as connection:
        # The acceptance branch of m1d_validate_campaign_run requires the referenced hosted
        # configuration set to exist.
        connection.execute(
            text(
                "INSERT INTO hosted_configuration_sets "
                "(organization_id, configuration_sha256, schema_version, release_sha256, "
                "payload, rationale, actor_user_id, actor_session_id) VALUES "
                "(:org, :cfg, '1', :release, CAST(:payload AS jsonb), 'test', 'user_x', 'sess_x') "
                "ON CONFLICT DO NOTHING"
            ),
            {
                "org": _ORGANIZATION_ID,
                "cfg": _SHA,
                "release": _REVIEW_SHA,
                "payload": json.dumps({"schema_version": "1"}),
            },
        )
        connection.execute(
            text(
                # campaign_run_authority_shape requires the two-person campaign columns to be
                # NULL on an acceptance run: acceptance authority is a different branch entirely,
                # not a campaign with extra fields.
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, run_kind, acceptance_configuration_sha256, "
                "acceptance_generation_policy_sha256, acceptance_context_sha256, "
                "acceptance_attempt_id, acceptance_limits, acceptance_expires_at, "
                "acceptance_actor_id, acceptance_provenance) VALUES "
                "(:run_id, :org, 'agent_acceptance', "
                ":cfg, :pol, :ctx, :attempt_id, CAST(:limits AS jsonb), :expires, "
                "'system:live-acceptance', CAST(:prov AS jsonb))"
            ),
            {
                "run_id": run_id,
                "org": _ORGANIZATION_ID,
                "cfg": _SHA,
                "pol": _REVIEW_SHA,
                "ctx": _GENERATION_SHA,
                "attempt_id": attempt_id,
                "limits": json.dumps(
                    {
                        "schema_version": "1",
                        "network_scope": "openrouter_langfuse_only",
                        "target_call_limit": 0,
                        "allowed_roles": ["orchestrator", "judge", "documentation"],
                        "role_call_caps": {
                            "orchestrator": 1,
                            "judge": 1,
                            "documentation": 1,
                        },
                    }
                ),
                "expires": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
                "prov": json.dumps(
                    {
                        "actor_type": "system",
                        "schema_version": "1",
                        "source": "agentforge.live_acceptance",
                    }
                ),
            },
        )
        attempt = {
            "org": _ORGANIZATION_ID,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "case_id": "agentforge-hosted-acceptance-v1",
            "context": _GENERATION_SHA,
            "fixture": json.dumps(
                {
                    "classification": "synthetic",
                    "contains_real_phi": False,
                    "schema_version": "1",
                    "source": "agentforge.live_acceptance",
                }
            ),
            "source_kind": None,
            "workload_instance_id": None,
            "review_record_sha256": None,
            "source_generation_sha256": None,
        }
        attempt.update(attempt_columns)
        connection.execute(
            text(
                "INSERT INTO campaign_attempts "
                "(organization_id, run_id, attempt_id, ordinal, case_id, case_content_hash, "
                "fixture_provenance, source_kind, workload_instance_id, review_record_sha256, "
                "source_generation_sha256) VALUES "
                "(:org, :run_id, :attempt_id, 0, :case_id, :context, CAST(:fixture AS jsonb), "
                ":source_kind, :workload_instance_id, :review_record_sha256, "
                ":source_generation_sha256)"
            ),
            attempt,
        )


def test_agent_acceptance_attempt_with_no_provenance_is_accepted(migrated_db: Engine) -> None:
    _acceptance_run_with_attempt(migrated_db)


def test_agent_acceptance_attempt_cannot_carry_workload_provenance(migrated_db: Engine) -> None:
    """The 0025 guard must stop a target-free acceptance attempt claiming reviewed lineage."""

    with pytest.raises(DBAPIError):
        _acceptance_run_with_attempt(
            migrated_db,
            source_kind="hosted_red_team",
            workload_instance_id="HOSTED-042",
            review_record_sha256=_REVIEW_SHA,
            source_generation_sha256=_GENERATION_SHA,
        )


# --------------------------------------------------------------------------------------
# Runtime validation must reject exactly what PostgreSQL rejects.
# --------------------------------------------------------------------------------------


def _store(engine: Engine) -> ControlPlaneStore:
    return ControlPlaneStore(engine=engine, environment="staging")


def _attempt_kwargs(run_id: str, ordinal: int = 0, **overrides) -> dict:
    kwargs = {
        "run_id": run_id,
        "ordinal": ordinal,
        "case_id": f"AF-RT-{ordinal:03d}",
        "case_content_hash": _SHA,
        "category": "prompt_injection",
        "severity": "high",
        "attack_class": "boundary",
        "owasp_mappings": _OWASP,
        "fixture_provenance": _FIXTURE,
    }
    kwargs.update(overrides)
    return kwargs


@pytest.mark.parametrize("category", sorted(SUPPORTED_CASE_CATEGORIES))
def test_runtime_accepts_every_supported_category(migrated_db: Engine, category: str) -> None:
    run_id = _campaign_run(migrated_db)
    _store(migrated_db).ensure_campaign_attempt(**_attempt_kwargs(run_id, category=category))


def test_runtime_rejects_an_unknown_category(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(InvalidControlPlaneInput):
        _store(migrated_db).ensure_campaign_attempt(
            **_attempt_kwargs(run_id, category="cryptomining")
        )


def test_runtime_rejects_partial_tool_provenance(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    store = _store(migrated_db)
    with pytest.raises(InvalidControlPlaneInput):
        store.ensure_campaign_attempt(**_attempt_kwargs(run_id, source_tool="garak"))
    with pytest.raises(InvalidControlPlaneInput):
        store.ensure_campaign_attempt(**_attempt_kwargs(run_id, source_technique="dan.Dan_11_0"))


def test_runtime_rejects_a_producer_kind_as_a_source_tool(migrated_db: Engine) -> None:
    """``hosted_red_team`` is not in the security-tool catalog and must never be a tool."""

    run_id = _campaign_run(migrated_db)
    with pytest.raises(InvalidControlPlaneInput):
        _store(migrated_db).ensure_campaign_attempt(
            **_attempt_kwargs(
                run_id, source_tool="hosted_red_team", source_technique="hosted_red_team"
            )
        )


@pytest.mark.parametrize("present", sorted(_NEW_COLUMNS))
def test_runtime_rejects_partial_reviewed_lineage(migrated_db: Engine, present: str) -> None:
    values = {
        "source_kind": "hosted_red_team",
        "workload_instance_id": "HOSTED-042",
        "review_record_sha256": _REVIEW_SHA,
        "source_generation_sha256": _GENERATION_SHA,
    }
    run_id = _campaign_run(migrated_db)
    with pytest.raises(InvalidControlPlaneInput):
        _store(migrated_db).ensure_campaign_attempt(
            **_attempt_kwargs(run_id, **{present: values[present]})
        )


def test_runtime_accepts_complete_reviewed_lineage(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    _store(migrated_db).ensure_campaign_attempt(
        **_attempt_kwargs(
            run_id,
            source_kind="hosted_red_team",
            workload_instance_id="HOSTED-042",
            review_record_sha256=_REVIEW_SHA,
            source_generation_sha256=_GENERATION_SHA,
        )
    )


@pytest.mark.parametrize("source_kind", ["m11_seed", "hosted_red_team"])
def test_runtime_rejects_tool_provenance_for_non_tool_source_kind(
    migrated_db: Engine, source_kind: str
) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(InvalidControlPlaneInput):
        _store(migrated_db).ensure_campaign_attempt(
            **_attempt_kwargs(
                run_id,
                source_tool="garak",
                source_technique="dan.Dan_11_0",
                source_kind=source_kind,
                workload_instance_id="HOSTED-001",
                review_record_sha256=_REVIEW_SHA,
                source_generation_sha256=_GENERATION_SHA,
            )
        )


def test_runtime_requires_tool_provenance_for_reviewed_full_scan(
    migrated_db: Engine,
) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(InvalidControlPlaneInput):
        _store(migrated_db).ensure_campaign_attempt(
            **_attempt_kwargs(
                run_id,
                source_kind="reviewed_full_scan",
                workload_instance_id="BASE-009",
                review_record_sha256=_REVIEW_SHA,
                source_generation_sha256=_GENERATION_SHA,
            )
        )


def test_runtime_requires_case_metadata_for_reviewed_lineage(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    with pytest.raises(InvalidControlPlaneInput):
        _store(migrated_db).ensure_campaign_attempt(
            run_id=run_id,
            ordinal=0,
            case_id="AF-BARE-REVIEWED",
            source_kind="hosted_red_team",
            workload_instance_id="HOSTED-001",
            review_record_sha256=_REVIEW_SHA,
            source_generation_sha256=_GENERATION_SHA,
        )


def test_runtime_keeps_legacy_attempts_without_reviewed_lineage_valid(
    migrated_db: Engine,
) -> None:
    run_id = _campaign_run(migrated_db)
    _store(migrated_db).ensure_campaign_attempt(**_attempt_kwargs(run_id))


def test_runtime_and_postgres_admit_all_100_reviewed_cases(migrated_db: Engine) -> None:
    corpus = load_live_100_corpus(expected_manifest_sha256=_LIVE_100_MANIFEST_SHA256)
    run_id = _campaign_run(migrated_db)
    store = _store(migrated_db)
    for ordinal, case in enumerate(corpus.cases):
        payload = verified_case_payload(case)
        store.ensure_campaign_attempt(
            run_id=run_id,
            ordinal=ordinal,
            case_id=payload["case_id"],
            case_content_hash=case.content_hash,
            category=payload["category"],
            severity=payload["severity"]["rating"],
            attack_class=payload["test_design"]["classification"],
            owasp_mappings=payload["owasp"],
            fixture_provenance=payload["fixture_provenance"],
            source_tool=case.source_tool,
            source_technique=case.source_technique,
            source_kind=case.source_kind,
            workload_instance_id=case.instance_id,
            review_record_sha256=case.review_record_sha256,
            source_generation_sha256=case.source_generation_sha256,
        )

    with migrated_db.connect() as connection:
        total = connection.execute(
            text("SELECT count(*) FROM campaign_attempts WHERE run_id = :run_id"),
            {"run_id": run_id},
        ).scalar_one()
        source_counts = dict(
            connection.execute(
                text(
                    "SELECT source_kind, count(*) FROM campaign_attempts "
                    "WHERE run_id = :run_id GROUP BY source_kind"
                ),
                {"run_id": run_id},
            ).all()
        )
        tool_counts = dict(
            connection.execute(
                text(
                    "SELECT source_tool, count(*) FROM campaign_attempts "
                    "WHERE run_id = :run_id GROUP BY source_tool"
                ),
                {"run_id": run_id},
            ).all()
        )

    assert total == 100
    assert source_counts == {"m11_seed": 9, "reviewed_full_scan": 5, "hosted_red_team": 86}
    assert tool_counts == {None: 95, "garak": 1, "promptfoo": 1, "pyrit": 3}


def test_idempotent_replay_refuses_to_re_attribute_lineage(migrated_db: Engine) -> None:
    """Replaying the same ordinal with a different producer must conflict, not overwrite."""

    run_id = _campaign_run(migrated_db)
    store = _store(migrated_db)
    original = _attempt_kwargs(
        run_id,
        source_kind="hosted_red_team",
        workload_instance_id="HOSTED-042",
        review_record_sha256=_REVIEW_SHA,
        source_generation_sha256=_GENERATION_SHA,
    )
    store.ensure_campaign_attempt(**original)
    # Same attempt identity, different reviewed lineage.
    with pytest.raises(RecordConflictError):
        store.ensure_campaign_attempt(**{**original, "source_kind": "m11_seed"})


def test_idempotent_replay_refuses_to_omit_existing_lineage(migrated_db: Engine) -> None:
    run_id = _campaign_run(migrated_db)
    store = _store(migrated_db)
    original = _attempt_kwargs(
        run_id,
        source_kind="hosted_red_team",
        workload_instance_id="HOSTED-001",
        review_record_sha256=_REVIEW_SHA,
        source_generation_sha256=_GENERATION_SHA,
    )
    store.ensure_campaign_attempt(**original)
    stripped = {
        key: value
        for key, value in original.items()
        if key
        not in {
            "source_kind",
            "workload_instance_id",
            "review_record_sha256",
            "source_generation_sha256",
        }
    }
    with pytest.raises(RecordConflictError):
        store.ensure_campaign_attempt(**stripped)
