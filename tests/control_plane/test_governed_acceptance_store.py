"""Store authority for the governed, target-BOUND four-role acceptance run (0022)."""

from __future__ import annotations

import datetime
import hashlib
import uuid
from decimal import Decimal

import pytest
from sqlalchemy import Engine, text

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.prompts import load_prompt_registry
from agentforge.auth.principal import Principal
from agentforge.control_plane.errors import (
    AuthorizationDeniedError,
    RecordConflictError,
)
from agentforge.control_plane.store import (
    ControlPlaneStore,
    GovernedAcceptanceRunIdentity,
    canonical_governed_acceptance_limits,
)
from agentforge.providers.lineage import ProviderTerminalEventV1

_ORGANIZATION_ID = "org_GovernedAcceptance"
_GENERATION_POLICY_SHA256 = "d" * 64
_RELEASE_SHA256 = hashlib.sha256(b"reviewed-governed-release").hexdigest()
_JUDGE_CALIBRATION_ID = f"JC-{'c' * 64}"
_REVIEWED_CASE_ID = "AF-M11-PI-001"
_REVIEWED_CONTENT_HASH = hashlib.sha256(b"reviewed-governed-case").hexdigest()
_LAUNCHER = "user_GovLauncher"
_LAUNCHER_SESSION = "sess_GovLauncher"
_APPROVER = "user_GovApprover"
_MODELS = {
    "orchestrator": "anthropic/claude-opus-4.8",
    "red_team": "qwen/qwen3.5-397b-a17b",
    "judge": "google/gemini-2.5-pro",
    "documentation": "openai/gpt-5.4",
}
_UPSTREAM = {
    "orchestrator": "anthropic",
    "red_team": "together",
    "judge": "google-vertex",
    "documentation": "openai",
}
_SERVED_UPSTREAM = {
    "orchestrator": "Anthropic",
    "red_team": "Together",
    "judge": "Google",
    "documentation": "OpenAI",
}
_USD_CAPS = {
    "orchestrator": Decimal("1.5"),
    "red_team": Decimal("1"),
    "judge": Decimal("4"),
    "documentation": Decimal("1"),
}
_TOKEN_CAPS = {
    "orchestrator": (8_192, 512, 1_024),
    "red_team": (4_096, 512, 512),
    "judge": (8_192, 512, 1_024),
    "documentation": (8_192, 512, 1_024),
}


def _prompt(role: str):
    return next(record for record in load_prompt_registry() if record.role == role)


def _configuration() -> HostedConfigurationSet:
    return HostedConfigurationSet(
        roles=tuple(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=_MODELS[role],
                upstream_provider=_UPSTREAM[role],
                credential_reference=f"secretref://local/openrouter/{role}/governed-1",
                prompt_sha256=_prompt(role).sha256,
                policy_sha256=hashlib.sha256(f"{role}:governed".encode()).hexdigest(),
                prices=TokenPrices(
                    input_usd_per_million_tokens=Decimal("100"),
                    output_usd_per_million_tokens=Decimal("100"),
                    reasoning_usd_per_million_tokens=Decimal("100"),
                ),
                limits=HostedLimits(
                    max_calls=1,
                    max_input_tokens=_TOKEN_CAPS[role][0],
                    max_output_tokens=_TOKEN_CAPS[role][1],
                    max_reasoning_tokens=_TOKEN_CAPS[role][2],
                    max_usd=_USD_CAPS[role],
                    max_retries=0,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
            for role in ("orchestrator", "red_team", "judge", "documentation")
        ),
        global_limits=HostedLimits(
            max_calls=4,
            max_input_tokens=28_672,
            max_output_tokens=2_048,
            max_reasoning_tokens=3_584,
            max_usd=Decimal("10"),
            max_retries=0,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


_PROD_CALL_CAPS = {"orchestrator": 9, "red_team": 19, "judge": 19, "documentation": 9}
_PROD_USD_CAPS = {
    "orchestrator": Decimal("0.75"),
    "red_team": Decimal("1"),
    "judge": Decimal("2.50"),
    "documentation": Decimal("0.50"),
}


def _production_configuration() -> HostedConfigurationSet:
    """The confirmed production authority: Judge max_calls=56 (roles 9/19/19/9, retries=1)."""
    return HostedConfigurationSet(
        roles=tuple(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=_MODELS[role],
                upstream_provider=_UPSTREAM[role],
                credential_reference=f"secretref://local/openrouter/{role}/production-1",
                prompt_sha256=_prompt(role).sha256,
                policy_sha256=hashlib.sha256(f"{role}:production".encode()).hexdigest(),
                prices=TokenPrices(
                    input_usd_per_million_tokens=Decimal("1.25"),
                    output_usd_per_million_tokens=Decimal("10"),
                    reasoning_usd_per_million_tokens=Decimal("10"),
                ),
                limits=HostedLimits(
                    max_calls=_PROD_CALL_CAPS[role],
                    max_input_tokens=_PROD_CALL_CAPS[role] * 10_000,
                    max_output_tokens=_PROD_CALL_CAPS[role] * 2_000,
                    max_reasoning_tokens=_PROD_CALL_CAPS[role] * 1_000,
                    max_usd=_PROD_USD_CAPS[role],
                    max_retries=1,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
            for role in ("orchestrator", "red_team", "judge", "documentation")
        ),
        global_limits=HostedLimits(
            max_calls=56,
            max_input_tokens=560_000,
            max_output_tokens=112_000,
            max_reasoning_tokens=56_000,
            max_usd=Decimal("5"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE campaign_runs, campaign_authorization_decisions, "
                "campaign_authorization_requests, hosted_configuration_sets, "
                "command_idempotency, audit_events RESTART IDENTITY CASCADE"
            )
        )


def _stage(store: ControlPlaneStore, configuration: HostedConfigurationSet) -> None:
    store.stage_hosted_configuration_set(
        principal=Principal(
            user_id="user_gov_operator",
            session_id="sess_gov_operator",
            organization_id=_ORGANIZATION_ID,
            organization_role="org:operator",
            organization_permissions=frozenset({"org:config:manage"}),
        ),
        configuration=configuration,
        release_sha256=_RELEASE_SHA256,
        rationale=(
            "Stage the four-role hosted configuration through CONFIG_MANAGE; this does not "
            "authorize campaign or target traffic."
        ),
        idempotency_key="governed-acceptance-stage-config-0001",
    )


def _seed_authorization(
    engine: Engine,
    *,
    launcher: str = _LAUNCHER,
    launcher_session: str = _LAUNCHER_SESSION,
    approver: str = _APPROVER,
    approved: bool = True,
    expired: bool = False,
) -> tuple[str, str]:
    """Raw-seed one campaign-style two-person authorization (request + decision)."""
    request_id = f"gov-req-{uuid.uuid4().hex[:12]}"
    scope_hash = hashlib.sha256(request_id.encode()).hexdigest()
    interval = "-5 minutes" if expired else "15 minutes"
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:req, :org, :scope, '{}'::jsonb, :launcher, :session, "
                f"clock_timestamp() + interval '{interval}')"
            ),
            {
                "req": request_id,
                "org": _ORGANIZATION_ID,
                "scope": scope_hash,
                "launcher": launcher,
                "session": launcher_session,
            },
        )
        if approved:
            connection.execute(
                text(
                    "INSERT INTO campaign_authorization_decisions "
                    "(decision_id, organization_id, request_id, scope_hash, decision, "
                    "approver_user_id, approver_session_id) VALUES "
                    "(:dec, :org, :req, :scope, 'approved', :approver, 'sess_GovApprover')"
                ),
                {
                    "dec": f"gov-dec-{uuid.uuid4().hex[:12]}",
                    "org": _ORGANIZATION_ID,
                    "req": request_id,
                    "scope": scope_hash,
                    "approver": approver,
                },
            )
    return request_id, scope_hash


def _create(
    engine: Engine,
    *,
    launcher: str = _LAUNCHER,
    approver: str = _APPROVER,
) -> tuple[ControlPlaneStore, GovernedAcceptanceRunIdentity, HostedConfigurationSet]:
    _clean(engine)
    store = ControlPlaneStore(engine, environment="local")
    configuration = _configuration()
    _stage(store, configuration)
    request_id, scope_hash = _seed_authorization(engine, launcher=launcher, approver=approver)
    identity = store.create_governed_acceptance_run(
        organization_id=_ORGANIZATION_ID,
        authorization_request_id=request_id,
        scope_hash=scope_hash,
        launcher_user_id=launcher,
        launcher_session_id=_LAUNCHER_SESSION,
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY_SHA256,
        reviewed_case_id=_REVIEWED_CASE_ID,
        reviewed_case_content_hash=_REVIEWED_CONTENT_HASH,
        reviewed_category="prompt_injection",
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
    )
    return store, identity, configuration


def _start(
    store: ControlPlaneStore,
    identity: GovernedAcceptanceRunIdentity,
    configuration: HostedConfigurationSet,
    role: str,
    *,
    parent_execution_id: str | None = None,
    judge_calibration_state: str = "enabled",
) -> str:
    role_configuration = next(item for item in configuration.roles if item.role == role)
    return store.start_governed_agent_execution(
        run_id=identity.run_id,
        agent_role=role,  # type: ignore[arg-type]
        input_payload={"reviewed_case": _REVIEWED_CASE_ID, "role": role},
        provider=role_configuration.provider,
        model=role_configuration.model_id,
        upstream_provider=role_configuration.upstream_provider,
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role_configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY_SHA256,
        judge_calibration_id=_JUDGE_CALIBRATION_ID if role == "judge" else None,
        judge_calibration_state=judge_calibration_state if role == "judge" else None,
        parent_execution_id=parent_execution_id,
        detail={"input_kind": "reviewed_governed"},
    )


def _succeed(
    store: ControlPlaneStore,
    execution_id: str,
    configuration: HostedConfigurationSet,
    role: str,
) -> None:
    role_configuration = next(item for item in configuration.roles if item.role == role)
    prompt = _prompt(role)
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    cost = Decimal("0.010000000000")
    store.finish_physical_attempt(
        invocation,
        ProviderTerminalEventV1(
            invocation_id=invocation.invocation_id,
            physical_sequence=1,
            status="succeeded",
            returned_model=logical.requested_model,
            upstream_provider=_SERVED_UPSTREAM[role],
            provider_request_id=f"governed-provider-request-{role}",
            input_tokens=10,
            output_tokens=5,
            reasoning_tokens=2,
            cost_measurement_state="measured",
            measured_cost_usd=cost,
            error_code=None,
            finished_at=datetime.datetime.now(datetime.UTC),
        ),
    )
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"reviewed_case": _REVIEWED_CASE_ID, "role": role},
        returned_model=logical.requested_model,
        upstream_provider=_SERVED_UPSTREAM[role],
        provider_request_id=f"governed-provider-request-{role}",
        input_tokens=10,
        output_tokens=5,
        reasoning_tokens=2,
        measured_cost_usd=format(cost, "f"),
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role_configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY_SHA256,
        physical_attempts=1,
        oracle_agreement=True if role == "judge" else None,
        decision_authority="oracle" if role == "judge" else None,
    )


def _run_four_roles(
    store: ControlPlaneStore,
    identity: GovernedAcceptanceRunIdentity,
    configuration: HostedConfigurationSet,
) -> None:
    planner = _start(store, identity, configuration, "orchestrator")
    _succeed(store, planner, configuration, "orchestrator")
    generator = _start(store, identity, configuration, "red_team", parent_execution_id=planner)
    _succeed(store, generator, configuration, "red_team")
    evaluator = _start(store, identity, configuration, "judge", parent_execution_id=generator)
    _succeed(store, evaluator, configuration, "judge")
    reporter = _start(
        store, identity, configuration, "documentation", parent_execution_id=evaluator
    )
    _succeed(store, reporter, configuration, "documentation")


def _record_single_dispatch(engine: Engine, identity: GovernedAcceptanceRunIdentity) -> None:
    """Insert the one bounded target dispatch row the governed authority permits."""
    fields = {
        "schema_version": "1",
        "campaign_run_id": identity.run_id,
        "attempt_id": identity.attempt_id,
        "campaign_id": None,
        "target_id": None,
        "target_version": None,
        "attack_attempt": {"case_ref": _REVIEWED_CASE_ID},
        "request_transcript": "reviewed governed request",
        "response_transcript": "controlled target response",
        "policy_decision_id": uuid.uuid4().hex,
        "executed_at": datetime.datetime.now(datetime.UTC).isoformat(),
        "trace_id": None,
        "correlation_id": None,
        "recorder_identity": "execution-recorder",
        "recorder_version": "1",
        "organization_id": _ORGANIZATION_ID,
        "surface_id": None,
        "surface_version": None,
        "authorization_scope_hash": None,
        "execution_profile": "live",
        "evidence_provenance": None,
    }
    from agentforge.policy.recorder import ExecutionRecorder

    recorder = ExecutionRecorder()
    with engine.begin() as connection:
        recorder.record(fields, connection)


def test_governed_run_atomically_creates_reviewed_attempt(migrated_db: Engine) -> None:
    _, identity, configuration = _create(migrated_db)
    expected_attempt = hashlib.sha256(
        f"m1d-attempt:v1\0{identity.run_id}\0{0}\0{_REVIEWED_CASE_ID}".encode()
    ).hexdigest()
    assert identity.run_id.startswith("GA-")
    assert identity.attempt_id == expected_attempt
    with migrated_db.connect() as connection:
        run = (
            connection.execute(
                text(
                    "SELECT run_kind, launcher_user_id, acceptance_context_sha256, "
                    "acceptance_actor_id, acceptance_provenance, acceptance_limits "
                    "FROM campaign_runs WHERE run_id = :run"
                ),
                {"run": identity.run_id},
            )
            .mappings()
            .one()
        )
        attempt = (
            connection.execute(
                text(
                    "SELECT case_id, case_content_hash, category "
                    "FROM campaign_attempts WHERE run_id = :run"
                ),
                {"run": identity.run_id},
            )
            .mappings()
            .one()
        )
        state = (
            connection.execute(
                text("SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id"),
                {"run": identity.run_id},
            )
            .scalars()
            .all()
        )
    assert run["run_kind"] == "governed_acceptance"
    assert run["launcher_user_id"] == _LAUNCHER
    assert run["acceptance_context_sha256"] == _REVIEWED_CONTENT_HASH
    assert run["acceptance_actor_id"] is None
    assert run["acceptance_provenance"] is None
    assert run["acceptance_limits"] == canonical_governed_acceptance_limits(configuration)
    assert attempt["case_id"] == _REVIEWED_CASE_ID
    assert attempt["case_content_hash"] == _REVIEWED_CONTENT_HASH
    assert attempt["category"] == "prompt_injection"
    assert state == ["running"]


def test_self_approval_is_blocked_before_a_decision_can_even_exist(migrated_db: Engine) -> None:
    # Two-person control's first line is upstream: a self-approved decision can never be recorded,
    # so the store's own launcher!=approver check is unreachable defense in depth.
    _clean(migrated_db)
    with pytest.raises(Exception, match="cannot approve own authorization request"):
        _seed_authorization(migrated_db, launcher=_LAUNCHER, approver=_LAUNCHER)


def test_governed_create_refuses_a_launcher_that_differs_from_its_approval(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="local")
    configuration = _configuration()
    _stage(store, configuration)
    request_id, scope_hash = _seed_authorization(
        migrated_db, launcher=_LAUNCHER, approver=_APPROVER
    )
    with pytest.raises(AuthorizationDeniedError, match="launcher differs from its approval"):
        store.create_governed_acceptance_run(
            organization_id=_ORGANIZATION_ID,
            authorization_request_id=request_id,
            scope_hash=scope_hash,
            launcher_user_id="user_Impostor",
            launcher_session_id=_LAUNCHER_SESSION,
            configuration_set_sha256=configuration.configuration_sha256,
            generation_policy_sha256=_GENERATION_POLICY_SHA256,
            reviewed_case_id=_REVIEWED_CASE_ID,
            reviewed_case_content_hash=_REVIEWED_CONTENT_HASH,
            reviewed_category="prompt_injection",
            expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        )


def test_governed_create_refuses_without_live_approval(migrated_db: Engine) -> None:
    _clean(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="local")
    configuration = _configuration()
    _stage(store, configuration)
    request_id, scope_hash = _seed_authorization(migrated_db, approved=False)
    with pytest.raises(AuthorizationDeniedError, match="authorization is not live"):
        store.create_governed_acceptance_run(
            organization_id=_ORGANIZATION_ID,
            authorization_request_id=request_id,
            scope_hash=scope_hash,
            launcher_user_id=_LAUNCHER,
            launcher_session_id=_LAUNCHER_SESSION,
            configuration_set_sha256=configuration.configuration_sha256,
            generation_policy_sha256=_GENERATION_POLICY_SHA256,
            reviewed_case_id=_REVIEWED_CASE_ID,
            reviewed_case_content_hash=_REVIEWED_CONTENT_HASH,
            reviewed_category="prompt_injection",
            expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        )


def test_governed_create_refuses_missing_configuration(migrated_db: Engine) -> None:
    _clean(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="local")
    configuration = _configuration()
    request_id, scope_hash = _seed_authorization(migrated_db)
    with pytest.raises(AuthorizationDeniedError, match="human-staged configuration"):
        store.create_governed_acceptance_run(
            organization_id=_ORGANIZATION_ID,
            authorization_request_id=request_id,
            scope_hash=scope_hash,
            launcher_user_id=_LAUNCHER,
            launcher_session_id=_LAUNCHER_SESSION,
            configuration_set_sha256=configuration.configuration_sha256,
            generation_policy_sha256=_GENERATION_POLICY_SHA256,
            reviewed_case_id=_REVIEWED_CASE_ID,
            reviewed_case_content_hash=_REVIEWED_CONTENT_HASH,
            reviewed_category="prompt_injection",
            expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        )


def test_governed_binds_four_roles_with_enabled_judge(migrated_db: Engine) -> None:
    store, identity, configuration = _create(migrated_db)
    planner = _start(store, identity, configuration, "orchestrator")
    generator = _start(store, identity, configuration, "red_team", parent_execution_id=planner)
    evaluator = _start(store, identity, configuration, "judge", parent_execution_id=generator)
    reporter = _start(
        store, identity, configuration, "documentation", parent_execution_id=evaluator
    )
    with migrated_db.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT execution_id, attempt_id, parent_execution_id, agent_role, "
                    "judge_calibration_state, detail->>'run_kind' AS run_kind "
                    "FROM agent_executions WHERE campaign_run_id = :run ORDER BY id"
                ),
                {"run": identity.run_id},
            )
            .mappings()
            .all()
        )
    assert [row["agent_role"] for row in rows] == [
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    ]
    assert {row["attempt_id"] for row in rows} == {identity.attempt_id}
    assert {row["run_kind"] for row in rows} == {"governed_acceptance"}
    assert rows[0]["parent_execution_id"] is None
    assert rows[1]["parent_execution_id"] == planner
    assert rows[2]["parent_execution_id"] == generator
    assert rows[3]["parent_execution_id"] == evaluator
    assert reporter == rows[3]["execution_id"]
    assert (
        next(r for r in rows if r["agent_role"] == "judge")["judge_calibration_state"] == "enabled"
    )


def test_governed_judge_must_start_enabled(migrated_db: Engine) -> None:
    store, identity, configuration = _create(migrated_db)
    planner = _start(store, identity, configuration, "orchestrator")
    generator = _start(store, identity, configuration, "red_team", parent_execution_id=planner)
    with pytest.raises(AuthorizationDeniedError, match="must start with an enabled calibration"):
        _start(
            store,
            identity,
            configuration,
            "judge",
            parent_execution_id=generator,
            judge_calibration_state="failed",
        )


def test_governed_completion_requires_the_single_dispatch(migrated_db: Engine) -> None:
    store, identity, configuration = _create(migrated_db)
    _run_four_roles(store, identity, configuration)
    # Four measured successful calls, but no recorded target dispatch yet.
    with pytest.raises(RecordConflictError, match="single recorded target dispatch"):
        store.complete_governed_acceptance_run(run_id=identity.run_id)
    _record_single_dispatch(migrated_db, identity)
    assert store.complete_governed_acceptance_run(run_id=identity.run_id) == identity.run_id
    assert store.complete_governed_acceptance_run(run_id=identity.run_id) == identity.run_id
    with migrated_db.connect() as connection:
        states = (
            connection.execute(
                text("SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id"),
                {"run": identity.run_id},
            )
            .scalars()
            .all()
        )
    assert states == ["running", "complete"]


def test_governed_derives_production_config_budget_and_pins_one_dispatch(
    migrated_db: Engine,
) -> None:
    """Item 3 + guardrails: the governed budget DERIVES from the staged 56-call production config,
    while target_call_limit=1 + policy_gateway_target stay pinned even though the config allows an
    agent-level retry (retries=1). A relaxed budget never relaxes the dispatch ceiling."""
    configuration = _production_configuration()
    derived = canonical_governed_acceptance_limits(configuration)
    # Budget is DERIVED from the config.
    assert derived["global_call_cap"] == 56
    assert derived["role_call_caps"] == {
        "orchestrator": 9,
        "red_team": 19,
        "judge": 19,
        "documentation": 9,
    }
    assert {role: Decimal(cap) for role, cap in derived["role_usd_caps"].items()} == {
        "orchestrator": Decimal("0.75"),
        "red_team": Decimal("1"),
        "judge": Decimal("2.50"),
        "documentation": Decimal("0.50"),
    }
    assert Decimal(derived["global_usd_cap"]) == Decimal("5")
    # One-dispatch invariant is PINNED, never derived — even with the config's retries=1.
    assert derived["target_call_limit"] == 1
    assert derived["network_scope"] == "policy_gateway_target"

    _clean(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="local")
    _stage(store, configuration)
    request_id, scope_hash = _seed_authorization(migrated_db)
    identity = store.create_governed_acceptance_run(
        organization_id=_ORGANIZATION_ID,
        authorization_request_id=request_id,
        scope_hash=scope_hash,
        launcher_user_id=_LAUNCHER,
        launcher_session_id=_LAUNCHER_SESSION,
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_GENERATION_POLICY_SHA256,
        reviewed_case_id=_REVIEWED_CASE_ID,
        reviewed_case_content_hash=_REVIEWED_CONTENT_HASH,
        reviewed_category="prompt_injection",
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
    )
    with migrated_db.connect() as connection:
        stored = connection.execute(
            text("SELECT acceptance_limits FROM campaign_runs WHERE run_id = :run"),
            {"run": identity.run_id},
        ).scalar_one()
    # The store derives + matches against the LOADED (staged, content-hashed) config, and the run
    # row carries exactly that derivation — self-consistent under the stage/load round-trip.
    loaded = store.load_hosted_configuration_set(
        organization_id=_ORGANIZATION_ID,
        configuration_set_sha256=configuration.configuration_sha256,
        release_sha256=_RELEASE_SHA256,
    )
    assert stored == canonical_governed_acceptance_limits(loaded)
    assert stored["global_call_cap"] == 56
    assert stored["role_call_caps"]["judge"] == 19
    assert stored["target_call_limit"] == 1
    assert stored["network_scope"] == "policy_gateway_target"


def test_governed_abort_trips_the_kill_switch(migrated_db: Engine) -> None:
    store, identity, configuration = _create(migrated_db)
    planner = _start(store, identity, configuration, "orchestrator")
    assert (
        store.abort_governed_acceptance_run(
            run_id=identity.run_id, reason_code="operator_kill_switch"
        )
        == identity.run_id
    )
    # Idempotent, and no further executions may start once aborted.
    assert (
        store.abort_governed_acceptance_run(
            run_id=identity.run_id, reason_code="operator_kill_switch"
        )
        == identity.run_id
    )
    with pytest.raises(AuthorizationDeniedError, match="not executable"):
        _start(store, identity, configuration, "red_team", parent_execution_id=planner)
