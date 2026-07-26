"""The hosted Red Team attempt must exist before the provider call, not after it.

Every hosted live-100 campaign died the moment Red Team succeeded. The chronology was:

    1. hosted Red Team is invoked and terminalizes successfully (provider rows now exist)
    2. the Runner creates the campaign attempt
    3. the Runner calls ``bind_agent_execution_attempt``

and step 3 is refused twice over by the control plane — once because the execution is no longer
``running`` (:class:`RecordConflictError`) and once because a provider invocation already exists.
Neither guard is wrong: rewriting the lineage of a call that already happened is exactly what they
exist to prevent. The chronology was wrong.

The fix inverts it for exact-manifest workloads, where the next case is already fixed as
``remaining[0]``: create the durable attempt FIRST, hand its id to the hosted invocation, and let
every hosted row be born carrying it. No after-the-fact binding is attempted on the hosted path.

These tests pin both halves — that the new order produces one shared attempt id across all four
lineage tables, and that the old order still fails, so nothing quietly reintroduces it.
"""

from __future__ import annotations

import datetime
import hashlib
from decimal import Decimal

import pytest
from sqlalchemy import Engine, text

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.prompts import load_prompt_registry
from agentforge.auth.permissions import (
    CAMPAIGN_AUTHORIZE,
    CAMPAIGN_LAUNCH,
    CONFIG_MANAGE,
    TARGETS_MANAGE,
)
from agentforge.auth.principal import Principal
from agentforge.campaign.corpus import LIVE_100_BATCH_IDS, load_mvp_corpus
from agentforge.control_plane.errors import RecordConflictError
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.providers.lineage import ProviderTerminalEventV1
from agentforge.runner import (
    _EXACT_MANIFEST_WORKLOAD_IDS,
    DispatchUnavailable,
    HostedLineageUnsupported,
)
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    HostedRunBinding,
    OwaspMapping,
    RiskLevel,
    SafetyCaps,
    SurfaceKind,
    TargetDefinition,
    TargetEnvironment,
    TargetLifecycle,
)

_ORGANIZATION_ID = "org_HostedRedTeamLineage"
_PROMPTS = {record.role: record for record in load_prompt_registry()}
_POLICY_SHA = DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256


def _principal(user_id: str, *permissions: str) -> Principal:
    return Principal(
        user_id=user_id,
        session_id=f"sess_{user_id.removeprefix('user_')}",
        organization_id=_ORGANIZATION_ID,
        organization_role="org:operator",
        organization_permissions=frozenset(permissions),
    )


def _configuration() -> HostedConfigurationSet:
    models = {
        "orchestrator": "anthropic/claude-opus-4.8",
        "red_team": "qwen/qwen3.5-397b-a17b",
        "judge": "google/gemini-2.5-pro",
        "documentation": "openai/gpt-5.4",
    }
    upstream = {
        "orchestrator": "anthropic",
        "red_team": "chutes",
        "judge": "google-vertex",
        "documentation": "openai",
    }
    roles = [
        HostedRoleConfiguration(
            role=role,  # type: ignore[arg-type]
            provider="openrouter",
            model_id=models[role],
            upstream_provider=upstream[role],
            credential_reference=f"secretref://staging/providers/openrouter/{role}/gen-1",
            prompt_sha256=_PROMPTS[role].sha256,
            policy_sha256=hashlib.sha256(f"{role}:policy:v1".encode()).hexdigest(),
            prices=TokenPrices(
                input_usd_per_million_tokens=Decimal("1"),
                output_usd_per_million_tokens=Decimal("2"),
                reasoning_usd_per_million_tokens=Decimal("3"),
            ),
            limits=HostedLimits(
                max_calls=8,
                max_input_tokens=80_000,
                max_output_tokens=16_000,
                max_reasoning_tokens=32_768,
                max_usd=Decimal("0.5"),
                max_retries=1,
                max_requests_per_second=Decimal("0.5"),
                max_concurrency=1,
            ),
        )
        for role in ("orchestrator", "red_team", "judge", "documentation")
    ]
    return HostedConfigurationSet(
        roles=tuple(roles),
        global_limits=HostedLimits(
            max_calls=32,
            max_input_tokens=320_000,
            max_output_tokens=64_000,
            max_reasoning_tokens=131_072,
            max_usd=Decimal("2"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE agent_executions, agent_configuration_versions, "
                "hosted_configuration_sets, audit_events, command_idempotency, "
                "campaign_attempts, campaign_run_events, campaign_runs, "
                "campaign_authorization_decisions, campaign_authorization_requests, "
                "surface_state_events, attack_surface_definitions, surface_identities, "
                "target_lifecycle_events, target_definitions, target_identities, jobs "
                "RESTART IDENTITY CASCADE"
            )
        )


def _authorized_run(engine: Engine) -> tuple[ControlPlaneStore, str, HostedConfigurationSet]:
    """Drive the real two-person handshake so the run row satisfies every DB trigger.

    The run carries a real ``HostedRunBinding`` pinned to the CURRENT generation-policy digest,
    so the digest-propagation assertions below are checking the shipped policy, not a placeholder.
    """

    _clean(engine)
    store = ControlPlaneStore(engine, environment="staging")
    launcher = _principal(
        "user_LineageLauncher",
        TARGETS_MANAGE,
        CONFIG_MANAGE,
        CAMPAIGN_LAUNCH,
    )
    approver = _principal("user_LineageApprover", CAMPAIGN_AUTHORIZE)
    target = TargetDefinition(
        target_id="hosted-red-team-lineage-target",
        name="Synthetic hosted Red Team lineage fixture",
        version="1.0.0",
        adapter_kind="openemr",
        environment=TargetEnvironment.STAGING,
        base_url="https://target.example.test/openemr",
        allowlisted_hosts=("target.example.test",),
        auth_mode=AuthMode.BEARER,
        credential_ref="secretref://staging/targets/hosted-red-team-lineage",
        synthetic_data_only=True,
        synthetic_data_attestation_ref="attestation://synthetic/hosted-red-team-lineage",
        canary_refs=("oracle://canary/hosted-red-team-lineage",),
        oracle_refs=("oracle://judge/hosted-red-team-lineage",),
        safety_caps=SafetyCaps(
            budget_usd=2.0,
            max_attempts_per_run=3,
            target_requests_per_second=0.5,
            run_timeout_seconds=60.0,
        ),
    )
    surface = AttackSurfaceDefinition(
        surface_id="hosted-red-team-lineage-chat",
        version="1.0.0",
        target_id=target.target_id,
        target_version=target.version,
        kind=SurfaceKind.CHAT,
        protocol="https",
        method="POST",
        relative_path="api/copilot/message",
        trust_boundary="external-target",
        authentication_required=True,
        risk=RiskLevel.HIGH,
        owasp_mappings=(
            OwaspMapping(
                framework="OWASP LLM",
                version="2025",
                identifier="LLM01",
                name="Prompt Injection",
            ),
        ),
        oracle_refs=("oracle://canary/hosted-red-team-lineage",),
        enabled=True,
    )
    store.register_target(
        principal=launcher,
        target=target,
        idempotency_key="hosted-red-team-lineage-target-register",
    )
    store.register_surface(
        principal=launcher,
        surface=surface,
        idempotency_key="hosted-red-team-lineage-surface-register",
    )
    for lifecycle in (TargetLifecycle.VALIDATING, TargetLifecycle.READY):
        store.transition_target(
            principal=launcher,
            target_id=target.target_id,
            version=target.version,
            lifecycle=lifecycle,
            idempotency_key=f"hosted-red-team-lineage-target-{lifecycle.value}",
        )

    configuration = _configuration()
    store.stage_hosted_configuration_set(
        principal=launcher,
        configuration=configuration,
        release_sha256="e" * 64,
        rationale="Bind the exact synthetic four-role configuration.",
        idempotency_key="hosted-red-team-lineage-config-stage",
    )
    binding = HostedRunBinding(
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_POLICY_SHA,
        session_generation="generation-20260726",
        provider_model_call_limit=configuration.global_limits.max_calls,
        provider_model_spend_limit_usd=format(configuration.global_limits.max_usd, "f"),
        provider_max_retries=configuration.global_limits.max_retries,
        provider_max_concurrency=configuration.global_limits.max_concurrency,
        provider_timeout_seconds=30.0,
    )
    scope = store.build_scope(
        principal=launcher,
        target_id=target.target_id,
        target_version=target.version,
        surface_id=surface.surface_id,
        surface_version=surface.version,
        corpus_hash="a" * 64,
        caps=SafetyCaps(
            budget_usd=2.0,
            max_attempts_per_run=3,
            target_requests_per_second=0.5,
            run_timeout_seconds=60.0,
        ),
        run_nonce="hosted-red-team-lineage-run-nonce",
        hosted_run=binding,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="hosted-red-team-lineage-request",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="hosted-red-team-lineage-approve",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="hosted-red-team-lineage-launch",
    )
    return store, run.run_id, configuration


def _start_red_team(
    store: ControlPlaneStore,
    run_id: str,
    configuration: HostedConfigurationSet,
    *,
    attempt_id: str | None,
) -> str:
    role_configuration = next(item for item in configuration.roles if item.role == "red_team")
    return store.start_hosted_agent_execution(
        run_id=run_id,
        agent_role="red_team",
        input_payload={"case_ref": "AF-M11-DX-001"},
        provider=role_configuration.provider,
        model=role_configuration.model_id,
        upstream_provider=role_configuration.upstream_provider,
        configuration_set_sha256=configuration.configuration_sha256,
        role_configuration_sha256=role_configuration.configuration_sha256,
        generation_policy_sha256=_POLICY_SHA,
        judge_calibration_id=None,
        judge_calibration_state=None,
        attempt_id=attempt_id,
        detail={"phase": "authorized_case_selection"},
    )


def _record_provider_call(store: ControlPlaneStore, *, execution_id: str) -> str:
    """Perform one real physical provider round-trip's worth of lineage writes."""

    prompt = _PROMPTS["red_team"]
    logical = store.provider_logical_context(
        execution_id=execution_id,
        prompt_version=prompt.version,
        prompt_sha256=prompt.sha256,
    )
    invocation = store.begin_physical_attempt(logical, 1)
    store.finish_physical_attempt(
        invocation,
        ProviderTerminalEventV1(
            invocation_id=invocation.invocation_id,
            physical_sequence=1,
            status="succeeded",
            returned_model=logical.requested_model,
            upstream_provider="Chutes",
            provider_request_id="gen-hosted-lineage-1",
            input_tokens=300,
            output_tokens=3_710,
            reasoning_tokens=1,
            cost_measurement_state="measured",
            measured_cost_usd=Decimal("0.011268"),
            error_code=None,
            finished_at=datetime.datetime.now(datetime.UTC),
        ),
    )
    return invocation.invocation_id


def _seed_attempt(store: ControlPlaneStore, run_id: str, *, ordinal: int = 0) -> str:
    attempt = store.ensure_campaign_attempt(
        run_id=run_id,
        ordinal=ordinal,
        case_id="AF-M11-DX-001",
        case_content_hash="c" * 64,
        category="data_exfiltration",
        severity="critical",
        attack_class="invariant",
        owasp_mappings=[
            {
                "id": "A01",
                "name": "Broken Access Control",
                "version": "2021",
                "framework": "OWASP Web",
            }
        ],
        fixture_provenance={
            "source": "hand_authored",
            "fixture_id": "synthetic-clinical-context-v1",
            "classification": "synthetic",
            "fixture_version": "1.0.0",
            "contains_real_phi": False,
        },
        source_kind="m11_seed",
        workload_instance_id="BASE-000",
        review_record_sha256="e" * 64,
        source_generation_sha256="f" * 64,
    )
    return attempt.attempt_id


# ---------------------------------------------------------------------------------------
# The new chronology: attempt first, then every hosted row is born carrying its id.
# ---------------------------------------------------------------------------------------


def test_hosted_chronology_shares_one_attempt_id_across_every_lineage_table(
    migrated_db: Engine,
) -> None:
    """agent_executions, provider_call_invocations and provider_call_events all agree.

    This is the exact order the Runner now uses on the hosted path. Nothing is bound after the
    fact, so no guard is challenged and the four tables cannot disagree.
    """

    store, run_id, configuration = _authorized_run(migrated_db)

    attempt_id = _seed_attempt(store, run_id)
    execution_id = _start_red_team(store, run_id, configuration, attempt_id=attempt_id)
    invocation_id = _record_provider_call(store, execution_id=execution_id)
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"case_ref": "AF-M11-DX-001"},
        detail={"phase": "authorized_case_selection"},
    )

    with migrated_db.connect() as connection:
        execution = (
            connection.execute(
                text(
                    "SELECT attempt_id, status, agent_role FROM agent_executions "
                    "WHERE execution_id = :execution"
                ),
                {"execution": execution_id},
            )
            .mappings()
            .one()
        )
        invocation_attempts = (
            connection.execute(
                text(
                    "SELECT ca.attempt_id FROM provider_call_invocations pci "
                    "JOIN agent_executions ae "
                    "ON ae.execution_id = pci.logical_execution_id "
                    "JOIN campaign_attempts ca "
                    "ON ca.attempt_id = ae.attempt_id AND ca.run_id = ae.campaign_run_id "
                    "WHERE pci.invocation_id = :invocation"
                ),
                {"invocation": invocation_id},
            )
            .scalars()
            .all()
        )
        event_status = connection.execute(
            text("SELECT status FROM provider_call_events WHERE invocation_id = :invocation"),
            {"invocation": invocation_id},
        ).scalar_one()
        persisted_attempts = (
            connection.execute(
                text("SELECT attempt_id FROM campaign_attempts WHERE run_id = :run"),
                {"run": run_id},
            )
            .scalars()
            .all()
        )

    assert execution["agent_role"] == "red_team"
    # The execution terminalizes successfully — the selection genuinely worked.
    assert execution["status"] == "succeeded"
    # One attempt id, shared by every lineage row rather than reconciled afterwards.
    assert execution["attempt_id"] == attempt_id
    assert invocation_attempts == [attempt_id]
    assert persisted_attempts == [attempt_id]
    assert event_status == "succeeded"


def test_the_attempt_exists_before_the_provider_row_not_after_it(migrated_db: Engine) -> None:
    """Ordering, not just the end state: the attempt predates the provider invocation."""

    store, run_id, configuration = _authorized_run(migrated_db)

    attempt_id = _seed_attempt(store, run_id)
    execution_id = _start_red_team(store, run_id, configuration, attempt_id=attempt_id)
    invocation_id = _record_provider_call(store, execution_id=execution_id)

    with migrated_db.connect() as connection:
        attempt_created = connection.execute(
            text("SELECT created_at FROM campaign_attempts WHERE attempt_id = :attempt"),
            {"attempt": attempt_id},
        ).scalar_one()
        invocation_started = connection.execute(
            text("SELECT started_at FROM provider_call_invocations WHERE invocation_id = :inv"),
            {"inv": invocation_id},
        ).scalar_one()

    assert attempt_created <= invocation_started


# ---------------------------------------------------------------------------------------
# Regression: the old post-provider bind still fails, and is no longer reachable.
# ---------------------------------------------------------------------------------------


def test_binding_after_a_successful_hosted_call_is_still_refused(migrated_db: Engine) -> None:
    """The exact production failure, reproduced.

    Terminalizing first makes the execution non-``running``; that alone is fatal. Keeping this
    red proves the fix was a chronology change and not a relaxed guard.
    """

    store, run_id, configuration = _authorized_run(migrated_db)

    attempt_id = _seed_attempt(store, run_id)
    execution_id = _start_red_team(store, run_id, configuration, attempt_id=None)
    _record_provider_call(store, execution_id=execution_id)
    store.finish_hosted_agent_execution(
        execution_id=execution_id,
        status="succeeded",
        output_payload={"case_ref": "AF-M11-DX-001"},
        detail={"phase": "authorized_case_selection"},
    )

    with pytest.raises(RecordConflictError, match="only a running agent execution may bind"):
        store.bind_agent_execution_attempt(
            execution_id=execution_id,
            run_id=run_id,
            attempt_id=attempt_id,
        )


def test_binding_after_a_provider_invocation_is_refused_even_while_running(
    migrated_db: Engine,
) -> None:
    """The second, independent guard: lineage may not be rewritten once a call exists.

    Even if the hosted path had left the execution ``running``, binding would still fail — so
    "terminalize later" was never an available fix either.
    """

    store, run_id, configuration = _authorized_run(migrated_db)

    attempt_id = _seed_attempt(store, run_id)
    execution_id = _start_red_team(store, run_id, configuration, attempt_id=None)
    _record_provider_call(store, execution_id=execution_id)

    with pytest.raises(RecordConflictError, match="after provider invocation"):
        store.bind_agent_execution_attempt(
            execution_id=execution_id,
            run_id=run_id,
            attempt_id=attempt_id,
        )


def test_the_deterministic_bind_path_still_works(migrated_db: Engine) -> None:
    """The non-hosted chronology is untouched: start, select, then bind while still running."""

    store, run_id, configuration = _authorized_run(migrated_db)

    attempt_id = _seed_attempt(store, run_id)
    execution_id = _start_red_team(store, run_id, configuration, attempt_id=None)

    store.bind_agent_execution_attempt(
        execution_id=execution_id,
        run_id=run_id,
        attempt_id=attempt_id,
    )

    with migrated_db.connect() as connection:
        bound = connection.execute(
            text("SELECT attempt_id FROM agent_executions WHERE execution_id = :execution"),
            {"execution": execution_id},
        ).scalar_one()
    assert bound == attempt_id


# ---------------------------------------------------------------------------------------
# The unsupported hosted path is refused by type, not silently de-lineaged.
# ---------------------------------------------------------------------------------------


def test_unsupported_hosted_selection_is_a_typed_dispatch_refusal() -> None:
    assert issubclass(HostedLineageUnsupported, DispatchUnavailable)


# ---------------------------------------------------------------------------------------
# The Runner's own wiring: the attempt id reaches the hosted invocation, and nothing binds
# afterwards. Without these, the store-level tests above would still pass on the broken code.
# ---------------------------------------------------------------------------------------


class _RecordingStore:
    """Captures exactly what the lifecycle hands the store when a hosted role starts."""

    def __init__(self) -> None:
        self.starts: list[dict[str, object]] = []

    def start_hosted_agent_execution(self, **values: object) -> str:
        self.starts.append(dict(values))
        return "execution-recorded"

    def finish_hosted_agent_execution(self, **_values: object) -> None:  # pragma: no cover
        raise AssertionError("this test never terminalizes")


class _OpenLangfuse:
    def begin_agent(self, **_values: object) -> bool:
        return True


def _recording_lifecycle() -> tuple[_RecordingStore, object]:
    from agentforge.agents.judge.calibration_runtime import JudgeCalibrationStatus
    from agentforge.runner import _DurableHostedExecutionLifecycle

    store = _RecordingStore()
    lifecycle = _DurableHostedExecutionLifecycle(
        store=store,  # type: ignore[arg-type]
        telemetry=_OpenLangfuse(),  # type: ignore[arg-type]
        run_id="run-attempt-lineage",
        calibration=JudgeCalibrationStatus(
            state="unavailable",
            calibration_id=None,
            metrics=None,
            reason_codes=("calibration_artifact_unavailable",),
            model_authoritative=False,
            source="none",
        ),
    )
    return store, lifecycle


def test_an_attempt_id_given_to_invocation_reaches_the_execution_row() -> None:
    """The mechanism the hosted path now depends on: born bound, never bound later."""

    store, lifecycle = _recording_lifecycle()

    with lifecycle.invocation(  # type: ignore[attr-defined]
        role="red_team",
        attempt_id="attempt-abc",
        detail={"phase": "authorized_case_selection"},
    ):
        lifecycle.start(  # type: ignore[attr-defined]
            role="red_team",
            parent_execution_id=None,
            input_payload={"case_ref": "AF-M11-DX-001"},
            provider="openrouter",
            model="qwen/qwen3.5-397b-a17b",
            upstream_provider="chutes",
            configuration_sha256="a" * 64,
            role_configuration_sha256="b" * 64,
            generation_policy_sha256=_POLICY_SHA,
            judge_calibration_id=None,
        )

    assert len(store.starts) == 1
    assert store.starts[0]["attempt_id"] == "attempt-abc"


def test_omitting_the_attempt_id_is_what_produced_an_unbound_execution() -> None:
    """The pre-fix call shape, kept as the contrast case."""

    store, lifecycle = _recording_lifecycle()

    with lifecycle.invocation(  # type: ignore[attr-defined]
        role="red_team",
        detail={"phase": "authorized_case_selection"},
    ):
        lifecycle.start(  # type: ignore[attr-defined]
            role="red_team",
            parent_execution_id=None,
            input_payload={"case_ref": "AF-M11-DX-001"},
            provider="openrouter",
            model="qwen/qwen3.5-397b-a17b",
            upstream_provider="chutes",
            configuration_sha256="a" * 64,
            role_configuration_sha256="b" * 64,
            generation_policy_sha256=_POLICY_SHA,
            judge_calibration_id=None,
        )

    assert store.starts[0]["attempt_id"] is None


def _red_team_invocation_call() -> object:
    """The AST node for the Runner's hosted Red Team ``lifecycle.invocation(...)`` call."""

    import ast
    import inspect

    import agentforge.runner as runner_module

    tree = ast.parse(inspect.getsource(runner_module))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "invocation"):
            continue
        roles = [
            kw.value.value
            for kw in node.keywords
            if kw.arg == "role" and isinstance(kw.value, ast.Constant)
        ]
        if roles == ["red_team"]:
            return node
    raise AssertionError("the hosted Red Team invocation call was not found in runner.py")


def test_the_runner_passes_an_attempt_id_into_the_hosted_red_team_invocation() -> None:
    """Structural, because the alternative is a live provider call.

    If this regresses to the pre-fix shape, the hosted execution is created unbound again and
    every live campaign dies at the first successful selection.
    """

    import ast

    call = _red_team_invocation_call()
    keywords = {kw.arg for kw in call.keywords}  # type: ignore[attr-defined]
    assert "attempt_id" in keywords, "hosted Red Team must be born bound to its attempt"
    attempt_kw = next(
        kw
        for kw in call.keywords  # type: ignore[attr-defined]
        if kw.arg == "attempt_id"
    )
    # It must be the pre-created attempt, not a literal None.
    assert isinstance(attempt_kw.value, ast.Name)
    assert attempt_kw.value.id == "prebound_attempt_id"


def test_the_runner_binds_after_the_fact_only_on_the_deterministic_path() -> None:
    """``_bind_agent_execution_attempt`` must be unreachable once a provider call has run.

    Asserted over the AST: the single bind site must sit in the ``else`` of a branch keyed on
    ``prebound_attempt``. A dedent that made it unconditional again would move it out of that
    ``orelse`` body and fail here, which a substring check would not catch.
    """

    import ast
    import inspect
    import textwrap

    from agentforge.runner import DurableCampaignRunner

    tree = ast.parse(textwrap.dedent(inspect.getsource(DurableCampaignRunner._execute_prepared)))

    def _bind_calls(nodes) -> int:
        total = 0
        for node in nodes:
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and inner.func.attr == "_bind_agent_execution_attempt"
                ):
                    total += 1
        return total

    assert _bind_calls([tree]) == 1, "exactly one bind site — the deterministic branch"

    guarded = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        if "prebound_attempt" not in ast.dump(node.test):
            continue
        # Hosted branch must never bind; the deterministic else-branch is the only one that may.
        assert _bind_calls(node.body) == 0, "the hosted path must not bind after the fact"
        guarded += _bind_calls(node.orelse)
    assert guarded == 1, "the bind must live in the else of the prebound-attempt branch"


def test_every_live_100_workload_is_an_exact_manifest_workload() -> None:
    """The supported hosted path is exactly the three-batch live-100 suite plus the whole."""

    for batch_id in LIVE_100_BATCH_IDS:
        assert batch_id in _EXACT_MANIFEST_WORKLOAD_IDS
    assert len(LIVE_100_BATCH_IDS) == 3


def test_the_mvp_corpus_is_not_an_exact_manifest_workload() -> None:
    """So a hosted run against it takes the typed refusal rather than inventing lineage."""

    assert load_mvp_corpus().corpus_id not in _EXACT_MANIFEST_WORKLOAD_IDS


# ---------------------------------------------------------------------------------------
# The reliability change and its digest.
# ---------------------------------------------------------------------------------------


def test_red_team_timeout_is_180_seconds_with_token_bounds_unchanged() -> None:
    bounds = DEFAULT_HOSTED_GENERATION_POLICY.call_bounds["red_team"]

    assert bounds.timeout_seconds == 180.0
    # The proven constraint was time, not tokens. These stay exactly where they were.
    assert bounds.input_tokens == 32_768
    assert bounds.output_tokens == 8_192
    assert bounds.reasoning_tokens == 8_192


def test_exact_caps_contract_still_demands_zero_target_retries() -> None:
    """The hotfix widened a timeout, not retry authority.

    Read the guard's own source rather than a copy of the rule, so deleting the condition fails
    this test instead of silently passing it.
    """

    import inspect

    from agentforge.runner import DurableCampaignRunner

    preflight_source = inspect.getsource(DurableCampaignRunner.preflight)
    assert "caps.target_retries_per_turn != 0" in preflight_source
    assert "exact_request_caps_mismatch" in preflight_source


def test_policy_digest_changed_and_is_the_only_resolvable_policy() -> None:
    """A digest change is a deploy-coupling event: Web and Runner must agree on it."""

    from agentforge.agents.hosted_policy import resolve_hosted_generation_policy

    digest = DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256
    # The pre-fix digest, pinned so an accidental revert of the timeout is loud.
    assert digest != "ed601d546a09782dab3b3f3215cc3071de0952edd572e5286d9064bc9b2995cc"
    assert resolve_hosted_generation_policy(digest) is DEFAULT_HOSTED_GENERATION_POLICY


def test_the_digest_travels_onto_every_hosted_execution_row(migrated_db: Engine) -> None:
    """Digest propagation: what the policy computes is what the lineage records."""

    store, run_id, configuration = _authorized_run(migrated_db)
    attempt_id = _seed_attempt(store, run_id)
    execution_id = _start_red_team(store, run_id, configuration, attempt_id=attempt_id)
    invocation_id = _record_provider_call(store, execution_id=execution_id)

    with migrated_db.connect() as connection:
        execution_digest = connection.execute(
            text(
                "SELECT generation_policy_sha256 FROM agent_executions "
                "WHERE execution_id = :execution"
            ),
            {"execution": execution_id},
        ).scalar_one()
        invocation_digest = connection.execute(
            text(
                "SELECT generation_policy_sha256 FROM provider_call_invocations "
                "WHERE invocation_id = :invocation"
            ),
            {"invocation": invocation_id},
        ).scalar_one()

    assert execution_digest == DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256
    assert invocation_digest == DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256
