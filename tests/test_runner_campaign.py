"""Authoritative synthetic campaign through queue, Runner, Judge, and result repositories."""

from __future__ import annotations

import contextlib
import dataclasses
import datetime
import hashlib
import json
import time
from decimal import Decimal
from types import SimpleNamespace
from typing import NamedTuple

import pytest
from sqlalchemy import Engine, text

from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.judge.calibration_runtime import JudgeCalibrationStatus
from agentforge.agents.judge.envelope import EvidenceEnvelopeBuilder
from agentforge.api.postgres import PostgresApiBackend
from agentforge.auth.permissions import CAMPAIGN_AUTHORIZE, CAMPAIGN_LAUNCH
from agentforge.auth.principal import Principal
from agentforge.campaign.coordinator import CampaignAbort
from agentforge.campaign.corpus import (
    load_full_scan_corpus,
    load_mvp_corpus,
    verified_case_payload,
)
from agentforge.contracts import is_valid
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.policy.recorder import ExecutionRecorder
from agentforge.policy.scoped_credentials import (
    CredentialResolutionError,
    SealedEnvironmentCredentialResolver,
    SessionLeaseMetadata,
)
from agentforge.runner import (
    DispatchUnavailable,
    DurableCampaignRunner,
    PreflightReport,
    _campaign_session_required_until,
    _DurableHostedExecutionLifecycle,
    _PreManifestHostedJudge,
    _reconcile_runner_evaluator,
    _require_hosted_workload_capacity,
    _sanitize_hosted_transcript,
)
from agentforge.secrets import Secret
from agentforge.storage.queue import JobRecord, LogicalQueue, PostgresJobQueue
from agentforge.target.catalog import CatalogEntry, TrustedTargetCatalog
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    ExecutionProfile,
    OwaspMapping,
    RiskLevel,
    SafetyCaps,
    SurfaceKind,
    SurfaceOperationTemplate,
    SurfacePolicy,
    TargetDefinition,
    TargetEnvironment,
)

ORG_ID = "org_RunnerFixture"
_LEASE = datetime.timedelta(minutes=10)


class _AdvancingClock:
    def __init__(self) -> None:
        self.value = time.time()

    def now(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _RecordingAgentTelemetry:
    """Network-free recorder for Runner-to-outbound lifecycle assertions."""

    def __init__(self) -> None:
        self.starts: list[dict[str, object]] = []
        self.finishes: list[dict[str, object]] = []
        self.flush_count = 0
        self.heartbeat_count = 0
        self.released_campaigns: list[str] = []

    def begin_agent(self, **values: object) -> None:
        self.starts.append(dict(values))

    def finish_agent(self, **values: object) -> None:
        self.finishes.append(dict(values))

    def flush(self) -> None:
        self.flush_count += 1

    def heartbeat(self, **_values: object) -> None:
        self.heartbeat_count += 1

    def release_campaign(self, campaign_run_id: str) -> None:
        self.released_campaigns.append(campaign_run_id)


def test_hosted_evaluator_transcript_exactly_redacts_the_sealed_target_session() -> None:
    raw_session = "opaque-session-value-7f6c2b"
    transcript = f'{{"answer":"safe","echo":"{raw_session}"}}'

    sanitized = _sanitize_hosted_transcript(
        transcript,
        target_credential=Secret(raw_session),
    )

    assert raw_session not in sanitized
    assert "[REDACTED_TARGET_SESSION]" in sanitized
    assert (
        _sanitize_hosted_transcript(
            "synthetic no-auth response",
            target_credential=None,
        )
        == "synthetic no-auth response"
    )


def _principal(user_id: str, permission: str) -> Principal:
    return Principal(
        user_id=user_id,
        session_id=f"sess_{user_id.removeprefix('user_')}",
        organization_id=ORG_ID,
        organization_role="org:operator",
        organization_permissions=frozenset({permission}),
    )


def test_pre_manifest_hosted_judge_reconciles_before_return_and_preserves_local_evidence() -> None:
    events: list[str] = []
    raw_session = "opaque-session-value-pre-manifest"
    envelope = EvidenceEnvelopeBuilder().build(
        campaign_run_id="run-pre-manifest",
        attempt_id="attempt-pre-manifest",
        transcript=f"Synthetic response echoed {raw_session}.",
        oracle_results=[
            {
                "id": "oracle-synthetic",
                "provenance": "code",
                "hit": False,
            }
        ],
        canary_hits=[],
        policy_decision="allow",
    )
    original = json.loads(json.dumps(envelope))
    deterministic = {
        "schema_version": "1",
        "campaign_run_id": "run-pre-manifest",
        "attempt_id": "attempt-pre-manifest",
        "state": "INDETERMINATE",
        "confidence": 0.0,
        "reason_codes": ["non_oracle_uncalibrated_indeterminate"],
    }
    effective = {
        "schema_version": "1",
        "campaign_run_id": "run-pre-manifest",
        "attempt_id": "attempt-pre-manifest",
        "state": "NO_EXPLOIT_OBSERVED",
        "confidence": 0.93,
        "reason_codes": ["calibrated_negative"],
        "confirmation_source": "calibrated_model",
    }

    class DeterministicJudge:
        def evaluate(self, value: object, *, integrity_ok: bool) -> dict[str, object]:
            events.append("deterministic")
            assert value is envelope
            assert integrity_ok is True
            return dict(deterministic)

    class Evaluator:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def evaluate(self, value: object, **kwargs: object) -> SimpleNamespace:
            events.append("hosted")
            self.calls.append({"envelope": value, **kwargs})
            return SimpleNamespace(execution_id="execution-judge-pre-manifest")

    class Lifecycle:
        def __init__(self) -> None:
            self.invocations: list[dict[str, object]] = []
            self.taken: list[str] = []

        def invocation(self, **kwargs: object) -> contextlib.AbstractContextManager[None]:
            self.invocations.append(dict(kwargs))
            return contextlib.nullcontext()

        def take_judge_reconciliation(self, *, execution_id: str) -> SimpleNamespace:
            events.append("reconcile")
            self.taken.append(execution_id)
            return SimpleNamespace(effective_verdict=effective)

    evaluator = Evaluator()
    lifecycle = Lifecycle()
    executions: list[tuple[str, str]] = []
    bridge = _PreManifestHostedJudge(
        deterministic_judge=DeterministicJudge(),  # type: ignore[arg-type]
        hosted_evaluator=evaluator,  # type: ignore[arg-type]
        lifecycle=lifecycle,  # type: ignore[arg-type]
        calibration=JudgeCalibrationStatus(
            state="enabled",
            calibration_id="JC-" + ("a" * 64),
            metrics={"agreement_rate": 1.0, "false_negative_rate": 0.0},
            reason_codes=(),
            model_authoritative=True,
            source="configured_file",
        ),
        target_credential_resolver=lambda: Secret(raw_session),
        execution_recorder=lambda attempt_id, execution_id: executions.append(
            (attempt_id, execution_id)
        ),
    )

    with bridge.attempt(
        attempt_id="attempt-pre-manifest",
        expected_safe_behavior="The assistant must refuse the synthetic request.",
        parent_execution_id="execution-red-team-pre-manifest",
    ):
        verdict = bridge.evaluate(envelope, integrity_ok=True)

    assert events == ["deterministic", "hosted", "reconcile"]
    assert verdict == effective
    assert envelope == original
    provider_envelope = evaluator.calls[0]["envelope"]
    assert isinstance(provider_envelope, dict)
    assert raw_session not in provider_envelope["hostile"]["transcript"]
    assert "[REDACTED_TARGET_SESSION]" in provider_envelope["hostile"]["transcript"]
    assert provider_envelope["trusted"]["expected_safe_behavior"] == (
        "The assistant must refuse the synthetic request."
    )
    assert evaluator.calls[0]["parent_execution_id"] == ("execution-red-team-pre-manifest")
    assert lifecycle.invocations[0]["ground_truth_verdict"] == deterministic
    assert lifecycle.taken == ["execution-judge-pre-manifest"]
    assert executions == [("attempt-pre-manifest", "execution-judge-pre-manifest")]


@pytest.mark.parametrize(
    (
        "calibration_state",
        "model_authoritative",
        "deterministic_state",
        "confirmation_source",
        "assessment_state",
        "expected_state",
        "expected_authority",
        "expected_authority_basis",
    ),
    [
        (
            "failed",
            False,
            "INDETERMINATE",
            None,
            "NO_EXPLOIT_OBSERVED",
            "INDETERMINATE",
            "oracle",
            "deterministic_ground_truth",
        ),
        (
            "enabled",
            True,
            "INDETERMINATE",
            None,
            "NO_EXPLOIT_OBSERVED",
            "NO_EXPLOIT_OBSERVED",
            "model",
            "calibrated_model",
        ),
        (
            "enabled",
            True,
            "EXPLOIT_CONFIRMED",
            "oracle",
            "NO_EXPLOIT_OBSERVED",
            "EXPLOIT_CONFIRMED",
            "oracle",
            "oracle_canary",
        ),
    ],
)
def test_pre_manifest_hosted_judge_applies_exact_authority_and_records_lineage(
    calibration_state: str,
    model_authoritative: bool,
    deterministic_state: str,
    confirmation_source: str | None,
    assessment_state: str,
    expected_state: str,
    expected_authority: str,
    expected_authority_basis: str,
) -> None:
    attempt_id = f"attempt-{calibration_state}-{deterministic_state.lower()}"
    deterministic: dict[str, object] = {
        "schema_version": "1",
        "campaign_run_id": "run-authority-matrix",
        "attempt_id": attempt_id,
        "state": deterministic_state,
        "confidence": 1.0 if deterministic_state == "EXPLOIT_CONFIRMED" else 0.0,
        "reason_codes": [
            (
                "oracle_confirmed"
                if deterministic_state == "EXPLOIT_CONFIRMED"
                else "non_oracle_uncalibrated_indeterminate"
            )
        ],
    }
    if confirmation_source is not None:
        deterministic["confirmation_source"] = confirmation_source
    assessment = {
        "state": assessment_state,
        "confidence": 0.91,
        "rationale": "The sanitized synthetic evidence supports this assessment.",
        "criteria_hits": ["expected_invariant_observed"],
        "error_code": None,
    }
    calibration = JudgeCalibrationStatus(
        state=calibration_state,  # type: ignore[arg-type]
        calibration_id="JC-" + ("b" * 64),
        metrics={"agreement_rate": 1.0, "false_negative_rate": 0.0},
        reason_codes=(),
        model_authoritative=model_authoritative,
        source="configured_file",
    )

    class Store:
        def __init__(self) -> None:
            self.finishes: list[dict[str, object]] = []

        def start_hosted_agent_execution(self, **_values: object) -> str:
            return f"execution-{attempt_id}"

        def finish_hosted_agent_execution(self, **values: object) -> None:
            self.finishes.append(dict(values))

    class Telemetry:
        def begin_agent(self, **_values: object) -> bool:
            return True

        def finish_agent(self, **_values: object) -> None:
            return None

        def flush(self) -> None:
            return None

        def heartbeat(self) -> None:
            return None

    store = Store()
    lifecycle = _DurableHostedExecutionLifecycle(
        store=store,  # type: ignore[arg-type]
        telemetry=Telemetry(),  # type: ignore[arg-type]
        run_id="run-authority-matrix",
        calibration=calibration,
    )

    class DeterministicJudge:
        def evaluate(
            self,
            _envelope: object,
            *,
            integrity_ok: bool,
        ) -> dict[str, object]:
            assert integrity_ok is True
            return dict(deterministic)

    class Evaluator:
        def evaluate(self, _envelope: object, **values: object) -> SimpleNamespace:
            execution_id = lifecycle.start(
                role="judge",
                parent_execution_id=values["parent_execution_id"],  # type: ignore[arg-type]
                input_payload={"sanitized": True},
                provider="openrouter",
                model="google/gemini-2.5-pro",
                upstream_provider="google",
                configuration_sha256="c" * 64,
                role_configuration_sha256="d" * 64,
                generation_policy_sha256="e" * 64,
                judge_calibration_id=values["judge_calibration_id"],  # type: ignore[arg-type]
            )
            lifecycle.finish(
                execution_id=execution_id,
                status="succeeded",
                output_payload=assessment,
                lineage=SimpleNamespace(
                    returned_model="google/gemini-2.5-pro",
                    upstream_provider="google",
                    provider_request_id=f"provider-{attempt_id}",
                    input_tokens=100,
                    output_tokens=20,
                    reasoning_tokens=5,
                    measured_cost_usd="0.01",
                    configuration_sha256="c" * 64,
                    role_configuration_sha256="d" * 64,
                    generation_policy_sha256="e" * 64,
                    physical_attempts=1,
                ),
                error_code=None,
            )
            return SimpleNamespace(execution_id=execution_id)

    executions: list[tuple[str, str]] = []
    bridge = _PreManifestHostedJudge(
        deterministic_judge=DeterministicJudge(),  # type: ignore[arg-type]
        hosted_evaluator=Evaluator(),  # type: ignore[arg-type]
        lifecycle=lifecycle,
        calibration=calibration,
        target_credential_resolver=lambda: None,
        execution_recorder=lambda observed_attempt, execution_id: executions.append(
            (observed_attempt, execution_id)
        ),
    )
    envelope = EvidenceEnvelopeBuilder().build(
        campaign_run_id="run-authority-matrix",
        attempt_id=attempt_id,
        transcript="Sanitized synthetic target response.",
        oracle_results=[],
        canary_hits=[],
        policy_decision="allow",
    )

    with bridge.attempt(
        attempt_id=attempt_id,
        expected_safe_behavior="The assistant preserves the synthetic policy boundary.",
        parent_execution_id="execution-red-team-authority-matrix",
    ):
        effective = bridge.evaluate(envelope, integrity_ok=True)

    assert effective["state"] == expected_state
    assert store.finishes[0]["decision_authority"] == expected_authority
    detail = store.finishes[0]["detail"]
    assert isinstance(detail, dict)
    assert detail["decision_authority_basis"] == expected_authority_basis
    assert executions == [(attempt_id, f"execution-{attempt_id}")]


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE agent_executions, agent_configuration_versions, "
                "regression_dispositions, vuln_reports, "
                "campaign_run_summaries, finding_evidence_links, "
                "finding_decision_events, finding, verdict, attempt_result, audit_events, "
                "command_idempotency, campaign_attempts, campaign_run_events, campaign_runs, "
                "campaign_authorization_decisions, campaign_authorization_requests, "
                "surface_state_events, attack_surface_definitions, surface_identities, "
                "target_lifecycle_events, target_definitions, target_identities, jobs "
                "RESTART IDENTITY CASCADE"
            )
        )


def _live_chat_prepared(
    *,
    auth_mode: AuthMode = AuthMode.SESSION,
    payload_profile: str = "copilot_chat",
) -> SimpleNamespace:
    """Minimal trusted composition input; it never constructs a client or opens a socket."""

    scope = SimpleNamespace(
        execution_profile=ExecutionProfile.LIVE,
        auth_mode=auth_mode,
    )
    policy = SimpleNamespace(
        request_timeout_seconds=30.0,
        redirect_policy="deny",
        response_size_limit_bytes=262_144,
        allowed_content_types=("application/json",),
        allow_private_destination=False,
        payload_profile=payload_profile,
    )
    return SimpleNamespace(
        authorized=SimpleNamespace(scope=scope),
        entry=SimpleNamespace(
            target=SimpleNamespace(base_url="https://copilot.example.test"),
            transport_policy=policy,
        ),
        surface=SimpleNamespace(method="POST", relative_path="chat"),
    )


def test_live_runner_composes_approved_bruno_chat_contract_without_network() -> None:
    runner = object.__new__(DurableCampaignRunner)

    adapter = runner._adapter(_live_chat_prepared())

    assert adapter.base_url == "https://copilot.example.test"
    assert adapter.relative_path == "chat"
    assert adapter.payload_profile == "copilot_chat"
    assert adapter.credential is None


def test_live_runner_refuses_chat_profile_without_session_bound_scope() -> None:
    runner = object.__new__(DurableCampaignRunner)

    with pytest.raises(DispatchUnavailable, match="copilot_chat_scope_invalid"):
        runner._adapter(_live_chat_prepared(auth_mode=AuthMode.BEARER))


def test_live_runner_refuses_catalog_profile_that_differs_from_approved_scope() -> None:
    runner = object.__new__(DurableCampaignRunner)

    with pytest.raises(DispatchUnavailable, match="payload_profile_scope_mismatch"):
        runner._adapter(_live_chat_prepared(payload_profile="openemr_turns"))


def test_live_runner_refuses_v2_policy_until_physical_operation_gateway_is_integrated() -> None:
    runner = object.__new__(DurableCampaignRunner)
    prepared = _live_chat_prepared()
    prepared.entry.transport_policy = None

    with pytest.raises(DispatchUnavailable, match="surface_policy_dispatch_not_integrated"):
        runner._adapter(prepared)


def test_live_runner_preflight_refuses_v2_policy_before_side_effects(
    migrated_db: Engine,
    tmp_path,
) -> None:
    _clean(migrated_db)
    launcher = _principal("user_RunnerV2Launcher", CAMPAIGN_LAUNCH)
    approver = _principal("user_RunnerV2Approver", CAMPAIGN_AUTHORIZE)
    corpus = load_mvp_corpus()
    started = datetime.datetime.now(datetime.UTC)
    credential_ref = "secretref://production/clinical-copilot-week2/session/generation-v2-preflight"
    caps = SafetyCaps(
        budget_usd=1.0,
        max_attempts_per_run=len(corpus.cases),
        target_requests_per_second=100.0,
        run_timeout_seconds=300.0,
        logical_case_limit=14,
        physical_request_limit=51,
        target_retries_per_turn=2,
    )
    target = TargetDefinition(
        target_id="clinical-copilot-week2-v2-preflight",
        name="Clinical Co-Pilot v2 preflight refusal",
        version="2.0.0",
        adapter_kind="openemr",
        environment=TargetEnvironment.PRODUCTION,
        base_url="https://copilot.example.test",
        allowlisted_hosts=("copilot.example.test",),
        auth_mode=AuthMode.SESSION,
        credential_ref=credential_ref,
        synthetic_data_only=True,
        synthetic_data_attestation_ref="attestation://agentforge/synthetic-v2-preflight",
        # Both seeded literals: the corpus carries a patient-beta AND a system-prompt canary case,
        # and preflight now refuses (canary_literal_not_seeded) when a target does not declare every
        # literal its corpus expects. Declaring one would model a target where the system-prompt
        # cases can never fire.
        canary_refs=(
            "oracle://agentforge/SYNTH_CANARY_PATIENT_BETA_8C1E",
            "oracle://agentforge/SYNTH_CANARY_SYSTEM_PROMPT_4D2B",
        ),
        oracle_refs=("oracle://agentforge/v2-preflight-refusal",),
        safety_caps=caps,
    )
    operation = SurfaceOperationTemplate(
        operation_class="chat",
        method="POST",
        relative_path="chat",
        request_content_type="application/json",
        response_content_types=("application/json",),
        credential_placement="json",
        credential_field_name="session_id",
        retry_count=0,
        maximum_logical_operations=1,
    )
    policy = SurfacePolicy(
        schema="agentforge.target-surface-policy",
        schema_version=2,
        adapter_profile="copilot_chat",
        auth_mode=AuthMode.SESSION,
        credential_ref=credential_ref,
        explicit_no_auth=False,
        redirect_policy="deny",
        response_size_limit_bytes=262_144,
        request_timeout_seconds=30.0,
        tls_required=True,
        operation_templates=(operation,),
        maximum_logical_operations=1,
        physical_request_limit=1,
        fixture_descriptors=(),
    )
    surface = AttackSurfaceDefinition(
        surface_id="clinical-copilot-week2-chat-v2-preflight",
        version="2.0.0",
        target_id=target.target_id,
        target_version=target.version,
        kind=SurfaceKind.CHAT,
        protocol="https",
        method="POST",
        relative_path="chat",
        trust_boundary="live-target",
        authentication_required=True,
        risk=RiskLevel.HIGH,
        owasp_mappings=(
            OwaspMapping(
                framework="OWASP Web",
                version="2021",
                identifier="A01",
                name="Broken Access Control",
            ),
        ),
        oracle_refs=("oracle://agentforge/v2-preflight-refusal",),
        enabled=True,
        surface_policy=policy,
        surface_policy_sha256=policy.policy_hash(),
    )
    entry = CatalogEntry(
        target=target,
        surfaces=(surface,),
        transport_policy=None,
        ownership_authorization_ref="authorization://agentforge/v2-preflight-owner",
    )
    catalog = TrustedTargetCatalog((entry,))
    store = ControlPlaneStore(migrated_db, environment="production")
    catalog.synchronize(store, organization_id=ORG_ID)
    scope = store.build_scope(
        principal=launcher,
        target_id=target.target_id,
        target_version=target.version,
        surface_id=surface.surface_id,
        surface_version=surface.version,
        corpus_id=corpus.corpus_id,
        corpus_hash=corpus.content_hash,
        caps=caps,
        run_nonce="runner-v2-preflight-nonce-0001",
        execution_profile=ExecutionProfile.LIVE,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=started + datetime.timedelta(hours=1),
        idempotency_key="runner-v2-preflight-request-0001",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="runner-v2-preflight-approve-0001",
    )
    store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="runner-v2-preflight-launch-0001",
    )
    session_value = "synthetic-v2-preflight-session"
    credentials = SealedEnvironmentCredentialResolver(
        {credential_ref: "RUNNER_V2_PREFLIGHT_SESSION"},
        environment={"RUNNER_V2_PREFLIGHT_SESSION": session_value},
        session_metadata={
            credential_ref: SessionLeaseMetadata(
                generation=credential_ref.rsplit("/", 1)[-1],
                expires_at=started + datetime.timedelta(hours=2),
                value_sha256=hashlib.sha256(session_value.encode()).hexdigest(),
                expiry_source="operator_conservative_lease",
            )
        },
    )
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="production",
        corpus=corpus,
        catalog=catalog,
        credentials=credentials,
        clock=SimpleNamespace(now=started.timestamp),
        manifest_root=tmp_path,
    )
    job = _claim_enqueued_job(runner, worker_id="runner-v2-preflight-test")

    side_effect_calls: list[str] = []

    def forbidden(label: str):
        def invoke(*_args: object, **_kwargs: object) -> object:
            side_effect_calls.append(label)
            raise AssertionError(f"preflight reached forbidden {label} side effect")

        return invoke

    runner.credentials = SimpleNamespace(  # type: ignore[assignment]
        has=credentials.has,
        session_ready=credentials.session_ready,
        lease=forbidden("credential_lease"),
    )
    runner._execute_prepared = forbidden("execute_prepared")  # type: ignore[method-assign]
    runner._adapter = forbidden("adapter")  # type: ignore[method-assign]

    report, prepared = runner.preflight(job)

    assert report.blockers == ("surface_policy_dispatch_not_integrated",)
    assert prepared is None
    assert side_effect_calls == []
    with pytest.raises(
        DispatchUnavailable,
        match=r"^preflight_blocked:surface_policy_dispatch_not_integrated$",
    ):
        runner.execute_claimed(job)
    assert side_effect_calls == []


def test_synthetic_catalog_versions_the_fourteen_case_safety_contract() -> None:
    catalog = TrustedTargetCatalog.from_environment("staging")

    entry, surface = catalog.resolve(target_id="synthetic-copilot", surface_id="synthetic-chat")

    assert entry.target.version == "1.1.0"
    assert entry.target.safety_caps.max_attempts_per_run == 14
    assert surface.version == "1.1.0"
    assert surface.target_version == entry.target.version


def test_authorization_and_session_must_cover_the_full_run_timeout() -> None:
    started = datetime.datetime(2026, 7, 22, 18, 0, tzinfo=datetime.UTC)
    scope = SimpleNamespace(caps=SimpleNamespace(run_timeout_seconds=300.0))

    authorization_first = SimpleNamespace(
        scope=scope,
        expires_at=started + datetime.timedelta(seconds=120),
    )
    timeout_first = SimpleNamespace(
        scope=scope,
        expires_at=started + datetime.timedelta(seconds=900),
    )

    with pytest.raises(DispatchUnavailable, match="campaign_session_window_invalid"):
        _campaign_session_required_until(
            authorization_first,
            now=started.timestamp(),
        )
    assert _campaign_session_required_until(
        timeout_first,
        now=started.timestamp(),
    ) == started + datetime.timedelta(seconds=300)
    with pytest.raises(DispatchUnavailable, match="campaign_session_window_invalid"):
        _campaign_session_required_until(
            SimpleNamespace(scope=scope, expires_at=started),
            now=started.timestamp(),
        )


def test_runner_pins_and_releases_session_resources_on_campaign_abort() -> None:
    reference = "secretref://staging/openemr/session/generation-test"
    session_value = "synthetic-runner-session-0001"
    environment = {"OPENEMR_TEST_SESSION": session_value}
    started = datetime.datetime(2026, 7, 22, 18, 0, tzinfo=datetime.UTC)
    credentials = SealedEnvironmentCredentialResolver(
        {reference: "OPENEMR_TEST_SESSION"},
        environment=environment,
        session_metadata={
            reference: SessionLeaseMetadata(
                generation="generation-test",
                expires_at=started + datetime.timedelta(minutes=10),
                value_sha256=hashlib.sha256(session_value.encode()).hexdigest(),
                expiry_source="operator_conservative_lease",
            )
        },
    )
    prepared = SimpleNamespace(
        authorized=SimpleNamespace(
            scope=SimpleNamespace(
                credential_ref=reference,
                execution_profile=ExecutionProfile.LIVE,
                auth_mode=AuthMode.SESSION,
                caps=SimpleNamespace(run_timeout_seconds=300.0),
            ),
            expires_at=started + datetime.timedelta(minutes=8),
        )
    )

    class ClosableAdapter:
        def __init__(self) -> None:
            self.credential = None
            self.closed = False

        def close(self) -> None:
            self.credential = None
            self.closed = True

    adapter = ClosableAdapter()
    captured: list[object] = []
    runner = object.__new__(DurableCampaignRunner)
    runner.clock = SimpleNamespace(now=started.timestamp)
    runner.credentials = credentials
    runner.preflight = lambda _job: (PreflightReport(()), prepared)
    runner._adapter = lambda _prepared: adapter

    def fail_after_resolution(_job: object, _prepared: object, lease: object):
        live_adapter = runner._adapter(_prepared)
        runner._campaign_adapter = live_adapter
        first = lease.resolve(reference)
        environment["OPENEMR_TEST_SESSION"] = "synthetic-rotated-session"
        second = lease.resolve(reference)
        assert first is second
        live_adapter.credential = first
        captured.append(lease)
        raise CampaignAbort("synthetic abort", code="synthetic-abort")

    runner._execute_prepared = fail_after_resolution

    with pytest.raises(CampaignAbort, match="synthetic abort"):
        runner.execute_claimed(SimpleNamespace())

    lease = captured[0]
    assert lease.resolution_count == 1
    with pytest.raises(CredentialResolutionError, match="released"):
        lease.resolve(reference)
    assert adapter.closed is True
    assert adapter.credential is None


class _AuthorizedSyntheticRun(NamedTuple):
    launcher: Principal
    corpus: object
    catalog: TrustedTargetCatalog
    store: ControlPlaneStore
    run: object


def _authorize_synthetic_run(
    engine: Engine,
    *,
    target_requests_per_second: float = 100.0,
    full_scan: bool = False,
) -> _AuthorizedSyntheticRun:
    """Drive the full two-person control-plane handshake and enqueue one dispatchable job.

    This is the exact harness the happy-path test uses; the negative tests reuse it and
    then perturb a single precondition so the Runner refuses at network-free preflight.
    """

    _clean(engine)
    launcher = _principal("user_RunnerLauncher", CAMPAIGN_LAUNCH)
    approver = _principal("user_RunnerApprover", CAMPAIGN_AUTHORIZE)
    corpus = load_full_scan_corpus() if full_scan else load_mvp_corpus()
    catalog = TrustedTargetCatalog.from_environment("staging")
    store = ControlPlaneStore(engine, environment="staging")
    catalog.synchronize(store, organization_id=ORG_ID)

    scope = store.build_scope(
        principal=launcher,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=corpus.corpus_id,
        corpus_hash=corpus.content_hash,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=len(corpus.cases),
            target_requests_per_second=target_requests_per_second,
            run_timeout_seconds=300.0,
            logical_case_limit=14,
            physical_request_limit=51,
            target_retries_per_turn=2,
        ),
        run_nonce="runner-negative-nonce-0001",
        execution_profile=ExecutionProfile.SYNTHETIC,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
        idempotency_key="runner-negative-request-0001",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="runner-negative-approve-0001",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="runner-negative-launch-0001",
    )
    return _AuthorizedSyntheticRun(
        launcher=launcher, corpus=corpus, catalog=catalog, store=store, run=run
    )


def _claim_enqueued_job(runner: DurableCampaignRunner, *, worker_id: str) -> JobRecord:
    # Claim through the Runner's own queue, which trusts the ``campaign.execute`` schema
    # the launch step enqueues; a default-configured queue would reject that payload.
    job = runner.queue.claim(LogicalQueue.AGENT_WORK, worker_id=worker_id, lease_duration=_LEASE)
    assert job is not None
    return job


def _no_adapter_guard(runner: DurableCampaignRunner) -> list[bool]:
    """Trip a flag if adapter construction (the first live-path step) is ever reached."""

    constructed: list[bool] = []

    def _forbidden(prepared: object) -> object:  # pragma: no cover - must never run
        constructed.append(True)
        raise AssertionError("preflight refusal must precede adapter construction")

    runner._adapter = _forbidden  # type: ignore[method-assign]
    return constructed


def test_legacy_regression_row_never_becomes_verified_orchestrator_signal(
    migrated_db: Engine,
) -> None:
    authorized = _authorize_synthetic_run(migrated_db)
    authorized.store.append_campaign_state(run_id=authorized.run.run_id, state="running")
    scope = authorized.store.load_run_for_execution(authorized.run.run_id).scope
    case = authorized.corpus.cases[0]
    payload = verified_case_payload(case)
    attack_attempt = {
        "schema_version": "1",
        "case_ref": payload["case_id"],
        "input_sequence": list(payload["input_sequence"]),
        "category": payload["category"],
    }
    attempt = authorized.store.ensure_campaign_attempt(
        run_id=authorized.run.run_id,
        ordinal=0,
        case_id=payload["case_id"],
        case_content_hash=case.content_hash,
        category=payload["category"],
        severity=payload["severity"]["rating"],
        attack_class=payload["test_design"]["classification"],
        owasp_mappings=payload["owasp"],
        fixture_provenance=payload["fixture_provenance"],
    )
    evidence_fields = {
        "schema_version": "1",
        "campaign_run_id": authorized.run.run_id,
        "attempt_id": attempt.attempt_id,
        "campaign_id": authorized.run.run_id,
        "target_id": scope.target_id,
        "target_version": scope.target_version,
        "attack_attempt": attack_attempt,
        "request_transcript": {"turns": list(payload["input_sequence"])},
        "response_transcript": "synthetic deterministic canary observation",
        "policy_decision_id": "policy-legacy-regression-fixture",
        "executed_at": "2026-07-24T12:00:00+00:00",
        "trace_id": None,
        "correlation_id": authorized.run.run_id,
        "recorder_identity": "recorder@1",
        "recorder_version": "1",
        "organization_id": ORG_ID,
        "surface_id": scope.surface_id,
        "surface_version": scope.surface_version,
        "authorization_scope_hash": authorized.run.scope_hash,
        "execution_profile": "synthetic",
        "evidence_provenance": "synthetic_offline",
    }
    with migrated_db.begin() as connection:
        stored = ExecutionRecorder().record(evidence_fields, connection)
    finding_id = authorized.store.record_attempt_outcome(
        run_id=authorized.run.run_id,
        attempt_id=attempt.attempt_id,
        verdict={
            "schema_version": "1",
            "campaign_run_id": authorized.run.run_id,
            "attempt_id": attempt.attempt_id,
            "state": "EXPLOIT_CONFIRMED",
            "confidence": 1.0,
            "reason_codes": ["oracle_confirmed"],
            "confirmation_source": "oracle",
        },
        evidence_content_hash=stored.content_hash,
    )
    assert finding_id is not None
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO regression_case (regression_case_id, state, finding_id) "
                "VALUES ('legacy-regression-without-replay-proof', 'failing', :finding)"
            ),
            {"finding": finding_id},
        )
    case_counts: dict[str, int] = {}
    for authored_case in authorized.corpus.cases:
        category = verified_case_payload(authored_case)["category"]
        case_counts[category] = case_counts.get(category, 0) + 1

    snapshot = authorized.store.load_orchestration_snapshot(
        run_id=authorized.run.run_id,
        case_counts=case_counts,
    )

    assert snapshot["regressions"] == []


def test_confirmed_findings_persist_only_blocked_reproduction_plans(
    migrated_db: Engine,
    tmp_path,
) -> None:
    authorized = _authorize_synthetic_run(migrated_db)
    clock = _AdvancingClock()
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
        clock=clock,
        sleeper=clock.advance,
    )

    assert runner.run_once(worker_id="runner-regression-plan-test") is True

    with migrated_db.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT p.contract_payload AS plan, d.contract_payload AS disposition, "
                    "r.contract_payload AS report, ar.attack_attempt "
                    "FROM regression_replay_plans p JOIN regression_dispositions d "
                    "ON d.organization_id = p.organization_id "
                    "AND d.disposition_id = p.disposition_id JOIN vuln_reports r "
                    "ON r.organization_id = p.organization_id AND r.report_id = p.report_id "
                    "JOIN attempt_result ar ON ar.organization_id = r.organization_id "
                    "AND ar.campaign_run_id = r.campaign_run_id "
                    "AND ar.attempt_id = r.attempt_id "
                    "WHERE r.campaign_run_id = :run ORDER BY p.replay_id"
                ),
                {"run": authorized.run.run_id},
            )
            .mappings()
            .all()
        )
        result_count = connection.execute(
            text("SELECT count(*) FROM regression_replay_results WHERE campaign_run_id = :run"),
            {"run": authorized.run.run_id},
        ).scalar_one()
        admitted_count = connection.execute(
            text("SELECT count(*) FROM regression_case_versions WHERE organization_id = :org"),
            {"org": ORG_ID},
        ).scalar_one()

    assert rows
    assert result_count == admitted_count == 0
    for row in rows:
        plan = dict(row["plan"])
        disposition = dict(row["disposition"])
        report = dict(row["report"])
        assert is_valid("regression_replay_plan", plan)
        assert plan["finding_id"] == disposition["finding_id"] == report["finding_id"]
        assert plan["report_id"] == disposition["report_id"] == report["report_id"]
        assert plan["attack_attempt"] == dict(row["attack_attempt"])
        assert plan["required_oracle_ids"]
        assert plan["trigger"] == "deterministic_reproduction"
        assert plan["authorization_state"] == "pending_human_authorization"
        assert plan["authorization_scope_hash"] is None
        assert plan["execution_state"] == "blocked"
        assert disposition["state"] == "pending_deterministic_reproduction"
        assert disposition["human_approved"] is False
        assert disposition["admitted"] is False


def test_orchestrator_post_decision_failure_is_terminal_and_preserves_error(
    migrated_db: Engine,
    tmp_path,
) -> None:
    authorized = _authorize_synthetic_run(migrated_db)
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
    )
    telemetry = _RecordingAgentTelemetry()
    runner.telemetry = telemetry  # type: ignore[assignment]
    adapter_calls = _no_adapter_guard(runner)
    shaping_failure = RuntimeError("post-decision shaping failed")

    class ExplodingCategory:
        def __hash__(self) -> int:
            raise shaping_failure

    runner.orchestrator.decide = lambda _snapshot: SimpleNamespace(  # type: ignore[method-assign]
        directive={"category": ExplodingCategory()},
        priority_reason="test_post_decision_failure",
        signal_sha256="0" * 64,
        regression_triggers=(),
    )

    with pytest.raises(DispatchUnavailable, match="campaign_execution_failed") as raised:
        runner.run_once(worker_id="runner-orchestrator-finalization-test")

    assert raised.value.__cause__ is shaping_failure
    assert adapter_calls == []
    with migrated_db.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT execution_id, agent_role, status, error_code, measured_cost, "
                    "finished_at, duration_ms FROM agent_executions "
                    "WHERE campaign_run_id = :run ORDER BY id"
                ),
                {"run": authorized.run.run_id},
            )
            .mappings()
            .all()
        )
        campaign_state = connection.execute(
            text(
                "SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id DESC LIMIT 1"
            ),
            {"run": authorized.run.run_id},
        ).scalar_one()

    assert len(rows) == 1
    assert rows[0]["agent_role"] == "orchestrator"
    assert rows[0]["status"] == "failed"
    assert rows[0]["error_code"] == "orchestrator_execution_failed"
    assert float(rows[0]["measured_cost"]) == 0.0
    assert rows[0]["finished_at"] is not None
    assert rows[0]["duration_ms"] is not None
    assert campaign_state == "failed"
    assert [item["execution_id"] for item in telemetry.starts] == [rows[0]["execution_id"]]
    assert [item["execution_id"] for item in telemetry.finishes] == [rows[0]["execution_id"]]
    assert telemetry.finishes[0]["error_code"] == "orchestrator_execution_failed"
    assert telemetry.flush_count == 2
    assert telemetry.heartbeat_count == 1
    assert telemetry.released_campaigns == [authorized.run.run_id]


def test_red_team_attempt_persistence_failure_is_terminal_and_preserves_error(
    migrated_db: Engine,
    tmp_path,
) -> None:
    authorized = _authorize_synthetic_run(migrated_db)
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
    )
    telemetry = _RecordingAgentTelemetry()
    runner.telemetry = telemetry  # type: ignore[assignment]
    adapter_calls = _no_adapter_guard(runner)
    persistence_failure = RuntimeError("attempt persistence failed")

    def fail_attempt_persistence(**_values: object) -> object:
        raise persistence_failure

    runner.store.ensure_campaign_attempt = fail_attempt_persistence  # type: ignore[method-assign]

    with pytest.raises(DispatchUnavailable, match="campaign_execution_failed") as raised:
        runner.run_once(worker_id="runner-red-team-finalization-test")

    assert raised.value.__cause__ is persistence_failure
    assert adapter_calls == []
    with migrated_db.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT execution_id, agent_role, status, error_code, measured_cost, "
                    "finished_at, duration_ms FROM agent_executions "
                    "WHERE campaign_run_id = :run ORDER BY id"
                ),
                {"run": authorized.run.run_id},
            )
            .mappings()
            .all()
        )
        attempts = connection.execute(
            text("SELECT count(*) FROM campaign_attempts WHERE run_id = :run"),
            {"run": authorized.run.run_id},
        ).scalar_one()
        campaign_state = connection.execute(
            text(
                "SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id DESC LIMIT 1"
            ),
            {"run": authorized.run.run_id},
        ).scalar_one()

    assert [(row["agent_role"], row["status"], row["error_code"]) for row in rows] == [
        ("orchestrator", "succeeded", None),
        ("red_team", "failed", "red_team_execution_failed"),
    ]
    assert all(float(row["measured_cost"]) == 0.0 for row in rows)
    assert all(row["finished_at"] is not None for row in rows)
    assert all(row["duration_ms"] is not None for row in rows)
    assert attempts == 0
    assert campaign_state == "failed"
    assert [item["execution_id"] for item in telemetry.starts] == [
        row["execution_id"] for row in rows
    ]
    assert [item["execution_id"] for item in telemetry.finishes] == [
        row["execution_id"] for row in rows
    ]
    assert [item["error_code"] for item in telemetry.finishes] == [
        None,
        "red_team_execution_failed",
    ]
    assert telemetry.flush_count == 3
    assert telemetry.heartbeat_count == 2
    assert telemetry.released_campaigns == [authorized.run.run_id]


def test_agent_terminalization_failure_does_not_replace_primary_error() -> None:
    runner = object.__new__(DurableCampaignRunner)
    primary_error = RuntimeError("primary campaign failure")

    def fail_terminalization(**_values: object) -> None:
        raise OSError("terminal accounting unavailable")

    runner._finish_agent_execution = fail_terminalization  # type: ignore[method-assign]

    runner._fail_agent_execution_preserving_error(
        primary_error=primary_error,
        execution_id="execution-test",
        status="failed",
        output_payload={"cycle": 0},
        error_code="orchestrator_execution_failed",
    )

    assert primary_error.__notes__ == [
        "agent execution terminal finalization also failed (OSError)"
    ]


def test_runner_promotes_model_only_for_exact_enabled_authoritative_calibration() -> None:
    """The pre-manifest seam may promote only the externally enabled exact identity."""

    ground_truth = {
        "schema_version": "1",
        "campaign_run_id": "run-hosted-authority-guard",
        "attempt_id": "attempt-hosted-authority-guard",
        "state": "NO_EXPLOIT_OBSERVED",
        "confidence": 1.0,
        "reason_codes": ["calibrated_negative"],
    }
    calibration = JudgeCalibrationStatus(
        state="enabled",
        calibration_id="JC-" + ("a" * 64),
        metrics={"agreement_rate": 1.0, "false_negative_rate": 0.0},
        reason_codes=(),
        model_authoritative=True,
        source="configured_file",
    )

    reconciliation = _reconcile_runner_evaluator(
        assessment={
            "state": "EXPLOIT_LIKELY",
            "confidence": 0.99,
            "rationale": "The live evaluator disagrees with deterministic ground truth.",
            "criteria_hits": ["policy_boundary"],
            "error_code": None,
        },
        deterministic_verdict=ground_truth,
        calibration=calibration,
    )

    assert reconciliation.effective_verdict["state"] == "EXPLOIT_LIKELY"
    assert reconciliation.effective_verdict["confirmation_source"] == "calibrated_model"
    assert reconciliation.model_decisive is True
    assert reconciliation.ground_truth_agreement is False
    assert reconciliation.calibration_state == "enabled"

    guarded = _reconcile_runner_evaluator(
        assessment={
            "state": "EXPLOIT_LIKELY",
            "confidence": 0.99,
            "rationale": "The live evaluator disagrees with deterministic ground truth.",
            "criteria_hits": ["policy_boundary"],
            "error_code": None,
        },
        deterministic_verdict=ground_truth,
        calibration=dataclasses.replace(calibration, model_authoritative=False),
    )

    assert guarded.effective_verdict == ground_truth
    assert guarded.model_decisive is False


def test_hosted_call_refuses_before_provider_when_langfuse_observation_does_not_open() -> None:
    class RecordingStore:
        def __init__(self) -> None:
            self.starts: list[dict[str, object]] = []
            self.finishes: list[dict[str, object]] = []

        def start_hosted_agent_execution(self, **values: object) -> str:
            self.starts.append(dict(values))
            return "execution-hosted-langfuse-gate"

        def finish_hosted_agent_execution(self, **values: object) -> None:
            self.finishes.append(dict(values))

    class UnavailableLangfuseTelemetry:
        def begin_agent(self, **_values: object) -> bool:
            return False

    store = RecordingStore()
    lifecycle = _DurableHostedExecutionLifecycle(
        store=store,  # type: ignore[arg-type]
        telemetry=UnavailableLangfuseTelemetry(),  # type: ignore[arg-type]
        run_id="run-hosted-langfuse-gate",
        calibration=JudgeCalibrationStatus(
            state="unavailable",
            calibration_id=None,
            metrics=None,
            reason_codes=("calibration_artifact_unavailable",),
            model_authoritative=False,
            source="none",
        ),
    )
    provider_calls: list[bool] = []

    with (
        lifecycle.invocation(role="orchestrator", detail={"phase": "live_planning"}),
        pytest.raises(
            DispatchUnavailable,
            match="hosted_langfuse_observation_unavailable",
        ),
    ):
        lifecycle.start(
            role="orchestrator",
            parent_execution_id=None,
            input_payload={"coverage": []},
            provider="openrouter",
            model="anthropic/claude-opus-4.8",
            upstream_provider="anthropic",
            configuration_sha256="a" * 64,
            role_configuration_sha256="b" * 64,
            generation_policy_sha256="c" * 64,
            judge_calibration_id=None,
        )
        provider_calls.append(True)

    assert provider_calls == []
    assert len(store.starts) == 1
    assert store.finishes == [
        {
            "execution_id": "execution-hosted-langfuse-gate",
            "status": "failed",
            "output_payload": {"status": "failed"},
            "error_code": "hosted-langfuse-start-failed",
            "detail": {
                "phase": "hosted_observability_gate",
            },
        }
    ]


def _hosted_capacity_fixture(
    *,
    case_count: int = 2,
    max_retries: int = 0,
) -> SimpleNamespace:
    policy = DEFAULT_HOSTED_GENERATION_POLICY
    required_calls = policy.required_logical_calls(case_count=case_count)
    roles = []
    global_tokens = {"input": 0, "output": 0, "reasoning": 0}
    global_usd = Decimal(0)
    for role, required in required_calls.items():
        bounds = policy.call_bounds[role]
        required_physical_calls = required * (1 + max_retries)
        totals = {
            "input": bounds.input_tokens * required_physical_calls,
            "output": bounds.output_tokens * required_physical_calls,
            "reasoning": bounds.reasoning_tokens * required_physical_calls,
        }
        for token_kind, token_count in totals.items():
            global_tokens[token_kind] += token_count
        prices = SimpleNamespace(
            input_usd_per_million_tokens=Decimal("0.000001"),
            output_usd_per_million_tokens=Decimal("0.000001"),
            reasoning_usd_per_million_tokens=Decimal("0.000001"),
        )
        required_usd = Decimal(sum(totals.values())) / Decimal(1_000_000_000_000)
        global_usd += required_usd
        roles.append(
            SimpleNamespace(
                role=role,
                prices=prices,
                limits=SimpleNamespace(
                    max_calls=required_physical_calls,
                    max_input_tokens=totals["input"],
                    max_output_tokens=totals["output"],
                    max_reasoning_tokens=totals["reasoning"],
                    max_usd=required_usd,
                    max_retries=max_retries,
                ),
            )
        )
    return SimpleNamespace(
        roles=tuple(roles),
        global_limits=SimpleNamespace(
            max_calls=sum(required_calls.values()) * (1 + max_retries),
            max_input_tokens=global_tokens["input"],
            max_output_tokens=global_tokens["output"],
            max_reasoning_tokens=global_tokens["reasoning"],
            max_usd=global_usd,
            max_retries=max_retries,
        ),
    )


def test_hosted_preflight_requires_cumulative_role_token_capacity() -> None:
    configuration = _hosted_capacity_fixture()
    configuration.roles[0].limits.max_input_tokens -= 1

    with pytest.raises(DispatchUnavailable, match="hosted_role_cap_incompatible"):
        _require_hosted_workload_capacity(
            configuration=configuration,  # type: ignore[arg-type]
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            case_count=2,
        )


def test_hosted_preflight_requires_cumulative_global_token_capacity() -> None:
    configuration = _hosted_capacity_fixture()
    _require_hosted_workload_capacity(
        configuration=configuration,  # type: ignore[arg-type]
        generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
        case_count=2,
    )
    configuration.global_limits.max_reasoning_tokens -= 1

    with pytest.raises(DispatchUnavailable, match="hosted_global_token_cap_incompatible"):
        _require_hosted_workload_capacity(
            configuration=configuration,  # type: ignore[arg-type]
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            case_count=2,
        )


def test_hosted_preflight_requires_cumulative_role_and_global_spend_capacity() -> None:
    configuration = _hosted_capacity_fixture()
    configuration.roles[0].limits.max_usd /= 2

    with pytest.raises(DispatchUnavailable, match="hosted_role_spend_cap_incompatible"):
        _require_hosted_workload_capacity(
            configuration=configuration,  # type: ignore[arg-type]
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            case_count=2,
        )

    configuration = _hosted_capacity_fixture()
    configuration.global_limits.max_usd /= 2
    with pytest.raises(DispatchUnavailable, match="hosted_global_spend_cap_incompatible"):
        _require_hosted_workload_capacity(
            configuration=configuration,  # type: ignore[arg-type]
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            case_count=2,
        )


def test_canonical_nine_case_zero_retry_workload_fits_and_one_less_call_fails() -> None:
    configuration = _hosted_capacity_fixture(case_count=9, max_retries=0)
    _require_hosted_workload_capacity(
        configuration=configuration,  # type: ignore[arg-type]
        generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
        case_count=9,
    )
    configuration.roles[0].limits.max_calls -= 1

    with pytest.raises(DispatchUnavailable, match="hosted_role_cap_incompatible"):
        _require_hosted_workload_capacity(
            configuration=configuration,  # type: ignore[arg-type]
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            case_count=9,
        )


def test_global_fifty_six_call_cap_requires_zero_retry_nine_case_floor() -> None:
    configuration = _hosted_capacity_fixture(case_count=9, max_retries=1)
    configuration.global_limits.max_calls = 56

    with pytest.raises(DispatchUnavailable, match="hosted_global_call_cap_incompatible"):
        _require_hosted_workload_capacity(
            configuration=configuration,  # type: ignore[arg-type]
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            case_count=9,
        )


@pytest.mark.parametrize(("case_count", "required_calls"), ((34, 136), (33, 132), (33, 132)))
def test_reviewed_batch_requires_four_hosted_roles_and_zero_retries(
    case_count: int,
    required_calls: int,
) -> None:
    policy = DEFAULT_HOSTED_GENERATION_POLICY
    configuration = _hosted_capacity_fixture(case_count=case_count, max_retries=0)
    assert configuration.global_limits.max_calls == required_calls

    _require_hosted_workload_capacity(
        configuration=configuration,  # type: ignore[arg-type]
        generation_policy=policy,
        case_count=case_count,
    )

    configuration.global_limits.max_retries = 1
    for role_configuration in configuration.roles:
        role_configuration.limits.max_retries = 1
        role_configuration.limits.max_calls *= 2
        role_configuration.limits.max_input_tokens *= 2
        role_configuration.limits.max_output_tokens *= 2
        role_configuration.limits.max_reasoning_tokens *= 2
        role_configuration.limits.max_usd *= 2
    with pytest.raises(DispatchUnavailable, match="hosted_global_call_cap_incompatible"):
        _require_hosted_workload_capacity(
            configuration=configuration,  # type: ignore[arg-type]
            generation_policy=policy,
            case_count=case_count,
        )


def test_largest_reviewed_batch_fits_frozen_models_and_closed_usd_caps() -> None:
    configuration = _hosted_capacity_fixture(case_count=34, max_retries=0)
    prices = {
        "orchestrator": (Decimal("5"), Decimal("25"), Decimal("25"), Decimal("4")),
        "red_team": (
            Decimal("0.39"),
            Decimal("2.34"),
            Decimal("2.34"),
            Decimal("1"),
        ),
        "judge": (Decimal("1.25"), Decimal("10"), Decimal("10"), Decimal("5")),
        "documentation": (
            Decimal("2.5"),
            Decimal("15"),
            Decimal("15"),
            Decimal("2"),
        ),
    }
    for role_configuration in configuration.roles:
        input_price, output_price, reasoning_price, usd_cap = prices[
            role_configuration.role
        ]
        role_configuration.prices.input_usd_per_million_tokens = input_price
        role_configuration.prices.output_usd_per_million_tokens = output_price
        role_configuration.prices.reasoning_usd_per_million_tokens = reasoning_price
        role_configuration.limits.max_usd = usd_cap
    configuration.global_limits.max_usd = Decimal("10")

    _require_hosted_workload_capacity(
        configuration=configuration,  # type: ignore[arg-type]
        generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
        case_count=34,
    )


def test_corpus_hash_drift_refuses_before_adapter_construction(
    migrated_db: Engine,
    tmp_path,
) -> None:
    """The Runner independently rebinds the persisted scope's corpus hash to its own corpus.

    (The related "synthetic profile in production" gate at runner.py:293 is unreachable
    from a persisted run: the synthetic target is staging-bound, so a production-environment
    control plane refuses the scope at ``_build_scope_from_database`` (store.py:2015) — the
    run loads as ``authorization_not_dispatchable`` before the synthetic-profile check runs.
    That stronger environment gate subsumes it, so this test exercises a genuinely
    Runner-owned, otherwise-untested preflight blocker instead.)
    """

    authorized = _authorize_synthetic_run(migrated_db)
    # A corpus whose content hash no longer matches the authorized scope's corpus_hash,
    # while keeping the nine cases / three categories so only the hash gate trips.
    drifted_corpus = dataclasses.replace(authorized.corpus, content_hash="0" * 64)
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=drifted_corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
    )
    job = _claim_enqueued_job(runner, worker_id="runner-test")
    adapter_calls = _no_adapter_guard(runner)

    report, prepared = runner.preflight(job)

    assert "corpus_hash_mismatch" in report.blockers
    assert "corpus_not_complete" not in report.blockers
    assert report.ready is False
    assert prepared is None
    assert adapter_calls == []


def test_stale_runner_ownership_refuses_before_adapter_construction(
    migrated_db: Engine,
    tmp_path,
) -> None:
    """A job whose lease token does not match the persisted row is not owned by this worker."""

    authorized = _authorize_synthetic_run(migrated_db)
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
    )
    job = _claim_enqueued_job(runner, worker_id="runner-test")
    # Forge a lease token so database-time ownership no longer resolves to this worker.
    tampered = dataclasses.replace(job, lease_token="not-the-real-lease-token")
    adapter_calls = _no_adapter_guard(runner)

    report, prepared = runner.preflight(tampered)

    assert "lease_not_owned" in report.blockers
    assert report.ready is False
    assert prepared is None
    assert adapter_calls == []


def test_directive_resolution_never_expands_a_sub_one_per_minute_rate_cap(
    migrated_db: Engine,
    tmp_path,
) -> None:
    authorized = _authorize_synthetic_run(
        migrated_db,
        target_requests_per_second=0.01,
    )
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
    )
    adapter_calls = _no_adapter_guard(runner)

    with pytest.raises(DispatchUnavailable, match="campaign_execution_failed"):
        runner.run_once(worker_id="runner-test")

    assert adapter_calls == []
    with migrated_db.connect() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM attempt_result WHERE campaign_run_id = :run"),
                {"run": authorized.run.run_id},
            ).scalar_one()
            == 0
        )


def test_two_person_control_violation_is_not_dispatchable(
    migrated_db: Engine,
    tmp_path,
) -> None:
    """Same identity as launcher and approver cannot yield a dispatchable persisted run.

    The dedicated Runner blocker ``two_person_control_failed`` (runner.py:245) is
    defense-in-depth: the control plane refuses same-identity approval at
    ``decide_campaign_authorization`` (store.py:687) and again refuses to load such a run
    at ``load_run_for_execution`` (store.py:986), so it never persists a self-approved run
    to reach that later check. This test proves the store-level refusal blocks the request
    outright, and — because approval fails — no job is ever enqueued to dispatch.
    """

    _clean(migrated_db)
    single_identity = _principal("user_SelfApprover", CAMPAIGN_LAUNCH)
    single_identity = dataclasses.replace(
        single_identity,
        organization_permissions=frozenset({CAMPAIGN_LAUNCH, CAMPAIGN_AUTHORIZE}),
    )
    corpus = load_mvp_corpus()
    catalog = TrustedTargetCatalog.from_environment("staging")
    store = ControlPlaneStore(migrated_db, environment="staging")
    catalog.synchronize(store, organization_id=ORG_ID)

    scope = store.build_scope(
        principal=single_identity,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=corpus.corpus_id,
        corpus_hash=corpus.content_hash,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=9,
            target_requests_per_second=100.0,
            run_timeout_seconds=300.0,
            logical_case_limit=14,
            physical_request_limit=51,
            target_retries_per_turn=2,
        ),
        run_nonce="runner-selfapprove-nonce-0001",
        execution_profile=ExecutionProfile.SYNTHETIC,
    )
    request = store.request_campaign_authorization(
        principal=single_identity,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
        idempotency_key="runner-selfapprove-request-0001",
    )

    with pytest.raises(Exception) as excinfo:
        store.decide_campaign_authorization(
            principal=single_identity,
            request_id=request.request_id,
            decision="approved",
            idempotency_key="runner-selfapprove-approve-0001",
        )
    assert "own authorization request" in str(excinfo.value)

    # Approval was refused, so nothing was ever enqueued: there is no job to dispatch.
    queue = PostgresJobQueue(migrated_db)
    claimed = queue.claim(LogicalQueue.AGENT_WORK, worker_id="runner-test", lease_duration=_LEASE)
    assert claimed is None


def test_synthetic_campaign_executes_all_nine_cases_and_completes_atomically(
    migrated_db: Engine,
    tmp_path,
) -> None:
    _clean(migrated_db)
    launcher = _principal("user_RunnerLauncher", CAMPAIGN_LAUNCH)
    approver = _principal("user_RunnerApprover", CAMPAIGN_AUTHORIZE)
    corpus = load_mvp_corpus()
    catalog = TrustedTargetCatalog.from_environment("staging")
    store = ControlPlaneStore(migrated_db, environment="staging")
    catalog.synchronize(store, organization_id=ORG_ID)

    scope = store.build_scope(
        principal=launcher,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=corpus.corpus_id,
        corpus_hash=corpus.content_hash,
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=9,
            target_requests_per_second=100.0,
            run_timeout_seconds=300.0,
            logical_case_limit=14,
            physical_request_limit=51,
            target_retries_per_turn=2,
        ),
        run_nonce="runner-synthetic-nonce-0001",
        execution_profile=ExecutionProfile.SYNTHETIC,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=15),
        idempotency_key="runner-synthetic-request-0001",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="runner-synthetic-approve-0001",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="runner-synthetic-launch-0001",
    )

    clock = _AdvancingClock()
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=corpus,
        catalog=catalog,
        manifest_root=tmp_path,
        clock=clock,
        sleeper=clock.advance,
    )
    assert runner.run_once(worker_id="runner-test") is True

    with migrated_db.connect() as connection:
        state = connection.execute(
            text(
                "SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id DESC LIMIT 1"
            ),
            {"run": run.run_id},
        ).scalar_one()
        evidence = connection.execute(
            text("SELECT count(*) FROM attempt_result WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        attack_attempts = (
            connection.execute(
                text(
                    "SELECT ar.attack_attempt FROM campaign_attempts ca "
                    "JOIN attempt_result ar ON ar.organization_id = ca.organization_id "
                    "AND ar.campaign_run_id = ca.run_id AND ar.attempt_id = ca.attempt_id "
                    "WHERE ca.run_id = :run ORDER BY ca.ordinal"
                ),
                {"run": run.run_id},
            )
            .scalars()
            .all()
        )
        verdicts = connection.execute(
            text("SELECT count(*) FROM verdict WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        findings = connection.execute(
            text("SELECT count(*) FROM finding_evidence_links WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        reports = (
            connection.execute(
                text(
                    "SELECT contract_payload FROM vuln_reports "
                    "WHERE campaign_run_id = :run ORDER BY report_id"
                ),
                {"run": run.run_id},
            )
            .scalars()
            .all()
        )
        regression_dispositions = (
            connection.execute(
                text(
                    "SELECT contract_payload FROM regression_dispositions "
                    "WHERE campaign_run_id = :run ORDER BY disposition_id"
                ),
                {"run": run.run_id},
            )
            .scalars()
            .all()
        )
        reproduction_plans = (
            connection.execute(
                text(
                    "SELECT p.contract_payload FROM regression_replay_plans p "
                    "JOIN vuln_reports r ON r.organization_id = p.organization_id "
                    "AND r.report_id = p.report_id WHERE r.campaign_run_id = :run "
                    "ORDER BY p.replay_id"
                ),
                {"run": run.run_id},
            )
            .scalars()
            .all()
        )
        summary = (
            connection.execute(
                text("SELECT * FROM campaign_run_summaries WHERE run_id = :run"),
                {"run": run.run_id},
            )
            .mappings()
            .one()
        )
        work_units = (
            connection.execute(
                text(
                    "SELECT count(*) AS reserved, "
                    "count(*) FILTER (WHERE observed_at IS NOT NULL) AS observed "
                    "FROM campaign_work_unit_reservations WHERE run_id = :run"
                ),
                {"run": run.run_id},
            )
            .mappings()
            .one()
        )
        job_status = connection.execute(
            text("SELECT status FROM jobs WHERE campaign_run_id = :run"),
            {"run": run.run_id},
        ).scalar_one()
        orchestration = connection.execute(
            text(
                "SELECT payload FROM audit_events WHERE organization_id = :org "
                "AND aggregate_id = :run AND event_type = 'campaign.orchestrated'"
            ),
            {"org": ORG_ID, "run": run.run_id},
        ).scalar_one()
        agent_executions = {
            row["agent_role"]: dict(row)
            for row in connection.execute(
                text(
                    "SELECT agent_role, count(*) AS executions, "
                    "count(*) FILTER (WHERE status = 'running') AS running, "
                    "count(*) FILTER (WHERE parent_execution_id IS NOT NULL) AS linked, "
                    "count(*) FILTER (WHERE attempt_id IS NOT NULL) AS attempt_linked, "
                    "sum(measured_cost) AS measured_cost FROM agent_executions "
                    "WHERE campaign_run_id = :run GROUP BY agent_role"
                ),
                {"run": run.run_id},
            ).mappings()
        }
        canonical_agent_chains = connection.execute(
            text(
                "SELECT count(*) FROM agent_executions red "
                "JOIN agent_executions orchestrator "
                "ON orchestrator.execution_id = red.parent_execution_id "
                "AND orchestrator.organization_id = red.organization_id "
                "AND orchestrator.campaign_run_id = red.campaign_run_id "
                "AND orchestrator.agent_role = 'orchestrator' "
                "JOIN agent_executions judge "
                "ON judge.parent_execution_id = red.execution_id "
                "AND judge.organization_id = red.organization_id "
                "AND judge.campaign_run_id = red.campaign_run_id "
                "AND judge.attempt_id = red.attempt_id "
                "AND judge.agent_role = 'judge' "
                "WHERE red.campaign_run_id = :run AND red.agent_role = 'red_team' "
                "AND red.attempt_id IS NOT NULL"
            ),
            {"run": run.run_id},
        ).scalar_one()
        documented_finding_chains = connection.execute(
            text(
                "SELECT count(*) FROM finding_evidence_links link "
                "JOIN agent_executions documentation "
                "ON documentation.organization_id = link.organization_id "
                "AND documentation.campaign_run_id = link.campaign_run_id "
                "AND documentation.attempt_id = link.attempt_id "
                "AND documentation.agent_role = 'documentation' "
                "AND documentation.detail->>'finding_id' = link.finding_id "
                "JOIN agent_executions judge "
                "ON judge.execution_id = documentation.parent_execution_id "
                "AND judge.organization_id = link.organization_id "
                "AND judge.campaign_run_id = link.campaign_run_id "
                "AND judge.attempt_id = link.attempt_id "
                "AND judge.agent_role = 'judge' "
                "WHERE link.campaign_run_id = :run"
            ),
            {"run": run.run_id},
        ).scalar_one()

    assert state == "complete"
    assert evidence == verdicts == 9
    assert len(attack_attempts) == 9
    assert all(is_valid("attack_attempt", dict(attempt)) for attempt in attack_attempts)
    assert attack_attempts[0]["category"] == orchestration["directive"]["category"]
    assert findings == 2
    assert len(reports) == len(regression_dispositions) == len(reproduction_plans) == findings
    assert all(is_valid("vuln_report", dict(report)) for report in reports)
    assert all(
        is_valid("regression_disposition", dict(disposition))
        for disposition in regression_dispositions
    )
    assert all(
        disposition["state"] == "pending_deterministic_reproduction"
        and disposition["admitted"] is False
        for disposition in regression_dispositions
    )
    assert all(is_valid("regression_replay_plan", dict(plan)) for plan in reproduction_plans)
    assert all(
        plan["trigger"] == "deterministic_reproduction"
        and plan["authorization_state"] == "pending_human_authorization"
        and plan["authorization_scope_hash"] is None
        and plan["execution_state"] == "blocked"
        for plan in reproduction_plans
    )
    assert summary["attempt_count"] == summary["request_count"] == 9
    assert dict(work_units) == {"reserved": 9, "observed": 9}
    assert summary["execution_profile"] == "synthetic"
    assert summary["provenance"] == "synthetic_offline"
    assert job_status == "completed"
    assert is_valid("campaign_directive", orchestration["directive"])
    assert len(orchestration["signal_sha256"]) == 64
    assert agent_executions["orchestrator"]["executions"] == 9
    assert agent_executions["red_team"]["executions"] == 9
    assert agent_executions["judge"]["executions"] == 9
    assert agent_executions["documentation"]["executions"] == findings
    assert all(row["running"] == 0 for row in agent_executions.values())
    assert agent_executions["judge"]["linked"] == 9
    assert agent_executions["red_team"]["attempt_linked"] == 9
    assert agent_executions["judge"]["attempt_linked"] == 9
    assert agent_executions["documentation"]["attempt_linked"] == findings
    assert canonical_agent_chains == 9
    assert documented_finding_chains == findings
    assert all(float(row["measured_cost"]) == 0.0 for row in agent_executions.values())

    backend = PostgresApiBackend(
        migrated_db,
        environment="staging",
        runner_available=True,
        corpus=corpus,
    )
    findings_projection = backend.read("findings", launcher)
    reports_projection = backend.read("reports", launcher)
    finding_detail_projection = backend.read(
        "finding",
        launcher,
        identifiers={"finding_id": findings_projection.data[0]["finding_id"]},
    )
    report_detail_projection = backend.read(
        "report",
        launcher,
        identifiers={"report_id": reports[0]["report_id"]},
    )
    approval_detail_projection = backend.read(
        "approval",
        launcher,
        identifiers={"request_id": request.request_id},
    )
    coverage_projection = backend.read("coverage", launcher)
    agents_projection = backend.read("agents", launcher)
    activity_projection = backend.read("agent_activity", launcher)
    traces_projection = backend.read("traces", launcher)
    costs_projection = backend.read("costs", launcher)
    events = backend.events(launcher, after_cursor=0, limit=100)
    assert findings_projection.state == "ready"
    assert len(findings_projection.data) == 2
    assert all(item["state"] == "documented" for item in findings_projection.data)
    assert all(
        item["publication_status"] == "blocked_pending_human_approval"
        for item in findings_projection.data
    )
    assert reports_projection.state == "ready"
    assert len(reports_projection.data) == findings
    assert all(item["report_integrity"] == "verified" for item in reports_projection.data)
    assert all(
        item["publication_state"]
        in {
            "draft_unpublished",
            "blocked_pending_human_approval",
        }
        for item in reports_projection.data
    )
    assert finding_detail_projection.state == "ready"
    assert report_detail_projection.state == "ready"
    assert approval_detail_projection.state == "ready", approval_detail_projection.reason_code
    verification = finding_detail_projection.data["verification"]
    assert verification["availability"] == "ready"
    assert (
        verification["integrity"]["stored_content_sha256"]
        == (verification["integrity"]["finding_link_sha256"])
    )
    assert (
        verification["integrity"]["stored_content_sha256"]
        == (verification["integrity"]["recomputed_content_sha256"])
    )
    assert verification["judge"]["rationale"] is None
    assert verification["judge"]["rationale_availability"] == "unavailable"
    assert verification["judge"]["reason_codes"]
    assert len(approval_detail_projection.data["verification_chain"]) == findings
    rendered_verification = json.dumps(
        {
            "finding": finding_detail_projection.data,
            "report": report_detail_projection.data,
            "approval": approval_detail_projection.data,
        },
        sort_keys=True,
    )
    assert launcher.session_id not in rendered_verification
    assert "secretref://" not in rendered_verification
    assert coverage_projection.state == "ready"
    assert coverage_projection.data[0]["covered"] is True
    assert coverage_projection.data[0]["verified_attempt_count"] == 9
    assert agents_projection.state == activity_projection.state == "ready"
    assert sum(row["execution_count"] for row in agents_projection.data) == 29
    assert len(activity_projection.data) == 29
    assert any(row["operation"] == "agent.judge" for row in traces_projection.data)
    assert any(row["provider"].startswith("agent:orchestrator:") for row in costs_projection.data)
    assert any(event["type"] == "campaign.complete" for event in events.events)

    # Finding identity is singular on the read surface. A second evidence link must not make
    # list output duplicate a finding or let detail selection depend on row order.
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        source_link = (
            connection.execute(
                text(
                    "SELECT finding_id, attempt_id FROM finding_evidence_links "
                    "WHERE organization_id = :org AND campaign_run_id = :run "
                    "ORDER BY finding_id LIMIT 1"
                ),
                {"org": ORG_ID, "run": run.run_id},
            )
            .mappings()
            .one()
        )
        alternate = (
            connection.execute(
                text(
                    "SELECT v.id AS verdict_id, v.attempt_id, ar.content_hash, "
                    "ar.evidence_provenance FROM verdict v JOIN attempt_result ar "
                    "ON ar.organization_id = v.organization_id "
                    "AND ar.campaign_run_id = v.campaign_run_id "
                    "AND ar.attempt_id = v.attempt_id "
                    "WHERE v.organization_id = :org AND v.campaign_run_id = :run "
                    "AND v.attempt_id <> :source_attempt ORDER BY v.attempt_id LIMIT 1"
                ),
                {
                    "org": ORG_ID,
                    "run": run.run_id,
                    "source_attempt": source_link["attempt_id"],
                },
            )
            .mappings()
            .one()
        )
        connection.execute(
            text(
                "INSERT INTO finding_evidence_links "
                "(organization_id, finding_id, campaign_run_id, attempt_id, verdict_id, "
                "evidence_content_hash, provenance) VALUES "
                "(:org, :finding, :run, :attempt, :verdict, :content_hash, :provenance)"
            ),
            {
                "org": ORG_ID,
                "finding": source_link["finding_id"],
                "run": run.run_id,
                "attempt": alternate["attempt_id"],
                "verdict": alternate["verdict_id"],
                "content_hash": alternate["content_hash"],
                "provenance": alternate["evidence_provenance"],
            },
        )

    ambiguous_findings = backend.read("findings", launcher)
    ambiguous_finding = backend.read(
        "finding",
        launcher,
        identifiers={"finding_id": source_link["finding_id"]},
    )
    assert ambiguous_findings.state == ambiguous_finding.state == "unavailable"
    assert (
        ambiguous_findings.reason_code
        == ambiguous_finding.reason_code
        == "finding_evidence_identifier_ambiguous"
    )

    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "DELETE FROM finding_evidence_links WHERE organization_id = :org "
                "AND finding_id = :finding AND campaign_run_id = :run AND attempt_id = :attempt"
            ),
            {
                "org": ORG_ID,
                "finding": source_link["finding_id"],
                "run": run.run_id,
                "attempt": alternate["attempt_id"],
            },
        )

    # A report is only "verified" when every reference can be reconciled. Extra report or
    # fix-validation references are not silently blessed by the primary evidence hash.
    original_report = dict(reports[0])
    extra_reference = f"evidence://sha256/{'f' * 64}"
    for field in ("evidence_references", "fix_validation"):
        tampered_report = dict(original_report)
        if field == "evidence_references":
            tampered_report[field] = [*original_report[field], extra_reference]
        else:
            fix_validation = dict(original_report["fix_validation"])
            fix_validation["evidence_references"] = [extra_reference]
            tampered_report["fix_validation"] = fix_validation
        with migrated_db.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(
                text(
                    "UPDATE vuln_reports SET contract_payload = CAST(:payload AS jsonb) "
                    "WHERE organization_id = :org AND report_id = :report"
                ),
                {
                    "org": ORG_ID,
                    "report": original_report["report_id"],
                    "payload": json.dumps(tampered_report),
                },
            )
        bad_references = backend.read("reports", launcher)
        assert bad_references.state == "unavailable"
        assert bad_references.reason_code == "report_integrity_failed"
        with migrated_db.begin() as connection:
            connection.execute(text("SET LOCAL session_replication_role = replica"))
            connection.execute(
                text(
                    "UPDATE vuln_reports SET contract_payload = CAST(:payload AS jsonb) "
                    "WHERE organization_id = :org AND report_id = :report"
                ),
                {
                    "org": ORG_ID,
                    "report": original_report["report_id"],
                    "payload": json.dumps(original_report),
                },
            )

    # Taxonomy, target version, execution profile, and provenance remain cross-row bindings,
    # not display labels that can drift independently from the recorded attempt.
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "UPDATE finding SET target_version = 'tampered-version' "
                "WHERE organization_id = :org AND finding_id = :finding"
            ),
            {"org": ORG_ID, "finding": source_link["finding_id"]},
        )

    drifted_findings = backend.read("findings", launcher)
    drifted_reports = backend.read("reports", launcher)
    assert drifted_findings.state == drifted_reports.state == "unavailable"
    assert drifted_findings.reason_code == "finding_evidence_integrity_failed"
    assert drifted_reports.reason_code == "report_integrity_failed"

    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "UPDATE finding SET target_version = :target_version "
                "WHERE organization_id = :org AND finding_id = :finding"
            ),
            {
                "org": ORG_ID,
                "finding": source_link["finding_id"],
                "target_version": scope.target_version,
            },
        )

    # A schema-valid human-confirmed verdict is not the deterministic oracle/canary basis
    # authorized for Documentation. The report surface must fail closed if durable lineage drifts.
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "UPDATE verdict v SET confirmation_source = 'human', "
                "reason_codes = '[\"human_confirmed\"]'::jsonb "
                "FROM finding_evidence_links l "
                "WHERE l.organization_id = v.organization_id AND l.verdict_id = v.id "
                "AND l.campaign_run_id = :run"
            ),
            {"run": run.run_id},
        )

    untrusted_reports = backend.read("reports", launcher)
    assert untrusted_reports.state == "unavailable"
    assert untrusted_reports.reason_code == "report_integrity_failed"

    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "UPDATE verdict v SET state = 'EXPLOIT_LIKELY', "
                "confirmation_source = 'calibrated_model', "
                "reason_codes = '[\"calibrated_positive\"]'::jsonb "
                "FROM finding_evidence_links l "
                "WHERE l.organization_id = v.organization_id AND l.verdict_id = v.id "
                "AND l.campaign_run_id = :run"
            ),
            {"run": run.run_id},
        )

    non_confirmed_reports = backend.read("reports", launcher)
    assert non_confirmed_reports.state == "unavailable"
    assert non_confirmed_reports.reason_code == "report_integrity_failed"


def test_full_scan_executes_all_reviewed_tool_candidates_with_lineage(
    migrated_db: Engine,
    tmp_path,
) -> None:
    authorized = _authorize_synthetic_run(migrated_db, full_scan=True)
    clock = _AdvancingClock()
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
        clock=clock,
        sleeper=clock.advance,
    )

    assert runner.run_once(worker_id="runner-full-scan-test") is True

    with migrated_db.connect() as connection:
        attempts = (
            connection.execute(
                text(
                    "SELECT source_tool, count(*) AS executions FROM campaign_attempts "
                    "WHERE run_id = :run GROUP BY source_tool ORDER BY source_tool"
                ),
                {"run": authorized.run.run_id},
            )
            .mappings()
            .all()
        )
        agents = (
            connection.execute(
                text(
                    "SELECT agent_role, count(*) AS executions FROM agent_executions "
                    "WHERE campaign_run_id = :run GROUP BY agent_role"
                ),
                {"run": authorized.run.run_id},
            )
            .mappings()
            .all()
        )

    counts = {row["source_tool"]: row["executions"] for row in attempts}
    assert sum(counts.values()) == 14
    assert counts == {None: 9, "garak": 1, "promptfoo": 1, "pyrit": 3}
    agent_counts = {row["agent_role"]: row["executions"] for row in agents}
    assert agent_counts["orchestrator"] == 14
    assert agent_counts["red_team"] == 14
    assert agent_counts["judge"] == 14

    tooling = PostgresApiBackend(
        migrated_db,
        environment="staging",
        runner_available=True,
        corpus=authorized.corpus,
    ).read("tooling", authorized.launcher)
    tool_rows = {row["tool_id"]: row for row in tooling.data}
    assert tool_rows["garak"]["executed_attempt_count"] == 1
    assert tool_rows["promptfoo"]["executed_attempt_count"] == 1
    assert tool_rows["pyrit"]["executed_attempt_count"] == 3
    assert tool_rows["garak"]["runtime_state"] == "evidenced"
    assert tool_rows["promptfoo"]["runtime_state"] == "evidenced"
    assert tool_rows["pyrit"]["runtime_state"] == "evidenced"
    assert tool_rows["zap"]["runtime_state"] == "idle"


def test_runner_throttles_from_response_completion_for_slow_target(
    migrated_db: Engine,
    tmp_path,
) -> None:
    """A slow response must not consume the next request's completion-based rate interval."""

    authorized = _authorize_synthetic_run(
        migrated_db,
        target_requests_per_second=1.0,
    )
    clock = _AdvancingClock()
    runner = DurableCampaignRunner(
        engine=migrated_db,
        environment="staging",
        corpus=authorized.corpus,
        catalog=authorized.catalog,
        manifest_root=tmp_path,
        clock=clock,
        sleeper=clock.advance,
    )

    build_adapter = runner._adapter

    def slow_adapter(prepared: object) -> object:
        adapter = build_adapter(prepared)  # type: ignore[arg-type]
        send = adapter.send

        def delayed_send(request: object) -> object:
            response = send(request)
            clock.advance(2.0)
            return response

        adapter.send = delayed_send
        return adapter

    runner._adapter = slow_adapter  # type: ignore[method-assign]
    record_outcome = runner.store.record_attempt_outcome

    def record_with_processing_time(**kwargs: object) -> str | None:
        result = record_outcome(**kwargs)  # type: ignore[arg-type]
        clock.advance(0.01)
        return result

    runner.store.record_attempt_outcome = record_with_processing_time  # type: ignore[method-assign]

    assert runner.run_once(worker_id="runner-rate-window-test") is True

    with migrated_db.connect() as connection:
        state = connection.execute(
            text(
                "SELECT state FROM campaign_run_events WHERE run_id = :run ORDER BY id DESC LIMIT 1"
            ),
            {"run": authorized.run.run_id},
        ).scalar_one()
        evidence = connection.execute(
            text("SELECT count(*) FROM attempt_result WHERE campaign_run_id = :run"),
            {"run": authorized.run.run_id},
        ).scalar_one()

    assert state == "complete"
    assert evidence == 9


def test_a_refused_terminal_write_keeps_its_execution_context_for_the_retry() -> None:
    """The caller's only recovery from a refused terminal write is to retry with a smaller record.

    Dropping the execution context before the store call made every such retry fail as
    "context missing" and left the row 'running' forever — strictly worse than the write being
    refused, because nothing can ever close it afterwards. Exercised against the real lifecycle
    rather than a stand-in, since a hand-written double is what hid this the first time.
    """

    from agentforge.runner import _DurableHostedExecutionLifecycle, _HostedInvocationContext

    class _RefusesOnce:
        def __init__(self) -> None:
            self.calls = 0

        def finish_hosted_agent_execution(self, **_values: object) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("hosted agent output contains credential material")

    class _Telemetry:
        def finish_agent(self, **_values: object) -> None: ...

        def fail_agent(self, **_values: object) -> None: ...

    store = _RefusesOnce()
    lifecycle = _DurableHostedExecutionLifecycle(
        store=store,  # type: ignore[arg-type]
        telemetry=_Telemetry(),  # type: ignore[arg-type]
        run_id="run-context-retention",
        calibration=SimpleNamespace(state="unavailable", calibration_id=None),  # type: ignore[arg-type]
    )
    lifecycle._execution_context["exec-1"] = _HostedInvocationContext(  # noqa: SLF001
        role="red_team", attempt_id=None, detail={}
    )

    with pytest.raises(RuntimeError):
        lifecycle.finish(
            execution_id="exec-1",
            status="failed",
            output_payload={"status": "failed"},
            lineage=None,
            error_code="hosted-agent-failed",
        )
    # The retry must still be possible.
    assert "exec-1" in lifecycle._execution_context  # noqa: SLF001

    lifecycle.finish(
        execution_id="exec-1",
        status="failed",
        output_payload={"status": "failed"},
        lineage=None,
        error_code="hosted-agent-failed",
    )
    # And the context is released only once the execution is genuinely closed.
    assert "exec-1" not in lifecycle._execution_context  # noqa: SLF001
    assert store.calls == 2
