from __future__ import annotations

import datetime
import uuid
from dataclasses import replace

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from agentforge.auth.permissions import (
    AUDIT_READ,
    CAMPAIGN_ABORT,
    CAMPAIGN_AUTHORIZE,
    CAMPAIGN_LAUNCH,
    FINDINGS_APPROVE,
    TARGETS_MANAGE,
)
from agentforge.auth.principal import Principal
from agentforge.control_plane import (
    AuthorizationDeniedError,
    ControlPlaneStore,
    IdempotencyConflictError,
    RecordNotFoundError,
)
from agentforge.policy.recorder import ExecutionRecorder
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    OwaspMapping,
    RiskLevel,
    SafetyCaps,
    SurfaceKind,
    TargetDefinition,
    TargetEnvironment,
    TargetLifecycle,
)

ORG_ID = "org_M1dFixture"
OTHER_ORG_ID = "org_OtherFixture"
LAUNCHER_ID = "user_M1dLauncher"
APPROVER_ID = "user_M1dApprover"
CAPS = SafetyCaps(
    budget_usd=25.0,
    max_attempts_per_run=20,
    target_requests_per_second=2.0,
    run_timeout_seconds=600.0,
)


def _principal(
    user_id: str,
    *,
    session_id: str | None = None,
    organization_id: str = ORG_ID,
    permissions: tuple[str, ...] = (),
) -> Principal:
    return Principal(
        user_id=user_id,
        session_id=session_id or f"sess_{user_id.removeprefix('user_')}",
        organization_id=organization_id,
        organization_role="org:operator",
        organization_permissions=frozenset(permissions),
    )


def _target(*, target_id: str = "copilot", version: str = "1.0.0") -> TargetDefinition:
    return TargetDefinition(
        target_id=target_id,
        name="Clinical Co-Pilot",
        version=version,
        adapter_kind="openemr",
        environment=TargetEnvironment.STAGING,
        base_url="https://target.example.test",
        allowlisted_hosts=("target.example.test",),
        auth_mode=AuthMode.BEARER,
        credential_ref=f"secretref://staging/{target_id}",
        synthetic_data_only=True,
        synthetic_data_attestation_ref="attestation://synthetic/fixture",
        canary_refs=("oracle://canary/fixture",),
        oracle_refs=("oracle://judge/fixture",),
        safety_caps=CAPS,
    )


def _surface(
    *,
    target_id: str = "copilot",
    target_version: str = "1.0.0",
    surface_id: str = "chat",
    version: str = "1.0.0",
) -> AttackSurfaceDefinition:
    return AttackSurfaceDefinition(
        surface_id=surface_id,
        version=version,
        target_id=target_id,
        target_version=target_version,
        kind=SurfaceKind.CHAT,
        protocol="https",
        method="POST",
        relative_path="apis/default/api/copilot/message",
        trust_boundary="external-target",
        authentication_required=True,
        risk=RiskLevel.HIGH,
        owasp_mappings=(OwaspMapping("OWASP Web", "2021", "A01", "Broken Access Control"),),
        oracle_refs=("oracle://canary/fixture",),
        enabled=True,
    )


@pytest.fixture
def store(migrated_db: Engine, _clean_control_plane: None) -> ControlPlaneStore:
    return ControlPlaneStore(migrated_db, environment="staging")


@pytest.fixture
def _clean_control_plane(migrated_db: Engine) -> None:
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE finding_decision_events, audit_events, command_idempotency, "
                "campaign_attempts, campaign_run_events, campaign_runs, "
                "campaign_authorization_decisions, campaign_authorization_requests, "
                "surface_state_events, attack_surface_definitions, surface_identities, "
                "target_lifecycle_events, target_definitions, target_identities, jobs "
                "RESTART IDENTITY CASCADE"
            )
        )


def _ready_scope(store: ControlPlaneStore, launcher: Principal, *, corpus: str = "a" * 64):
    store.register_target(
        principal=launcher,
        target=_target(),
        idempotency_key=f"target-{uuid.uuid4().hex}",
    )
    store.register_surface(
        principal=launcher,
        surface=_surface(),
        idempotency_key=f"surface-{uuid.uuid4().hex}",
    )
    for lifecycle in (TargetLifecycle.VALIDATING, TargetLifecycle.READY):
        store.transition_target(
            principal=launcher,
            target_id="copilot",
            version="1.0.0",
            lifecycle=lifecycle,
            idempotency_key=f"lifecycle-{lifecycle.value}-{uuid.uuid4().hex}",
        )
    return store.build_scope(
        principal=launcher,
        target_id="copilot",
        target_version="1.0.0",
        surface_id="chat",
        surface_version="1.0.0",
        corpus_hash=corpus,
        caps=CAPS,
        run_nonce="nonce-m1d-fixture-0001",
    )


def _approved_request(store: ControlPlaneStore, launcher: Principal):
    scope = _ready_scope(store, launcher)
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key=f"request-{uuid.uuid4().hex}",
    )
    store.decide_campaign_authorization(
        principal=_principal(APPROVER_ID, permissions=(CAMPAIGN_AUTHORIZE,)),
        request_id=request.request_id,
        decision="approved",
        idempotency_key=f"approve-{uuid.uuid4().hex}",
    )
    return request


def test_target_surface_history_builds_pr7_canonical_scope(store: ControlPlaneStore) -> None:
    launcher = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH))
    scope = _ready_scope(store, launcher)

    assert scope.target_id == "copilot"
    assert scope.surface_id == "chat"
    assert scope.relative_path == "apis/default/api/copilot/message"
    assert len(scope.scope_hash()) == 64


def test_fake_target_is_rejected_outside_local_test_environment(
    store: ControlPlaneStore,
) -> None:
    manager = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE,))

    with pytest.raises(AuthorizationDeniedError, match="local-test-only"):
        store.register_target(
            principal=manager,
            target=replace(_target(), adapter_kind="fake"),
            idempotency_key="reject-fake-staging-target",
        )


def test_surface_disable_is_rechecked_before_scope_resolution(store: ControlPlaneStore) -> None:
    launcher = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH))
    _ready_scope(store, launcher)
    store.set_surface_enabled(
        principal=launcher,
        target_id="copilot",
        surface_id="chat",
        version="1.0.0",
        enabled=False,
        idempotency_key="disable-chat-fixture",
    )

    with pytest.raises(AuthorizationDeniedError):
        store.build_scope(
            principal=launcher,
            target_id="copilot",
            target_version="1.0.0",
            surface_id="chat",
            surface_version="1.0.0",
            corpus_hash="a" * 64,
            caps=CAPS,
            run_nonce="nonce-m1d-fixture-0001",
        )


def test_authorization_persists_launcher_and_denies_self_approval(
    store: ControlPlaneStore,
) -> None:
    launcher = _principal(
        LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH, CAMPAIGN_AUTHORIZE)
    )
    scope = _ready_scope(store, launcher)
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="request-auth-self-fixture",
    )

    assert request.launcher_user_id == LAUNCHER_ID
    with pytest.raises(AuthorizationDeniedError):
        store.decide_campaign_authorization(
            principal=launcher,
            request_id=request.request_id,
            decision="approved",
            idempotency_key="approve-self-fixture",
        )


def test_distinct_approver_can_approve_exact_scope_and_launcher_can_launch(
    store: ControlPlaneStore,
) -> None:
    launcher = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH))
    approver = _principal(APPROVER_ID, permissions=(CAMPAIGN_AUTHORIZE,))
    scope = _ready_scope(store, launcher)
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="request-auth-distinct-fixture",
    )
    decision = store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="approve-distinct-fixture",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="launch-distinct-fixture",
    )

    assert decision.approver_user_id == APPROVER_ID
    assert decision.scope_hash == scope.scope_hash()
    assert run.launcher_user_id == LAUNCHER_ID
    assert run.scope_hash == scope.scope_hash()
    assert run.state == "queued"


def test_cross_organization_lookup_and_decision_are_denied(store: ControlPlaneStore) -> None:
    launcher = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH))
    scope = _ready_scope(store, launcher)
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="request-cross-org-fixture",
    )
    other = _principal(
        APPROVER_ID,
        organization_id=OTHER_ORG_ID,
        permissions=(CAMPAIGN_AUTHORIZE,),
    )

    with pytest.raises(RecordNotFoundError):
        store.get_authorization_request(principal=other, request_id=request.request_id)
    with pytest.raises(RecordNotFoundError):
        store.decide_campaign_authorization(
            principal=other,
            request_id=request.request_id,
            decision="approved",
            idempotency_key="approve-cross-org-fixture",
        )


def test_launch_and_queue_enqueue_commit_atomically_and_are_idempotent(
    store: ControlPlaneStore,
    migrated_db: Engine,
) -> None:
    launcher = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH))
    approver = _principal(APPROVER_ID, permissions=(CAMPAIGN_AUTHORIZE,))
    scope = _ready_scope(store, launcher)
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="request-launch-idempotent",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="approve-launch-idempotent",
    )

    first = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="launch-idempotent",
    )
    second = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="launch-idempotent",
    )

    assert second == first
    with migrated_db.connect() as connection:
        count = connection.execute(
            text("SELECT count(*) FROM jobs WHERE campaign_run_id = :run_id"),
            {"run_id": first.run_id},
        ).scalar_one()
    assert count == 1


def test_launch_copies_persisted_launcher_identity_not_new_request_input(
    store: ControlPlaneStore,
) -> None:
    original = _principal(
        LAUNCHER_ID,
        session_id="sess_originalLauncher",
        permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH),
    )
    request = _approved_request(store, original)
    later_session = _principal(
        LAUNCHER_ID,
        session_id="sess_laterLauncher",
        permissions=(CAMPAIGN_LAUNCH,),
    )

    run = store.launch_campaign(
        principal=later_session,
        request_id=request.request_id,
        idempotency_key="launch-persisted-launcher-session",
    )

    assert run.launcher_user_id == request.launcher_user_id
    assert run.launcher_session_id == request.launcher_session_id
    assert run.launcher_session_id != later_session.session_id


def test_registry_mutation_invalidates_pending_approval(store: ControlPlaneStore) -> None:
    launcher = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH))
    scope = _ready_scope(store, launcher)
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="request-disable-before-approval",
    )
    store.set_surface_enabled(
        principal=launcher,
        target_id="copilot",
        surface_id="chat",
        version="1.0.0",
        enabled=False,
        idempotency_key="disable-before-approval",
    )

    with pytest.raises(AuthorizationDeniedError):
        store.decide_campaign_authorization(
            principal=_principal(APPROVER_ID, permissions=(CAMPAIGN_AUTHORIZE,)),
            request_id=request.request_id,
            decision="approved",
            idempotency_key="approve-disabled-surface",
        )


def test_abort_is_atomic_idempotent_and_makes_run_non_executable(
    store: ControlPlaneStore,
    migrated_db: Engine,
) -> None:
    launcher = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH))
    request = _approved_request(store, launcher)
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="launch-for-abort",
    )
    operator = _principal("user_AbortOperator", permissions=(CAMPAIGN_ABORT,))
    raw_secret = "Bearer abort-token-must-not-persist"

    first = store.abort_campaign(
        principal=operator,
        run_id=run.run_id,
        rationale=f"Operator observed a safety breach. {raw_secret}",
        reason_code="operator_abort",
        idempotency_key="abort-run-exactly-once",
    )
    second = store.abort_campaign(
        principal=operator,
        run_id=run.run_id,
        rationale=f"Operator observed a safety breach. {raw_secret}",
        reason_code="operator_abort",
        idempotency_key="abort-run-exactly-once",
    )

    assert first.state == second.state == "aborted"
    with migrated_db.connect() as connection:
        status = connection.execute(
            text("SELECT status FROM jobs WHERE campaign_run_id = :run_id"),
            {"run_id": run.run_id},
        ).scalar_one()
        abort_events = connection.execute(
            text(
                "SELECT count(*) FROM campaign_run_events "
                "WHERE run_id = :run_id AND state = 'aborted'"
            ),
            {"run_id": run.run_id},
        ).scalar_one()
        audit_payload = connection.execute(
            text(
                "SELECT payload FROM audit_events "
                "WHERE aggregate_id = :run_id AND event_type = 'campaign.aborted'"
            ),
            {"run_id": run.run_id},
        ).scalar_one()
    assert status == "cancelled"
    assert abort_events == 1
    assert raw_secret not in str(audit_payload)
    assert "***REDACTED***" in audit_payload["rationale"]
    with pytest.raises(AuthorizationDeniedError):
        store.load_run_for_execution(run.run_id)


def test_finding_decision_persists_bounded_redacted_plain_text(
    store: ControlPlaneStore,
    migrated_db: Engine,
) -> None:
    finding_id = f"finding-{uuid.uuid4().hex}"
    campaign_run_id = uuid.uuid4().hex
    attempt_id = uuid.uuid4().hex
    evidence_fields = {
        "schema_version": "1",
        "campaign_run_id": campaign_run_id,
        "attempt_id": attempt_id,
        "campaign_id": "synthetic-fixture",
        "target_id": "synthetic-target",
        "target_version": "1.0.0",
        "attack_attempt": {"case_ref": "synthetic-case"},
        "request_transcript": {"request": ["synthetic input"]},
        "response_transcript": "synthetic canary response",
        "policy_decision_id": "fixture-policy-decision",
        "executed_at": "2026-07-21T12:00:00+00:00",
        "trace_id": None,
        "correlation_id": campaign_run_id,
        "recorder_identity": "recorder@1",
        "recorder_version": "1",
        "organization_id": ORG_ID,
        "surface_id": "synthetic-surface",
        "surface_version": "1.0.0",
        "authorization_scope_hash": "a" * 64,
        "execution_profile": "synthetic",
        "evidence_provenance": "synthetic_offline",
    }
    recorder = ExecutionRecorder()
    with migrated_db.begin() as connection:
        stored = recorder.record(evidence_fields, connection)
        verdict_id = connection.execute(
            text(
                "INSERT INTO verdict "
                "(state, confidence, campaign_run_id, attempt_id, organization_id, "
                "reason_codes, confirmation_source) VALUES "
                "('EXPLOIT_CONFIRMED', 1.0, :run, :attempt, :org, "
                "CAST('[\"trusted_canary_hit\"]' AS jsonb), 'trusted_canary') RETURNING id"
            ),
            {"run": campaign_run_id, "attempt": attempt_id, "org": ORG_ID},
        ).scalar_one()
        connection.execute(
            text(
                "INSERT INTO finding "
                "(finding_id, organization_id, state, severity, category, target_version, "
                "source_kind, execution_profile) VALUES "
                "(:finding, :org, 'candidate', 'high', 'access-control', '1.0.0', "
                "'campaign', 'synthetic')"
            ),
            {"finding": finding_id, "org": ORG_ID},
        )
        connection.execute(
            text(
                "INSERT INTO finding_evidence_links "
                "(organization_id, finding_id, campaign_run_id, attempt_id, "
                "evidence_content_hash, verdict_id, provenance) VALUES "
                "(:org, :finding, :run, :attempt, :evidence_hash, :verdict_id, "
                "'synthetic_offline')"
            ),
            {
                "org": ORG_ID,
                "finding": finding_id,
                "run": campaign_run_id,
                "attempt": attempt_id,
                "evidence_hash": stored.content_hash,
                "verdict_id": verdict_id,
            },
        )
    approver = _principal(APPROVER_ID, permissions=(FINDINGS_APPROVE,))
    raw_secret = "Bearer this-must-never-be-persisted"
    rationale = f"Confirmed from reviewed evidence. {raw_secret} <script>alert(1)</script>"

    decision = store.record_finding_decision(
        principal=approver,
        finding_id=finding_id,
        decision="approved",
        rationale=rationale,
        reason_code="human_confirmed",
        idempotency_key="finding-decision-redacted",
    )

    assert raw_secret not in decision.rationale
    assert "***REDACTED***" in decision.rationale
    assert "<script>" in decision.rationale
    assert rationale not in repr(decision)
    with migrated_db.connect() as connection:
        stored = connection.execute(
            text("SELECT rationale FROM finding_decision_events WHERE decision_id = :id"),
            {"id": decision.decision_id},
        ).scalar_one()
    assert stored == decision.rationale


def test_idempotency_key_cannot_name_different_command_input(store: ControlPlaneStore) -> None:
    manager = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE,))
    store.register_target(principal=manager, target=_target(), idempotency_key="target-same-key")

    with pytest.raises(IdempotencyConflictError):
        store.register_target(
            principal=manager,
            target=_target(target_id="different"),
            idempotency_key="target-same-key",
        )


def test_db_rejects_direct_self_approval_and_append_only_mutation(
    store: ControlPlaneStore,
    migrated_db: Engine,
) -> None:
    launcher = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, CAMPAIGN_LAUNCH))
    scope = _ready_scope(store, launcher)
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key="request-db-trigger-fixture",
    )

    with pytest.raises(DBAPIError), migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) VALUES "
                "(:id, :org, :request, :hash, 'approved', :user_id, :session_id)"
            ),
            {
                "id": uuid.uuid4().hex,
                "org": ORG_ID,
                "request": request.request_id,
                "hash": request.scope_hash,
                "user_id": LAUNCHER_ID,
                "session_id": launcher.session_id,
            },
        )

    with pytest.raises(DBAPIError), migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE campaign_authorization_requests SET scope_hash = :hash "
                "WHERE request_id = :request"
            ),
            {"hash": "f" * 64, "request": request.request_id},
        )


def test_audit_events_are_org_scoped_and_monotonic(store: ControlPlaneStore) -> None:
    manager = _principal(LAUNCHER_ID, permissions=(TARGETS_MANAGE, AUDIT_READ))
    store.register_target(principal=manager, target=_target(), idempotency_key="audit-target")
    events = store.list_audit_events(principal=manager)

    assert events
    assert all(event.organization_id == ORG_ID for event in events)
    assert [event.cursor for event in events] == sorted(event.cursor for event in events)
    assert store.list_audit_events(principal=manager, after_cursor=events[-1].cursor) == ()
