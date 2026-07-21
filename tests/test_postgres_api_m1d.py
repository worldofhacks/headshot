"""End-to-end HTTP-to-PostgreSQL contracts for the M1d control plane."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from agentforge.api.postgres import PostgresApiBackend, _safe
from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.dependencies import get_clerk_auth_config, require_authenticated
from agentforge.auth.principal import Principal
from agentforge.control_plane import ControlPlaneStore
from agentforge.target.spec import TargetLifecycle
from agentforge.web import WebSecurityConfig, create_web_app

ORIGIN = "https://staging.headshot.example"
ORG_ID = "org_M1dApiFixture"
LAUNCHER_ID = "user_M1dApiLauncher"
APPROVER_ID = "user_M1dApiApprover"


def _headers(key: str) -> dict[str, str]:
    return {"Idempotency-Key": key}


def _principal(user_id: str, *permissions: str) -> Principal:
    return Principal(
        user_id=user_id,
        session_id=f"sess_{user_id.removeprefix('user_')}",
        organization_id=ORG_ID,
        organization_role="org:operator",
        organization_permissions=frozenset(permissions),
    )


def _app(engine: Engine, principal: Principal) -> Any:
    app = create_web_app(
        backend=PostgresApiBackend(engine, environment="staging", runner_available=False),
        readiness_check=lambda: True,
        security_config=WebSecurityConfig(
            environment="staging",
            allowed_origins=(ORIGIN,),
            clerk_frontend_api_origin="https://clerk.staging.headshot.example",
        ),
    )
    app.dependency_overrides[require_authenticated] = lambda: principal
    app.dependency_overrides[get_clerk_auth_config] = lambda: ClerkAuthConfig(
        environment="staging",
        publishable_key="public-test-identifier-not-used",
        jwt_key="public-test-verification-key-not-used",
        authorized_parties=(ORIGIN,),
        required_organization_id=ORG_ID,
    )
    return app


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
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


def _target_payload() -> dict[str, Any]:
    return {
        "target_id": "copilot-api",
        "name": "Clinical Co-Pilot staging registry entry",
        "version": "1.0.0",
        "adapter_kind": "openemr",
        "environment": "staging",
        "base_url": "https://target.example.test/openemr",
        "allowlisted_hosts": ["target.example.test"],
        "auth_mode": "bearer",
        "credential_ref": "secretref://staging/copilot-api",
        "synthetic_data_only": True,
        "synthetic_data_attestation_ref": "attestation://synthetic/api-fixture",
        "canary_refs": ["oracle://canary/api-fixture"],
        "oracle_refs": ["oracle://judge/api-fixture"],
        "safety_caps": {
            "budget_usd": 5.0,
            "max_attempts_per_run": 5,
            "target_requests_per_second": 1.0,
            "run_timeout_seconds": 120.0,
        },
    }


def _surface_payload() -> dict[str, Any]:
    return {
        "surface_id": "chat-api",
        "version": "1.0.0",
        "target_version": "1.0.0",
        "kind": "chat",
        "protocol": "https",
        "method": "POST",
        "relative_path": "apis/default/api/copilot/message",
        "trust_boundary": "external-target",
        "authentication_required": True,
        "risk": "high",
        "owasp_mappings": [
            {
                "framework": "OWASP Web",
                "version": "2021",
                "identifier": "A01",
                "name": "Broken Access Control",
            }
        ],
        "oracle_refs": ["oracle://canary/api-fixture"],
        "enabled": True,
    }


def _seed_ready_target(engine: Engine, principal: Principal) -> None:
    """Stand in for the still-missing trusted server-side authoring catalog."""

    store = ControlPlaneStore(engine, environment="staging")
    backend = PostgresApiBackend(engine, environment="staging")
    store.register_target(
        principal=principal,
        target=backend._target(_target_payload()),
        idempotency_key="server-catalog-target-0001",
    )
    store.register_surface(
        principal=principal,
        surface=backend._surface("copilot-api", _surface_payload()),
        idempotency_key="server-catalog-surface-0001",
    )
    for lifecycle in (TargetLifecycle.VALIDATING, TargetLifecycle.READY):
        store.transition_target(
            principal=principal,
            target_id="copilot-api",
            version="1.0.0",
            lifecycle=lifecycle,
            idempotency_key=f"server-catalog-lifecycle-{lifecycle.value}-0001",
        )


def test_exact_scope_two_person_flow_reaches_persistence_but_not_unwired_runner(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    launcher = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:campaign:launch",
        "org:targets:manage",
    )
    client = TestClient(_app(migrated_db, launcher))
    _seed_ready_target(migrated_db, launcher)

    request_response = client.post(
        "/api/v1/campaign-authorization-requests",
        json={
            "target_id": "copilot-api",
            "target_version": "1.0.0",
            "surface_id": "chat-api",
            "surface_version": "1.0.0",
            "corpus_hash": "a" * 64,
            "run_nonce": "nonce-api-fixture-0001",
            "caps": {
                "budget_usd": 2.0,
                "max_attempts_per_run": 3,
                "target_requests_per_second": 0.5,
                "run_timeout_seconds": 60.0,
            },
            "expires_in_seconds": 600,
        },
        headers=_headers("api-auth-request-0001"),
    )
    assert request_response.status_code == 200, request_response.text
    request_id = request_response.json()["resource_id"]

    pending = client.get("/api/v1/approvals")
    assert pending.status_code == 200
    pending_scope = pending.json()["data"][0]
    assert pending_scope["request_id"] == request_id
    assert pending_scope["status"] == "pending"
    assert pending_scope["target_id"] == "copilot-api"
    assert pending_scope["surface_id"] == "chat-api"
    assert pending_scope["endpoint"] == (
        "https://target.example.test/openemr/apis/default/api/copilot/message"
    )
    assert pending_scope["auth_posture"] == "bearer"
    assert pending_scope["run_nonce"] == "nonce-api-fixture-0001"
    assert "credential_ref" not in pending.text
    assert "secretref://" not in pending.text

    same_user_client = TestClient(
        _app(migrated_db, _principal(LAUNCHER_ID, "org:campaign:authorize"))
    )
    self_decision = same_user_client.post(
        f"/api/v1/campaign-authorization-requests/{request_id}/decisions",
        json={"decision": "approved"},
        headers=_headers("api-self-decision-0001"),
    )
    assert self_decision.status_code == 403

    distinct_client = TestClient(
        _app(migrated_db, _principal(APPROVER_ID, "org:campaign:authorize"))
    )
    approved = distinct_client.post(
        f"/api/v1/campaign-authorization-requests/{request_id}/decisions",
        json={"decision": "approved"},
        headers=_headers("api-distinct-decision-0001"),
    )
    assert approved.status_code == 200, approved.text

    launch = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("api-launch-unavailable-0001"),
    )
    assert launch.status_code == 503
    assert launch.json()["reason_code"] == "runner_execution_composition_missing"
    with migrated_db.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM campaign_runs")).scalar_one() == 0
        assert connection.execute(text("SELECT count(*) FROM jobs")).scalar_one() == 0


def test_target_projection_is_org_scoped_and_never_returns_credential_reference(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    manager = _principal(LAUNCHER_ID, "org:console:read", "org:targets:manage")
    client = TestClient(_app(migrated_db, manager))
    _seed_ready_target(migrated_db, manager)

    response = client.get("/api/v1/targets")
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "ready", body
    assert body["data"][0]["credential_configured"] is True
    assert body["data"][0]["allowed_lifecycle_transitions"] == ["disabled"]
    assert "secretref://" not in response.text


def test_browser_target_and_surface_authoring_remain_unavailable_without_trusted_catalog(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    manager = _principal(LAUNCHER_ID, "org:console:read", "org:targets:manage")
    client = TestClient(_app(migrated_db, manager))

    target = client.post(
        "/api/v1/targets",
        json=_target_payload(),
        headers=_headers("browser-target-authoring-0001"),
    )
    surface = client.post(
        "/api/v1/targets/copilot-api/surfaces",
        json=_surface_payload(),
        headers=_headers("browser-surface-authoring-0001"),
    )

    assert target.status_code == 503
    assert target.json()["reason_code"] == "trusted_target_authoring_catalog_missing"
    assert surface.status_code == 503
    assert surface.json()["reason_code"] == "trusted_surface_authoring_catalog_missing"
    with migrated_db.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM target_definitions")).scalar_one() == 0
        assert (
            connection.execute(text("SELECT count(*) FROM attack_surface_definitions")).scalar_one()
            == 0
        )


def test_recursive_output_redaction_covers_headers_cookies_tokens_and_credential_urls() -> None:
    unsafe = {
        "evidence": (
            "Authorization: Bearer abcdefghijklmnop\n"
            "Cookie: __session=eyJheader.payload.signature\n"
            "postgresql://operator:database-password@example.test/headshot\n"
            "access_token=opaque-runtime-credential\n"
            "secretref://staging/copilot-api\n"
            "sk-proj-provider-secret-value"
        )
    }

    rendered = str(_safe(unsafe))

    assert "abcdefghijklmnop" not in rendered
    assert "database-password" not in rendered
    assert "provider-secret-value" not in rendered
    assert "eyJheader.payload.signature" not in rendered
    assert "opaque-runtime-credential" not in rendered
    assert "secretref://" not in rendered


def test_coverage_fails_closed_without_recomputed_evidence_integrity(
    migrated_db: Engine,
) -> None:
    viewer = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:findings:read",
    )

    response = TestClient(_app(migrated_db, viewer)).get("/api/v1/coverage")

    assert response.status_code == 200
    assert response.json() == {
        "state": "unavailable",
        "data": None,
        "reason_code": "verified_coverage_projection_missing",
    }
