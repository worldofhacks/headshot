"""End-to-end HTTP-to-PostgreSQL contracts for the M1d control plane."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from agentforge.api.postgres import PostgresApiBackend, _safe
from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.dependencies import get_clerk_auth_config, require_authenticated
from agentforge.auth.principal import Principal
from agentforge.campaign.corpus import load_full_scan_corpus
from agentforge.control_plane import ControlPlaneStore
from agentforge.security_tools.repository import SecurityToolEvidenceRepository
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
                "TRUNCATE TABLE agent_executions, agent_configuration_versions, "
                "tool_execution_errors, security_tool_findings, scan_artifacts, "
                "security_tool_runs, finding_decision_events, audit_events, command_idempotency, "
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


def test_security_tool_catalog_is_exposed_with_truthful_scope_and_no_target_access(
    migrated_db: Engine,
) -> None:
    backend = PostgresApiBackend(migrated_db, environment="staging")
    principal = _principal(LAUNCHER_ID, "org:console:read")

    components = backend.read("components", principal)
    configuration = backend.read("configuration", principal)

    assert components.state == "ready"
    tools = {
        row["component_id"].removeprefix("security-tool:"): row
        for row in components.data
        if row["component_id"].startswith("security-tool:")
    }
    assert {
        "garak",
        "pyrit",
        "giskard",
        "promptfoo",
        "zap",
        "semgrep",
        "headshot-llm-workbench",
    } <= tools.keys()
    assert tools["garak"]["version"] == "0.15.1"
    assert tools["pyrit"]["target_access"] == "none"
    assert tools["giskard"]["adapter_only_scope"]
    assert tools["headshot-llm-workbench"]["availability"] == "operational and evidenced"
    assert tools["headshot-llm-workbench"]["target_access"] == "policy_gateway_only"
    assert configuration.state == "ready"
    assert len(configuration.data["configuration"]["security_tools"]) == len(tools)


def test_agent_models_and_tool_scope_are_real_configurable_projections(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    principal = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:targets:manage",
        "org:config:manage",
    )
    _seed_ready_target(migrated_db, principal)
    backend = PostgresApiBackend(
        migrated_db,
        environment="staging",
        corpus=load_full_scan_corpus(),
    )
    client = TestClient(_app(migrated_db, principal))
    client.app.state.api_backend = backend

    agents = client.get("/api/v1/agents")
    tooling = client.get("/api/v1/tooling")

    assert agents.status_code == tooling.status_code == 200
    assert agents.json()["state"] == "ready", agents.text
    assert tooling.json()["state"] == "ready", tooling.text
    assert {row["role"] for row in agents.json()["data"]} == {
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    }
    tool_rows = {row["tool_id"]: row for row in tooling.json()["data"]}
    assert tool_rows["garak"]["applicability"] == "in_campaign"
    assert tool_rows["garak"]["reviewed_candidate_count"] == 1
    assert tool_rows["pyrit"]["reviewed_candidate_count"] == 3
    assert tool_rows["zap"]["applicability"] == "companion_scan"
    assert tool_rows["semgrep"]["applicability"] == "platform_assurance"

    staged = client.post(
        "/api/v1/agents/red_team/configuration",
        json={
            "provider": "openrouter",
            "model": "provider/model-v1",
            "execution_mode": "hosted_advisory",
            "rationale": "Evaluate a reviewed hosted generator for a future corpus.",
        },
        headers=_headers("agent-config-stage-0001"),
    )
    assert staged.status_code == 200, staged.text
    red_team = next(
        row for row in client.get("/api/v1/agents").json()["data"] if row["role"] == "red_team"
    )
    assert red_team["active_assignment"]["model"] == "full-scan-corpus-v1"
    assert red_team["staged_assignment"]["model"] == "provider/model-v1"
    assert red_team["staged_assignment"]["activation_state"] == "staged_pending_authorization"

    rejected = client.post(
        "/api/v1/agents/judge/configuration",
        json={
            "provider": "anthropic",
            "model": "provider-model-v1",
            "execution_mode": "hosted_advisory",
            "rationale": "Attempt to replace the independent deterministic Judge.",
        },
        headers=_headers("agent-config-reject-0001"),
    )
    assert rejected.status_code == 409


def test_live_security_tool_findings_are_projected_into_the_console_register(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    raw = b'{"site":[]}'
    digest = hashlib.sha256(raw).hexdigest()
    observed_at = "2026-07-22T03:34:56+00:00"
    run = {
        "schema_version": "1",
        "run_id": "zap-live-projection-0001",
        "tool_name": "zap",
        "tool_version": "2.17.0",
        "configuration_sha256": "a" * 64,
        "run_nonce": "zap-live-projection-nonce-0001",
        "target_id": "openemr-copilot",
        "surface_id": "copilot-site",
        "scan_provenance": "live_target",
        "status": "completed",
        "started_at": observed_at,
        "finished_at": observed_at,
        "artifact_sha256": digest,
    }
    artifact = {
        "schema_version": "1",
        "artifact_id": "artifact-zap-live-projection-0001",
        "run_id": run["run_id"],
        "tool_name": "zap",
        "tool_version": "2.17.0",
        "media_type": "application/json",
        "sha256": digest,
        "sanitized": True,
        "byte_length": len(raw),
        "created_at": observed_at,
        "artifact_locator": "docs/evidence/zap/zap-target.json",
    }
    finding = {
        "schema_version": "1",
        "finding_id": "zap:projection0000000000000001",
        "tool_name": "zap",
        "tool_version": "2.17.0",
        "configuration_sha256": run["configuration_sha256"],
        "run_id": run["run_id"],
        "run_nonce": run["run_nonce"],
        "target_id": run["target_id"],
        "surface_id": run["surface_id"],
        "scan_provenance": "live_target",
        "observed_at": observed_at,
        "raw_artifact_sha256": digest,
        "owasp_mappings": ["A05:2021"],
        "severity": "low",
        "confidence": 0.9,
        "reproduction_evidence": {
            "summary": "X-Content-Type-Options Header Missing",
            "artifact_locator": "docs/evidence/zap/zap-target.json#finding=0",
        },
        "validation_state": "unvalidated",
        "disposition": "validate",
        "human_publication_state": "blocked_pending_human_approval",
        "source_kind": "security_tool",
        "evidence_provenance": "scan_only",
    }
    SecurityToolEvidenceRepository(migrated_db).ingest(
        organization_id=ORG_ID,
        run=run,
        artifact=artifact,
        sanitized_artifact=raw,
        findings=[finding],
    )

    result = PostgresApiBackend(migrated_db, environment="staging").read(
        "findings", _principal(LAUNCHER_ID, "org:findings:read")
    )

    assert result.state == "ready"
    assert result.data == [
        {
            "finding_id": finding["finding_id"],
            "state": "unvalidated",
            "severity": "low",
            "category": "X-Content-Type-Options Header Missing",
            "target_version": "openemr-copilot",
            "publication_status": "blocked_pending_human_approval",
            "evidence_integrity": "verified",
            "source_kind": "security_tool",
            "execution_profile": "live",
            "evidence_provenance": "scan_only",
            "campaign_run_id": None,
            "attempt_id": None,
            "evidence_content_hash": digest,
            "history": [],
        }
    ]


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


def test_authoritative_coverage_is_empty_without_verified_persisted_evidence(
    migrated_db: Engine,
) -> None:
    viewer = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:findings:read",
    )

    response = TestClient(_app(migrated_db, viewer)).get("/api/v1/coverage")

    assert response.status_code == 200
    assert response.json() == {"state": "empty", "data": []}


# --- Cost & trace read-model projections (M1d live-console pages) ----------------------------
#
# These pages read directly from persisted campaign artifacts. The seed writes rows with the
# session-level replication role switched to ``replica`` so that the ``campaign_runs`` INSERT
# trigger, the ``campaign_run_summaries`` FK/append-only trigger, and the append-only guards
# are bypassed for THIS seed transaction only (``SET LOCAL`` resets at commit). NOT NULL and
# CHECK constraints still apply, so the seed rows remain schema-valid. Each test uses a
# dedicated organization id so it is independent of the session-scoped ``migrated_db``.
COST_ORG_ID = "org_M1dCostProjection"
TRACE_ORG_ID = "org_M1dTraceProjection"


def _reader(org_id: str) -> Principal:
    # /costs needs console:read; /traces additionally needs evidence:read.
    return Principal(
        user_id="user_M1dConsoleReader",
        session_id="sess_M1dConsoleReader",
        organization_id=org_id,
        organization_role="org:operator",
        organization_permissions=frozenset({"org:console:read", "org:evidence:read"}),
    )


def _app_for(engine: Engine, principal: Principal) -> Any:
    """A web app whose Clerk config accepts this principal's (non-fixture) organization."""

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
        required_organization_id=principal.organization_id,
    )
    return app


def _seed_run_summary(engine: Engine, org_id: str, run_id: str) -> None:
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests (request_id, organization_id, "
                "scope_hash, scope_payload, launcher_user_id, launcher_session_id, expires_at) "
                "VALUES (:request, :org, :hash, CAST(:payload AS JSONB), :launcher, :session, "
                "TIMESTAMPTZ '2026-07-21 11:00:00+00')"
            ),
            {
                "request": f"req-{run_id}",
                "org": org_id,
                "hash": "b" * 64,
                "payload": json.dumps({"caps": {"budget_usd": 2}}),
                "launcher": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs (run_id, organization_id, authorization_request_id, "
                "scope_hash, launcher_user_id, launcher_session_id) "
                "VALUES (:run, :org, :req, :hash, :launcher, :session)"
            ),
            {
                "run": run_id,
                "org": org_id,
                "req": f"req-{run_id}",
                "hash": "b" * 64,
                "launcher": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_run_summaries (organization_id, run_id, execution_profile, "
                "provenance, attempt_count, request_count, confirmed_finding_count, "
                "measured_cost, currency, started_at, ended_at) VALUES (:org, :run, 'synthetic', "
                "'synthetic_offline', 9, 9, 0, 1.234567, 'USD', "
                "TIMESTAMPTZ '2026-07-21 10:00:00+00', TIMESTAMPTZ '2026-07-21 10:05:00+00')"
            ),
            {"org": org_id, "run": run_id},
        )


def _seed_trace(engine: Engine, org_id: str, run_id: str, attempt_id: str, trace_id: str) -> None:
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO attempt_result (organization_id, campaign_run_id, attempt_id, "
                "target_id, target_version, executed_at, trace_id, content_hash) VALUES "
                "(:org, :run, :att, 'copilot-api', '1.0.0', "
                "TIMESTAMPTZ '2026-07-21 10:00:00+00', :trace, :hash)"
            ),
            {"org": org_id, "run": run_id, "att": attempt_id, "trace": trace_id, "hash": "c" * 64},
        )
        connection.execute(
            text(
                "INSERT INTO verdict (state, confidence, campaign_run_id, attempt_id, "
                "organization_id, created_at) VALUES "
                "(CAST(:state AS verdict_state), 0.9, :run, :att, :org, "
                "TIMESTAMPTZ '2026-07-21 10:00:02.500+00')"
            ),
            {"state": "NO_EXPLOIT_OBSERVED", "run": run_id, "att": attempt_id, "org": org_id},
        )


def test_costs_projection_is_empty_for_org_without_persisted_summaries(
    migrated_db: Engine,
) -> None:
    reader = _reader("org_M1dCostEmpty")

    response = TestClient(_app_for(migrated_db, reader)).get("/api/v1/costs")

    assert response.status_code == 200
    assert response.json() == {"state": "empty", "data": []}


def test_costs_projection_is_ready_from_persisted_run_summary(migrated_db: Engine) -> None:
    _seed_run_summary(migrated_db, COST_ORG_ID, "run-cost-projection-0001")
    reader = _reader(COST_ORG_ID)

    response = TestClient(_app_for(migrated_db, reader)).get("/api/v1/costs")

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "ready", body
    assert len(body["data"]) == 1
    row = body["data"][0]
    assert set(row) == {
        "accounting_id",
        "campaign_id",
        "provider",
        "measured_cost",
        "currency",
        "request_count",
        "attempt_count",
        "confirmed_finding_count",
        "average_cost_per_request",
        "budget_usd",
        "budget_utilization",
        "duration_ms",
        "execution_profile",
        "started_at",
        "ended_at",
        "recorded_at",
    }
    assert row["accounting_id"] == "run-cost-projection-0001"
    assert row["campaign_id"] == "run-cost-projection-0001"
    assert row["provider"] == "synthetic_offline"
    # Numeric(14,6) must be projected as a JSON number, never a stringified Decimal.
    assert isinstance(row["measured_cost"], (int, float))
    assert row["measured_cost"] == 1.234567
    assert row["currency"] == "USD"
    assert row["request_count"] == 9
    assert row["attempt_count"] == 9
    assert row["confirmed_finding_count"] == 0
    assert abs(row["average_cost_per_request"] - (1.234567 / 9)) < 1e-12
    assert row["duration_ms"] == 300000.0
    assert row["execution_profile"] == "synthetic"
    assert row["budget_usd"] == 2.0
    assert abs(row["budget_utilization"] - (1.234567 / 2)) < 1e-12


def test_traces_projection_is_empty_for_org_without_persisted_results(
    migrated_db: Engine,
) -> None:
    reader = _reader("org_M1dTraceEmpty")

    response = TestClient(_app_for(migrated_db, reader)).get("/api/v1/traces")

    assert response.status_code == 200
    assert response.json() == {"state": "empty", "data": []}


def test_traces_projection_is_ready_from_persisted_attempt_and_verdict(
    migrated_db: Engine,
) -> None:
    _seed_trace(
        migrated_db,
        TRACE_ORG_ID,
        "run-trace-projection-0001",
        "attempt-trace-0001",
        "trace-projection-0001",
    )
    reader = _reader(TRACE_ORG_ID)

    response = TestClient(_app_for(migrated_db, reader)).get("/api/v1/traces")

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "ready", body
    assert len(body["data"]) == 1
    row = body["data"][0]
    assert set(row) == {
        "request_id",
        "trace_id",
        "campaign_id",
        "attempt_id",
        "operation",
        "provider",
        "method",
        "destination_host",
        "relative_path",
        "status",
        "status_code",
        "error_code",
        "started_at",
        "finished_at",
        "duration_ms",
        "request_bytes",
        "response_bytes",
        "measured_cost",
        "currency",
        "langfuse_status",
        "request_preview",
        "response_preview",
        "request_sha256",
        "response_sha256",
        "inspection_flags",
        "inspection_owasp_mappings",
    }
    assert row["trace_id"] == "trace-projection-0001"
    assert row["operation"] == "attempt:copilot-api@1.0.0"
    assert row["status"] == "NO_EXPLOIT_OBSERVED"
    # verdict.created_at (10:00:02.500) - attempt_result.executed_at (10:00:00) == 2500 ms.
    assert row["duration_ms"] == 2500.0
    assert row["started_at"].startswith("2026-07-21T10:00:00")
    assert row["campaign_id"] == "run-trace-projection-0001"
    assert row["attempt_id"] == "attempt-trace-0001"
    assert row["langfuse_status"] == "historical_not_instrumented"
    assert row["request_id"] is None
    assert row["request_preview"] is None
    assert row["inspection_flags"] == []
    assert row["finished_at"].startswith("2026-07-21T10:00:02.500")


def test_traces_projection_exposes_safe_physical_request_metadata(migrated_db: Engine) -> None:
    org_id = "org_M1dPhysicalTrace"
    run_id = "run-physical-trace-0001"
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_runs (run_id, organization_id, authorization_request_id, "
                "scope_hash, launcher_user_id, launcher_session_id) VALUES "
                "(:run, :org, 'request-physical-trace', :hash, :launcher, :session)"
            ),
            {
                "run": run_id,
                "org": org_id,
                "hash": "e" * 64,
                "launcher": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
            },
        )
        connection.execute(
            text(
                "INSERT INTO outbound_http_requests (request_id, organization_id, "
                "campaign_run_id, attempt_id, trace_id, operation, provider, method, "
                "destination_host, relative_path, request_payload, response_payload, status, "
                "status_code, request_bytes, response_bytes, duration_ms, measured_cost, "
                "currency, langfuse_status, started_at, finished_at) VALUES "
                "('request-physical-0001', :org, :run, 'attempt-physical-0001', :trace, "
                "'target.http', 'openemr', 'POST', 'target.example.test', 'chat', "
                'CAST(\'{"turns":["synthetic"]}\' AS JSONB), \'{"answer":"safe"}\', '
                "'succeeded', 200, 24, 17, 125.5, 0.01, 'USD', 'exported', "
                "TIMESTAMPTZ '2026-07-21 10:00:00+00', "
                "TIMESTAMPTZ '2026-07-21 10:00:00.1255+00')"
            ),
            {"org": org_id, "run": run_id, "trace": "f" * 32},
        )

    response = TestClient(_app_for(migrated_db, _reader(org_id))).get("/api/v1/traces")

    assert response.status_code == 200
    row = response.json()["data"][0]
    assert row["request_id"] == "request-physical-0001"
    assert row["method"] == "POST"
    assert row["destination_host"] == "target.example.test"
    assert row["relative_path"] == "chat"
    assert row["finished_at"].startswith("2026-07-21T10:00:00.125500")
    assert row["langfuse_status"] == "exported"
    assert row["request_preview"] == '{"turns":["synthetic"]}'
    assert row["response_preview"] == '{"answer":"safe"}'
    assert len(row["request_sha256"]) == 64
    assert len(row["response_sha256"]) == 64
    assert row["inspection_flags"] == []
