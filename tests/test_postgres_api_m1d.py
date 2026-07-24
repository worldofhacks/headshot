"""End-to-end HTTP-to-PostgreSQL contracts for the M1d control plane."""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.hosted_prompts import hosted_prompt
from agentforge.agents.runtime import default_assignment
from agentforge.api.postgres import PostgresApiBackend, _redact_evidence_display, _safe
from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.dependencies import get_clerk_auth_config, require_authenticated
from agentforge.auth.principal import Principal
from agentforge.campaign.corpus import load_full_scan_corpus
from agentforge.control_plane import ControlPlaneStore
from agentforge.correlation import campaign_trace_id
from agentforge.policy.recorder import ExecutionRecorder
from agentforge.security_tools.repository import SecurityToolEvidenceRepository
from agentforge.target.spec import SafetyCaps, TargetLifecycle
from agentforge.telemetry import OutboundHttpTelemetry
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
                "hosted_configuration_sets, "
                "tool_execution_errors, security_tool_findings, scan_artifacts, "
                "security_tool_runs, finding_decision_events, audit_events, command_idempotency, "
                "campaign_attempts, campaign_run_events, campaign_runs, "
                "campaign_authorization_decisions, campaign_authorization_requests, "
                "runtime_component_status, "
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


def _hosted_configuration_payload() -> dict[str, Any]:
    identities = {
        "orchestrator": ("anthropic/claude-opus-4.8", "anthropic", 9, "0.75"),
        "red_team": ("qwen/qwen3.5-397b-a17b", "together", 19, "1"),
        "judge": ("google/gemini-2.5-pro", "google-vertex", 19, "2.5"),
        "documentation": ("openai/gpt-5.4", "openai", 9, "0.5"),
    }
    roles = []
    for role, (model, upstream, calls, usd) in identities.items():
        roles.append(
            {
                "role": role,
                "provider": "openrouter",
                "model_id": model,
                "upstream_provider": upstream,
                "credential_reference": (
                    f"secretref://staging/openrouter/{role}/generation-20260724"
                ),
                "prompt_sha256": hosted_prompt(role).prompt_sha256,
                "policy_sha256": hashlib.sha256(f"{role}:policy".encode()).hexdigest(),
                "prices": {
                    "input_usd_per_million_tokens": "1",
                    "output_usd_per_million_tokens": "2",
                    "reasoning_usd_per_million_tokens": "3",
                },
                "limits": {
                    "max_calls": calls,
                    "max_input_tokens": 100000,
                    "max_output_tokens": 20000,
                    "max_reasoning_tokens": 10000,
                    "max_usd": usd,
                    "max_retries": 1,
                    "max_requests_per_second": "0.5",
                    "max_concurrency": 1,
                },
            }
        )
    return {
        "schema_version": "1",
        "roles": roles,
        "global_limits": {
            "max_calls": 56,
            "max_input_tokens": 400000,
            "max_output_tokens": 80000,
            "max_reasoning_tokens": 40000,
            "max_usd": "5",
            "max_retries": 1,
            "max_requests_per_second": "0.5",
            "max_concurrency": 1,
        },
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


def _seed_second_ready_target(engine: Engine, principal: Principal) -> None:
    store = ControlPlaneStore(engine, environment="staging")
    backend = PostgresApiBackend(engine, environment="staging")
    target_payload = _target_payload()
    target_payload.update(
        {
            "target_id": "copilot-api-b",
            "name": "Clinical Co-Pilot secondary staging entry",
            "base_url": "https://target-b.example.test/openemr",
            "allowlisted_hosts": ["target-b.example.test"],
            "credential_ref": "secretref://staging/copilot-api-b",
        }
    )
    surface_payload = _surface_payload()
    surface_payload.update({"surface_id": "chat-api-b"})
    store.register_target(
        principal=principal,
        target=backend._target(target_payload),
        idempotency_key="server-catalog-target-b-0001",
    )
    store.register_surface(
        principal=principal,
        surface=backend._surface("copilot-api-b", surface_payload),
        idempotency_key="server-catalog-surface-b-0001",
    )
    for lifecycle in (TargetLifecycle.VALIDATING, TargetLifecycle.READY):
        store.transition_target(
            principal=principal,
            target_id="copilot-api-b",
            version="1.0.0",
            lifecycle=lifecycle,
            idempotency_key=f"server-catalog-lifecycle-b-{lifecycle.value}-0001",
        )


def _seed_scheduled_tool_attempt(
    engine: Engine,
    launcher: Principal,
    *,
    target_id: str = "copilot-api",
    surface_id: str = "chat-api",
) -> tuple[Any, Any, Any]:
    store = ControlPlaneStore(engine, environment="staging")
    scope = store.build_scope(
        principal=launcher,
        target_id=target_id,
        target_version="1.0.0",
        surface_id=surface_id,
        surface_version="1.0.0",
        corpus_hash="c" * 64,
        caps=SafetyCaps(
            budget_usd=2.0,
            max_attempts_per_run=3,
            target_requests_per_second=1.0,
            run_timeout_seconds=120.0,
        ),
        run_nonce=f"tooling-scheduled-{target_id}-0001",
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10),
        idempotency_key=f"tooling-request-{target_id}-0001",
    )
    store.decide_campaign_authorization(
        principal=_principal(APPROVER_ID, "org:campaign:authorize"),
        request_id=request.request_id,
        decision="approved",
        idempotency_key=f"tooling-approve-{target_id}-0001",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key=f"tooling-launch-{target_id}-0001",
    )
    attempt = store.ensure_campaign_attempt(
        run_id=run.run_id,
        ordinal=0,
        case_id=f"tooling-{target_id}-garak-case",
        case_content_hash="d" * 64,
        category="prompt_injection",
        severity="low",
        attack_class="boundary",
        owasp_mappings=[
            {
                "framework": "OWASP LLM",
                "version": "2025",
                "id": "LLM01",
                "name": "Prompt Injection",
            }
        ],
        fixture_provenance={
            "classification": "synthetic",
            "fixture_id": "tooling-read-model-fixture",
            "fixture_version": "1.0.0",
            "source": "hand_authored",
            "contains_real_phi": False,
        },
        source_tool="garak",
        source_technique="scheduled-only-probe",
    )
    return run, attempt, scope


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
    for row in agents.json()["data"]:
        assignment = row["active_assignment"]
        assert assignment["resolved_model"] is None
        assert assignment["upstream_provider"] is None
        assert assignment["prompt_sha256"] is None
        assert assignment["prompt_version"] is None
    tool_rows = {row["tool_id"]: row for row in tooling.json()["data"]}
    assert tool_rows["garak"]["applicability"] == "in_campaign"
    assert tool_rows["garak"]["reviewed_candidate_count"] == 1
    assert tool_rows["pyrit"]["reviewed_candidate_count"] == 3
    assert tool_rows["zap"]["applicability"] == "companion_scan"
    assert tool_rows["semgrep"]["applicability"] == "platform_assurance"
    assert all(row["runtime_state"] == "idle" for row in tool_rows.values())
    assert all(row["evidenced_finding_count"] == 0 for row in tool_rows.values())
    assert all(row["last_error_code"] is None for row in tool_rows.values())

    per_role = client.post(
        "/api/v1/agents/red_team/configuration",
        json={
            "provider": "openrouter",
            "model": "provider/model-v1",
            "execution_mode": "hosted_advisory",
            "rationale": "Evaluate a reviewed hosted generator for a future corpus.",
        },
        headers=_headers("agent-config-stage-0001"),
    )
    assert per_role.status_code == 503
    assert per_role.json()["reason_code"] == "atomic_hosted_configuration_set_required"

    staged = client.post(
        "/api/v1/hosted-configuration-sets",
        json={
            "configuration": _hosted_configuration_payload(),
            "release_sha256": "f" * 64,
            "rationale": "Stage all four reviewed hosted identities atomically.",
        },
        headers=_headers("hosted-config-set-stage-0001"),
    )
    assert staged.status_code == 200, staged.text
    configuration_sha256 = staged.json()["resource_id"]
    projection = client.get(f"/api/v1/hosted-configuration-sets/{configuration_sha256}")
    assert projection.status_code == 200
    assert projection.json()["state"] == "ready"
    assert projection.json()["data"]["activation_state"] == "staged_pending_authorization"
    assert projection.json()["data"]["runtime_reason"] == "hosted_runtime_not_composed"
    assert len(projection.json()["data"]["roles"]) == 4
    assert "secretref://" not in projection.text
    assert all(
        role["provider_reference_bound"] is False for role in projection.json()["data"]["roles"]
    )
    staged_agents_response = client.get("/api/v1/agents")
    staged_agents = {row["role"]: row for row in staged_agents_response.json()["data"]}
    staged_red_team = staged_agents["red_team"]["staged_assignment"]
    assert staged_red_team["provider"] == "openrouter"
    assert staged_red_team["model"] == "qwen/qwen3.5-397b-a17b"
    assert staged_red_team["resolved_model"] is None
    assert staged_red_team["upstream_provider"] is None
    assert staged_red_team["prompt_sha256"] == hosted_prompt("red_team").prompt_sha256
    assert staged_red_team["prompt_version"] == hosted_prompt("red_team").version
    assert staged_red_team["configuration_sha256"] == configuration_sha256
    assert "system_prompt" not in staged_agents_response.text

    prompt = client.get("/api/v1/agents/red_team/prompt")
    assert prompt.status_code == 200
    assert prompt.json()["state"] == "ready"
    assert prompt.json()["data"] == {
        "role": "red_team",
        "prompt_version": hosted_prompt("red_team").version,
        "prompt_sha256": hosted_prompt("red_team").prompt_sha256,
        "system_prompt": hosted_prompt("red_team").system_prompt,
    }
    preflight = client.get(f"/api/v1/hosted-configuration-sets/{configuration_sha256}/preflight")
    assert preflight.status_code == 200
    assert preflight.json()["state"] == "degraded"
    assert preflight.json()["reason_code"] == "hosted_runtime_not_composed"
    assert preflight.json()["data"]["preflight"]["provider_calls_performed"] == 0
    assert preflight.json()["data"]["preflight"]["target_calls_performed"] == 0

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
    assert rejected.status_code == 503
    assert rejected.json()["reason_code"] == "atomic_hosted_configuration_set_required"


def test_agent_activation_calibration_and_budget_follow_latest_authority(
    migrated_db: Engine,
) -> None:
    """Historical hosted work cannot override a later deterministic restore."""

    _clean(migrated_db)
    organization_id = "org_M1dAgentAuthority"
    configuration = HostedConfigurationSet.from_payload(_hosted_configuration_payload())
    configuration_sha256 = configuration.configuration_sha256
    judge_configuration = next(role for role in configuration.roles if role.role == "judge")
    generation_policy_sha256 = DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256
    historical_calibration_id = f"JC-{'1' * 64}"
    current_calibration_id = f"JC-{'2' * 64}"
    deterministic = default_assignment("judge")
    first_run = "run-hosted-authority-history"
    first_request = "request-hosted-authority-history"
    first_scope_hash = "1" * 64
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO hosted_configuration_sets "
                "(organization_id, configuration_sha256, schema_version, release_sha256, "
                "payload, rationale, actor_user_id, actor_session_id, created_at) VALUES "
                "(:org, :configuration, '1', :release, CAST(:payload AS jsonb), "
                "'Reviewed four-role hosted configuration.', :actor, :session, :created_at)"
            ),
            {
                "org": organization_id,
                "configuration": configuration_sha256,
                "release": "a" * 64,
                "payload": json.dumps(_hosted_configuration_payload()),
                "actor": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
                "created_at": datetime.datetime(2026, 7, 24, 9, tzinfo=datetime.UTC),
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at, created_at) VALUES "
                "(:request, :org, :scope_hash, CAST(:scope AS jsonb), :actor, :session, "
                ":expires_at, :created_at)"
            ),
            {
                "request": first_request,
                "org": organization_id,
                "scope_hash": first_scope_hash,
                "scope": json.dumps(
                    {
                        "execution_profile": "live",
                        "hosted_run": {
                            "configuration_set_sha256": configuration_sha256,
                            "generation_policy_sha256": generation_policy_sha256,
                        },
                    }
                ),
                "actor": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
                "expires_at": datetime.datetime(2026, 7, 25, tzinfo=datetime.UTC),
                "created_at": datetime.datetime(2026, 7, 24, 9, 30, tzinfo=datetime.UTC),
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id, created_at) VALUES "
                "(:run, :org, :request, :scope_hash, :actor, :session, :created_at)"
            ),
            {
                "run": first_run,
                "org": organization_id,
                "request": first_request,
                "scope_hash": first_scope_hash,
                "actor": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
                "created_at": datetime.datetime(2026, 7, 24, 10, tzinfo=datetime.UTC),
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_run_events "
                "(organization_id, run_id, state, created_at) "
                "VALUES (:org, :run, 'complete', :created_at)"
            ),
            {
                "org": organization_id,
                "run": first_run,
                "created_at": datetime.datetime(2026, 7, 24, 10, 30, tzinfo=datetime.UTC),
            },
        )
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, agent_role, status, provider, "
                "model, execution_mode, configuration_version, input_sha256, output_sha256, "
                "returned_model, upstream_provider, provider_request_id, input_tokens, "
                "output_tokens, reasoning_tokens, measured_cost, trace_id, "
                "configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, physical_attempts, judge_calibration_id, "
                "judge_calibration_state, oracle_agreement, decision_authority, "
                "langfuse_status, detail, started_at, finished_at, duration_ms) VALUES "
                "('judge-history', :org, :run, 'judge', 'succeeded', 'openrouter', :model, "
                "'hosted_advisory', 1, :input_hash, :output_hash, :model, "
                "'Google AI Studio', 'provider-request-history', 100, 20, 5, 0.2, "
                ":trace, :configuration, :role_configuration, :generation_policy, 1, "
                ":calibration, 'enabled', true, 'model', 'disabled', '{}'::jsonb, "
                ":started_at, :finished_at, 1000)"
            ),
            {
                "org": organization_id,
                "run": first_run,
                "model": judge_configuration.model_id,
                "input_hash": "2" * 64,
                "output_hash": "3" * 64,
                "trace": "4" * 32,
                "configuration": configuration_sha256,
                "role_configuration": judge_configuration.configuration_sha256,
                "generation_policy": generation_policy_sha256,
                "calibration": historical_calibration_id,
                "started_at": datetime.datetime(2026, 7, 24, 10, 5, tzinfo=datetime.UTC),
                "finished_at": datetime.datetime(2026, 7, 24, 10, 5, 1, tzinfo=datetime.UTC),
            },
        )
        connection.execute(
            text(
                "INSERT INTO agent_configuration_versions "
                "(organization_id, agent_role, version, provider, model, execution_mode, "
                "activation_state, configuration_sha256, rationale, actor_user_id, "
                "actor_session_id, created_at) VALUES "
                "(:org, 'judge', 1, :provider, :model, 'deterministic', 'active', "
                ":configuration, 'Restore deterministic authority.', :actor, :session, "
                ":created_at)"
            ),
            {
                "org": organization_id,
                "provider": deterministic.provider,
                "model": deterministic.model,
                "configuration": deterministic.configuration_sha256,
                "actor": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
                "created_at": datetime.datetime(2026, 7, 24, 11, tzinfo=datetime.UTC),
            },
        )

    client = TestClient(_app_for(migrated_db, _reader(organization_id)))
    restored_judge = next(
        row for row in client.get("/api/v1/agents").json()["data"] if row["role"] == "judge"
    )
    assert restored_judge["active_assignment"]["execution_mode"] == "deterministic"
    assert restored_judge["active_assignment"]["model"] == "oracle-precedence-v1"
    assert restored_judge["judge_calibration"] == {
        "state": "unavailable",
        "calibration_id": None,
        "decision_authority": "none",
        "oracle_comparison_count": 0,
        "oracle_agreement_count": 0,
        "oracle_agreement_rate": None,
        "status_label": "not yet measured",
    }

    current_run = "run-hosted-authority-current"
    current_request = "request-hosted-authority-current"
    current_scope_hash = "5" * 64
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at, created_at) VALUES "
                "(:request, :org, :scope_hash, CAST(:scope AS jsonb), :actor, :session, "
                ":expires_at, :created_at)"
            ),
            {
                "request": current_request,
                "org": organization_id,
                "scope_hash": current_scope_hash,
                "scope": json.dumps(
                    {
                        "execution_profile": "live",
                        "hosted_run": {
                            "configuration_set_sha256": configuration_sha256,
                            "generation_policy_sha256": generation_policy_sha256,
                        },
                    }
                ),
                "actor": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
                "expires_at": datetime.datetime(2026, 7, 25, tzinfo=datetime.UTC),
                "created_at": datetime.datetime(2026, 7, 24, 11, 30, tzinfo=datetime.UTC),
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id, created_at) VALUES "
                "(:run, :org, :request, :scope_hash, :actor, :session, :created_at)"
            ),
            {
                "run": current_run,
                "org": organization_id,
                "request": current_request,
                "scope_hash": current_scope_hash,
                "actor": LAUNCHER_ID,
                "session": "sess_M1dApiLauncher",
                "created_at": datetime.datetime(2026, 7, 24, 12, tzinfo=datetime.UTC),
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_run_events "
                "(organization_id, run_id, state, created_at) "
                "VALUES (:org, :run, 'running', :created_at)"
            ),
            {
                "org": organization_id,
                "run": current_run,
                "created_at": datetime.datetime(2026, 7, 24, 12, 1, tzinfo=datetime.UTC),
            },
        )
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, agent_role, status, provider, "
                "model, execution_mode, configuration_version, input_sha256, output_sha256, "
                "returned_model, upstream_provider, provider_request_id, input_tokens, "
                "output_tokens, reasoning_tokens, measured_cost, trace_id, "
                "configuration_set_sha256, role_configuration_sha256, "
                "generation_policy_sha256, physical_attempts, judge_calibration_id, "
                "judge_calibration_state, oracle_agreement, decision_authority, "
                "langfuse_status, detail, started_at, finished_at, duration_ms) VALUES "
                "('judge-current-measured', :org, :run, 'judge', 'succeeded', 'openrouter', "
                ":model, 'hosted_advisory', 1, :input_hash, :output_hash, :model, "
                "'Google AI Studio', 'provider-request-current', 100, 20, 5, 0.1, "
                ":trace, :configuration, :role_configuration, :generation_policy, 2, "
                ":calibration, 'failed', false, 'oracle', 'disabled', '{}'::jsonb, "
                ":started_at, :finished_at, 1000), "
                "('judge-current-running', :org, :run, 'judge', 'running', 'openrouter', "
                ":model, 'hosted_advisory', 1, :running_input_hash, NULL, NULL, NULL, NULL, "
                "NULL, NULL, NULL, 0, :running_trace, :configuration, :role_configuration, "
                ":generation_policy, NULL, :calibration, 'failed', NULL, NULL, 'queued', "
                "'{}'::jsonb, :running_started_at, NULL, NULL)"
            ),
            {
                "org": organization_id,
                "run": current_run,
                "model": judge_configuration.model_id,
                "input_hash": "6" * 64,
                "output_hash": "7" * 64,
                "trace": "8" * 32,
                "running_input_hash": "9" * 64,
                "running_trace": "a" * 32,
                "configuration": configuration_sha256,
                "role_configuration": judge_configuration.configuration_sha256,
                "generation_policy": generation_policy_sha256,
                "calibration": current_calibration_id,
                "started_at": datetime.datetime(2026, 7, 24, 12, 5, tzinfo=datetime.UTC),
                "finished_at": datetime.datetime(2026, 7, 24, 12, 5, 1, tzinfo=datetime.UTC),
                "running_started_at": datetime.datetime(
                    2026,
                    7,
                    24,
                    12,
                    6,
                    tzinfo=datetime.UTC,
                ),
            },
        )

    agents = client.get("/api/v1/agents").json()
    assert agents["state"] == "ready", agents
    judge = next(row for row in agents["data"] if row["role"] == "judge")
    assert judge["active_assignment"]["execution_mode"] == "hosted_advisory"
    assert judge["active_assignment"]["configuration_sha256"] == configuration_sha256
    assert judge["active_assignment"]["resolved_model"] == judge_configuration.model_id
    assert judge["active_assignment"]["upstream_provider"] == "Google AI Studio"
    assert judge["judge_calibration"] == {
        "state": "failed",
        "calibration_id": current_calibration_id,
        "decision_authority": "oracle",
        "oracle_comparison_count": 1,
        "oracle_agreement_count": 0,
        "oracle_agreement_rate": 0.0,
        "status_label": "live, verified against oracle",
    }

    budget = judge["provider_budget"]
    assert budget["status"] == "active"
    assert budget["role_physical_calls"] == 1
    assert budget["role_unresolved_physical_calls"] == 3
    assert budget["role_calls_remaining"] == 15
    assert abs(budget["role_unresolved_usd_exposure"] - 0.386016) < 1e-9
    assert abs(budget["role_usd_remaining"] - 2.013984) < 1e-9
    assert budget["global_physical_calls"] == 1
    assert budget["global_unresolved_physical_calls"] == 3
    assert budget["global_calls_remaining"] == 52
    assert abs(budget["global_unresolved_usd_exposure"] - 0.386016) < 1e-9
    assert abs(budget["global_usd_remaining"] - 4.513984) < 1e-9

    costs = client.get("/api/v1/costs").json()
    assert costs["state"] == "ready", costs
    judge_costs = {
        row["campaign_id"]: row
        for row in costs["data"]
        if row["record_kind"] == "agent" and row["agent_role"] == "judge"
    }
    assert judge_costs[first_run]["provider_budget"]["status"] == "historical"
    assert judge_costs[current_run]["provider_budget"]["status"] == "active"
    assert judge_costs[current_run]["provider_budget"]["role_unresolved_physical_calls"] == 3


def test_tooling_does_not_count_scheduled_attempt_without_authoritative_result(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    launcher = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:campaign:launch",
        "org:targets:manage",
    )
    _seed_ready_target(migrated_db, launcher)
    _seed_scheduled_tool_attempt(migrated_db, launcher)

    result = PostgresApiBackend(
        migrated_db,
        environment="staging",
        corpus=load_full_scan_corpus(),
    ).read("tooling", launcher)

    assert result.state == "ready"
    garak = next(
        row
        for row in result.data
        if row["tool_id"] == "garak"
        and row["target_id"] == "copilot-api"
        and row["surface_id"] == "chat-api"
    )
    assert garak["executed_attempt_count"] == 0
    assert garak["last_executed_at"] is None
    assert garak["runtime_state"] == "idle"


def test_tooling_evidence_is_isolated_by_target_and_surface(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    launcher = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:campaign:launch",
        "org:targets:manage",
    )
    _seed_ready_target(migrated_db, launcher)
    _seed_second_ready_target(migrated_db, launcher)
    run, attempt, scope = _seed_scheduled_tool_attempt(migrated_db, launcher)
    executed_at = "2026-07-24T12:00:00+00:00"
    with migrated_db.begin() as connection:
        ExecutionRecorder().record(
            {
                "schema_version": "1",
                "campaign_run_id": run.run_id,
                "attempt_id": attempt.attempt_id,
                "campaign_id": run.run_id,
                "target_id": scope.target_id,
                "target_version": scope.target_version,
                "attack_attempt": {
                    "schema_version": "1",
                    "case_ref": "tooling-copilot-api-garak-case",
                    "input_sequence": ["Use the reviewed synthetic tooling fixture."],
                    "category": "prompt_injection",
                },
                "request_transcript": {"turns": ["Use the reviewed synthetic tooling fixture."]},
                "response_transcript": "Synthetic tooling response.",
                "policy_decision_id": "tooling-policy-decision-0001",
                "executed_at": executed_at,
                "trace_id": None,
                "correlation_id": run.run_id,
                "recorder_identity": "recorder@1",
                "recorder_version": "1",
                "organization_id": ORG_ID,
                "surface_id": scope.surface_id,
                "surface_version": scope.surface_version,
                "authorization_scope_hash": run.scope_hash,
                "execution_profile": "live",
                "evidence_provenance": "live_target",
            },
            connection,
        )

    raw_artifact = b'{"scan":"synthetic"}'
    artifact_sha256 = hashlib.sha256(raw_artifact).hexdigest()
    scan_run = {
        "schema_version": "1",
        "run_id": "zap-tooling-scope-0001",
        "tool_name": "zap",
        "tool_version": "2.17.0",
        "configuration_sha256": "e" * 64,
        "run_nonce": "zap-tooling-scope-nonce-0001",
        "target_id": "copilot-api",
        "surface_id": "chat-api",
        "scan_provenance": "live_target",
        "status": "completed",
        "started_at": executed_at,
        "finished_at": executed_at,
        "artifact_sha256": artifact_sha256,
    }
    scan_finding = {
        "schema_version": "1",
        "finding_id": "zap:toolingscope000000000001",
        "tool_name": scan_run["tool_name"],
        "tool_version": scan_run["tool_version"],
        "configuration_sha256": scan_run["configuration_sha256"],
        "run_id": scan_run["run_id"],
        "run_nonce": scan_run["run_nonce"],
        "target_id": scan_run["target_id"],
        "surface_id": scan_run["surface_id"],
        "scan_provenance": scan_run["scan_provenance"],
        "observed_at": executed_at,
        "raw_artifact_sha256": artifact_sha256,
        "owasp_mappings": ["A05:2021"],
        "severity": "low",
        "confidence": 0.9,
        "reproduction_evidence": {
            "summary": "Synthetic scoped ZAP observation",
            "artifact_locator": "docs/evidence/zap/tooling-scope.json#finding=0",
        },
        "validation_state": "unvalidated",
        "disposition": "validate",
        "human_publication_state": "blocked_pending_human_approval",
        "source_kind": "security_tool",
        "evidence_provenance": "scan_only",
    }
    SecurityToolEvidenceRepository(migrated_db).ingest(
        organization_id=ORG_ID,
        run=scan_run,
        artifact={
            "schema_version": "1",
            "artifact_id": "artifact-zap-tooling-scope-0001",
            "run_id": scan_run["run_id"],
            "tool_name": scan_run["tool_name"],
            "tool_version": scan_run["tool_version"],
            "media_type": "application/json",
            "sha256": artifact_sha256,
            "sanitized": True,
            "byte_length": len(raw_artifact),
            "created_at": executed_at,
            "artifact_locator": "docs/evidence/zap/tooling-scope.json",
        },
        sanitized_artifact=raw_artifact,
        findings=[scan_finding],
    )

    result = PostgresApiBackend(
        migrated_db,
        environment="staging",
        corpus=load_full_scan_corpus(),
    ).read("tooling", launcher)

    assert result.state == "ready"
    rows = {(row["tool_id"], row["target_id"], row["surface_id"]): row for row in result.data}
    garak_a = rows[("garak", "copilot-api", "chat-api")]
    garak_b = rows[("garak", "copilot-api-b", "chat-api-b")]
    assert garak_a["executed_attempt_count"] == 1
    assert garak_a["runtime_state"] == "evidenced"
    assert garak_a["last_executed_at"] is not None
    assert garak_b["executed_attempt_count"] == 0
    assert garak_b["runtime_state"] == "idle"
    assert garak_b["last_executed_at"] is None

    zap_a = rows[("zap", "copilot-api", "chat-api")]
    zap_b = rows[("zap", "copilot-api-b", "chat-api-b")]
    assert zap_a["recorded_scan_count"] == 1
    assert zap_a["recorded_finding_count"] == 1
    assert zap_a["evidenced_finding_count"] == 1
    assert zap_a["runtime_state"] == "evidenced"
    assert zap_a["last_executed_at"] is not None
    assert zap_b["recorded_scan_count"] == 0
    assert zap_b["recorded_finding_count"] == 0
    assert zap_b["evidenced_finding_count"] == 0
    assert zap_b["runtime_state"] == "idle"
    assert zap_b["last_executed_at"] is None


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
            "category": None,
            "target_version": None,
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

    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "UPDATE scan_artifacts SET sanitized_payload = :payload "
                "WHERE organization_id = :org AND artifact_id = :artifact"
            ),
            {
                "payload": b'{"site":{}}',
                "org": ORG_ID,
                "artifact": artifact["artifact_id"],
            },
        )

    tampered = PostgresApiBackend(migrated_db, environment="staging").read(
        "findings", _principal(LAUNCHER_ID, "org:findings:read")
    )
    assert tampered.state == "ready"
    assert tampered.data[0]["evidence_integrity"] == "unavailable"
    assert tampered.data[0]["evidence_content_hash"] is None


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

    client.app.state.api_backend = PostgresApiBackend(
        migrated_db,
        environment="staging",
        runner_available=True,
    )
    stale = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("api-launch-stale-runner-0001"),
    )
    assert stale.status_code == 503
    assert stale.json()["reason_code"] == "runner_heartbeat_stale"
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO runtime_component_status "
                "(environment, component_id, name, kind, availability, detail) VALUES "
                "('staging', 'runner', 'Private Runner', 'worker', "
                "'operational and evidenced', 'fresh test heartbeat') "
                "ON CONFLICT (environment, component_id) DO UPDATE SET "
                "availability = EXCLUDED.availability, heartbeat_at = clock_timestamp()"
            )
        )
    launched = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("api-launch-fresh-runner-0001"),
    )
    assert launched.status_code == 202, launched.text
    approvals = client.get("/api/v1/approvals").json()["data"]
    consumed = next(item for item in approvals if item["request_id"] == request_id)
    assert consumed["consumed"] is True
    assert consumed["expired"] is False
    with migrated_db.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM campaign_runs")).scalar_one() == 1
        assert connection.execute(text("SELECT count(*) FROM jobs")).scalar_one() == 1


def test_hosted_authorization_is_bound_but_launch_stays_unavailable_until_composed(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    launcher = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:campaign:launch",
        "org:targets:manage",
        "org:config:manage",
    )
    client = TestClient(_app(migrated_db, launcher))
    _seed_ready_target(migrated_db, launcher)

    staged = client.post(
        "/api/v1/hosted-configuration-sets",
        json={
            "configuration": _hosted_configuration_payload(),
            "release_sha256": "e" * 64,
            "rationale": "Bind the reviewed four-model set to one authorization.",
        },
        headers=_headers("hosted-config-set-stage-launch-0001"),
    )
    assert staged.status_code == 200, staged.text
    configuration_sha256 = staged.json()["resource_id"]

    requested = client.post(
        "/api/v1/campaign-authorization-requests",
        json={
            "target_id": "copilot-api",
            "target_version": "1.0.0",
            "surface_id": "chat-api",
            "surface_version": "1.0.0",
            "corpus_hash": "a" * 64,
            "run_nonce": "nonce-hosted-fixture-0001",
            "caps": {
                "budget_usd": 2.0,
                "max_attempts_per_run": 3,
                "target_requests_per_second": 0.5,
                "run_timeout_seconds": 60.0,
            },
            "hosted_run": {
                "configuration_set_sha256": configuration_sha256,
                "generation_policy_sha256": "d" * 64,
                "session_generation": "generation-20260724",
                "provider_model_call_limit": 56,
                "provider_model_spend_limit_usd": "5",
                "provider_max_retries": 1,
                "provider_max_concurrency": 1,
                "provider_timeout_seconds": 30.0,
            },
            "expires_in_seconds": 600,
        },
        headers=_headers("hosted-auth-request-0001"),
    )
    assert requested.status_code == 200, requested.text
    request_id = requested.json()["resource_id"]
    approval_scope = next(
        item
        for item in client.get("/api/v1/approvals").json()["data"]
        if item["request_id"] == request_id
    )
    assert approval_scope["hosted_run"] == {
        "configuration_set_sha256": configuration_sha256,
        "generation_policy_sha256": "d" * 64,
        "session_generation": "generation-20260724",
        "provider_model_call_limit": 56,
        "provider_model_spend_limit_usd": "5",
        "provider_max_retries": 1,
        "provider_max_concurrency": 1,
        "provider_timeout_seconds": 30.0,
    }
    assert "credential_ref" not in json.dumps(approval_scope)
    preflight = client.get(f"/api/v1/campaign-authorization-requests/{request_id}/preflight")
    assert preflight.status_code == 200
    assert preflight.json()["state"] == "degraded"
    assert preflight.json()["reason_code"] == "hosted_runtime_not_composed"
    assert preflight.json()["data"]["provider_calls_performed"] == 0
    assert preflight.json()["data"]["target_calls_performed"] == 0
    assert "credential_ref" not in preflight.text

    distinct_client = TestClient(
        _app(migrated_db, _principal(APPROVER_ID, "org:campaign:authorize"))
    )
    approved = distinct_client.post(
        f"/api/v1/campaign-authorization-requests/{request_id}/decisions",
        json={"decision": "approved"},
        headers=_headers("hosted-auth-decision-0001"),
    )
    assert approved.status_code == 200, approved.text

    client.app.state.api_backend = PostgresApiBackend(
        migrated_db,
        environment="staging",
        runner_available=True,
        hosted_runtime_available=False,
    )
    launch = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("hosted-launch-unavailable-0001"),
    )
    assert launch.status_code == 503
    assert launch.json()["reason_code"] == "hosted_runtime_not_composed"
    with migrated_db.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM campaign_runs")).scalar_one() == 0
        assert connection.execute(text("SELECT count(*) FROM jobs")).scalar_one() == 0

    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO runtime_component_status "
                "(environment, component_id, name, kind, availability, detail) VALUES "
                "('staging', 'runner', 'Private Runner', 'worker', "
                "'operational and evidenced', 'fresh test heartbeat') "
                "ON CONFLICT (environment, component_id) DO UPDATE SET "
                "availability = EXCLUDED.availability, heartbeat_at = clock_timestamp()"
            )
        )
    client.app.state.api_backend = PostgresApiBackend(
        migrated_db,
        environment="staging",
        runner_available=True,
        hosted_runtime_available=True,
        hosted_provider_bindings_verified=False,
    )
    unverified = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("hosted-launch-unverified-bindings-0001"),
    )
    assert unverified.status_code == 503
    assert unverified.json()["reason_code"] == "provider_credentials_runner_unverified"
    missing_hosted_preflight = client.get(
        f"/api/v1/hosted-configuration-sets/{configuration_sha256}/preflight"
    )
    assert missing_hosted_preflight.status_code == 200
    assert missing_hosted_preflight.json()["state"] == "degraded"
    assert (
        missing_hosted_preflight.json()["reason_code"] == "provider_credentials_runner_unverified"
    )
    missing_campaign_preflight = client.get(
        f"/api/v1/campaign-authorization-requests/{request_id}/preflight"
    )
    assert missing_campaign_preflight.status_code == 200
    assert missing_campaign_preflight.json()["state"] == "degraded"
    assert (
        missing_campaign_preflight.json()["reason_code"] == "provider_credentials_runner_unverified"
    )
    with migrated_db.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM campaign_runs")).scalar_one() == 0
        assert connection.execute(text("SELECT count(*) FROM jobs")).scalar_one() == 0

    telemetry = OutboundHttpTelemetry(migrated_db, environment="staging")
    telemetry.hosted_runtime_heartbeat(
        configuration_sha256="b" * 64,
        provider_bindings_verified=True,
        langfuse_observation_ready=True,
    )
    wrong_configuration = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("hosted-launch-wrong-config-heartbeat-0001"),
    )
    assert wrong_configuration.status_code == 503
    assert wrong_configuration.json()["reason_code"] == "provider_credentials_runner_unverified"

    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO runtime_component_status "
                "(environment, component_id, name, kind, availability, detail) VALUES "
                "('staging', :configuration, 'Scheduler collision', 'scheduler', "
                "'operational and evidenced', 'not a hosted runtime observation') "
                "ON CONFLICT (environment, component_id) DO UPDATE SET "
                "name = EXCLUDED.name, kind = EXCLUDED.kind, "
                "availability = EXCLUDED.availability, detail = EXCLUDED.detail, "
                "heartbeat_at = clock_timestamp()"
            ),
            {"configuration": configuration_sha256},
        )
    wrong_component_kind = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("hosted-launch-wrong-component-kind-0001"),
    )
    assert wrong_component_kind.status_code == 503
    assert wrong_component_kind.json()["reason_code"] == "provider_credentials_runner_unverified"

    telemetry.hosted_runtime_heartbeat(
        configuration_sha256=configuration_sha256,
        provider_bindings_verified=True,
        langfuse_observation_ready=True,
    )
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE runtime_component_status "
                "SET heartbeat_at = clock_timestamp() - interval '91 seconds' "
                "WHERE environment = 'staging' AND component_id = :configuration"
            ),
            {"configuration": configuration_sha256},
        )
    stale_configuration = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("hosted-launch-stale-config-heartbeat-0001"),
    )
    assert stale_configuration.status_code == 503
    assert stale_configuration.json()["reason_code"] == "provider_credentials_runner_unverified"
    stale_hosted_preflight = client.get(
        f"/api/v1/hosted-configuration-sets/{configuration_sha256}/preflight"
    )
    assert stale_hosted_preflight.status_code == 200
    assert stale_hosted_preflight.json()["state"] == "degraded"
    assert stale_hosted_preflight.json()["reason_code"] == (
        "provider_credentials_runner_unverified"
    )
    stale_campaign_preflight = client.get(
        f"/api/v1/campaign-authorization-requests/{request_id}/preflight"
    )
    assert stale_campaign_preflight.status_code == 200
    assert stale_campaign_preflight.json()["state"] == "degraded"
    assert stale_campaign_preflight.json()["reason_code"] == (
        "provider_credentials_runner_unverified"
    )

    telemetry.hosted_runtime_heartbeat(
        configuration_sha256=configuration_sha256,
        provider_bindings_verified=True,
        langfuse_observation_ready=True,
    )
    hosted_preflight = client.get(
        f"/api/v1/hosted-configuration-sets/{configuration_sha256}/preflight"
    )
    assert hosted_preflight.status_code == 200
    assert hosted_preflight.json()["state"] == "ready"
    assert hosted_preflight.json()["data"]["runtime_available"] is True
    assert hosted_preflight.json()["data"]["runtime_reason"] is None
    assert (
        hosted_preflight.json()["data"]["preflight"]["provider_binding_readiness"]
        == "runner_verified"
    )
    assert all(
        role["provider_reference_bound"] is True
        for role in hosted_preflight.json()["data"]["roles"]
    )
    assert "secretref://" not in hosted_preflight.text
    assert "credential_reference" not in hosted_preflight.text

    campaign_preflight = client.get(
        f"/api/v1/campaign-authorization-requests/{request_id}/preflight"
    )
    assert campaign_preflight.status_code == 200
    assert campaign_preflight.json()["state"] == "ready"
    assert campaign_preflight.json()["data"]["configuration_set_sha256"] == (configuration_sha256)
    assert campaign_preflight.json()["data"]["gates"]["provider_bindings_runner_verified"] is True
    assert campaign_preflight.json()["data"]["provider_calls_performed"] == 0
    assert campaign_preflight.json()["data"]["target_calls_performed"] == 0
    assert "secretref://" not in campaign_preflight.text
    assert "credential_reference" not in campaign_preflight.text

    launched = client.post(
        "/api/v1/campaigns",
        json={"authorization_request_id": request_id},
        headers=_headers("hosted-launch-exact-config-heartbeat-0001"),
    )
    assert launched.status_code == 202, launched.text
    with migrated_db.connect() as connection:
        assert connection.execute(text("SELECT count(*) FROM campaign_runs")).scalar_one() == 1
        assert connection.execute(text("SELECT count(*) FROM jobs")).scalar_one() == 1


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


def test_evidence_display_redacts_session_and_patient_identifiers_recursively() -> None:
    unsafe = {
        "session_id": "sess_raw-must-not-render",
        "patient": {
            "patient_id": "SYNTH-PATIENT-RAW-001",
            "note": (
                "SID=sess_raw-must-not-render; bare sess_unlabeled-private-001; "
                "MRN=MRN-0001; patient name: Synthetic Example; "
                "phone: (555) 010-1234; DOB 2000-01-02; "
                "address: 10 Example Street; patient@example.test; SSN 123-45-6789"
            ),
        },
    }

    rendered = json.dumps(_redact_evidence_display(unsafe), sort_keys=True)

    for forbidden in (
        "sess_raw-must-not-render",
        "SYNTH-PATIENT-RAW-001",
        "MRN-0001",
        "sess_unlabeled-private-001",
        "Synthetic Example",
        "(555) 010-1234",
        "2000-01-02",
        "10 Example Street",
        "patient@example.test",
        "123-45-6789",
    ):
        assert forbidden not in rendered


def test_attempt_evidence_is_verified_before_redaction_and_fails_closed_on_tamper(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    viewer = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:evidence:read",
        "org:campaign:launch",
        "org:targets:manage",
    )
    _seed_ready_target(migrated_db, viewer)
    run, attempt, scope = _seed_scheduled_tool_attempt(migrated_db, viewer)
    fields = {
        "schema_version": "1",
        "campaign_run_id": run.run_id,
        "attempt_id": attempt.attempt_id,
        "campaign_id": run.run_id,
        "target_id": scope.target_id,
        "target_version": scope.target_version,
        "attack_attempt": {
            "input_sequence": ["Review SYNTH-PATIENT-RAW-001 for patient name: Synthetic Example"],
            "patient_id": "SYNTH-PATIENT-RAW-001",
        },
        "request_transcript": {
            "session_id": "sess_raw-must-not-render",
            "message": (
                "bare sess_unlabeled-private-001; MRN=MRN-0001; "
                "phone: 555-010-1234; patient@example.test"
            ),
        },
        "response_transcript": (
            "SID=sess_raw-must-not-render; DOB 2000-01-02; "
            "address: 10 Example Street; SSN 123-45-6789"
        ),
        "policy_decision_id": "policy-evidence-read-0001",
        "executed_at": "2026-07-24T12:00:00+00:00",
        "trace_id": None,
        "correlation_id": run.run_id,
        "recorder_identity": "recorder@1",
        "recorder_version": "1",
        "organization_id": ORG_ID,
        "surface_id": scope.surface_id,
        "surface_version": scope.surface_version,
        "authorization_scope_hash": run.scope_hash,
        "execution_profile": "synthetic",
        "evidence_provenance": "synthetic_offline",
    }
    with migrated_db.begin() as connection:
        ExecutionRecorder().record(fields, connection)
        connection.execute(
            text(
                "INSERT INTO verdict "
                "(state, confidence, campaign_run_id, attempt_id, organization_id, "
                "reason_codes, confirmation_source) VALUES "
                "('EXPLOIT_CONFIRMED', 1.0, :run, :attempt, :org, "
                "'[\"oracle_confirmed\"]'::jsonb, 'oracle')"
            ),
            {"org": ORG_ID, "run": run.run_id, "attempt": attempt.attempt_id},
        )

    client = TestClient(_app(migrated_db, viewer))
    response = client.get(f"/api/v1/attempts/{attempt.attempt_id}/evidence")

    assert response.status_code == 200
    assert response.json()["state"] == "ready", response.text
    assert response.json()["data"]["verdict"] == "EXPLOIT_CONFIRMED"
    assert response.json()["data"]["confidence"] == 1.0
    rendered = response.text
    for forbidden in (
        "sess_raw-must-not-render",
        "sess_unlabeled-private-001",
        "SYNTH-PATIENT-RAW-001",
        "MRN-0001",
        "Synthetic Example",
        "555-010-1234",
        "2000-01-02",
        "10 Example Street",
        "patient@example.test",
        "123-45-6789",
    ):
        assert forbidden not in rendered
    assert "REDACTED" in rendered

    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "UPDATE verdict SET reason_codes = '[]'::jsonb "
                "WHERE organization_id = :org AND campaign_run_id = :run "
                "AND attempt_id = :attempt"
            ),
            {"org": ORG_ID, "run": run.run_id, "attempt": attempt.attempt_id},
        )

    invalid_verdict = client.get(f"/api/v1/attempts/{attempt.attempt_id}/evidence")
    assert invalid_verdict.status_code == 200
    assert invalid_verdict.json()["state"] == "unavailable"
    assert invalid_verdict.json()["reason_code"] == "verdict_integrity_failed"

    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "UPDATE attempt_result SET response_transcript = 'tampered' "
                "WHERE organization_id = :org AND campaign_run_id = :run "
                "AND attempt_id = :attempt"
            ),
            {"org": ORG_ID, "run": run.run_id, "attempt": attempt.attempt_id},
        )

    tampered = client.get(f"/api/v1/attempts/{attempt.attempt_id}/evidence")
    assert tampered.status_code == 200
    assert tampered.json()["state"] == "unavailable"
    assert tampered.json()["reason_code"] == "evidence_integrity_failed"


def test_attempt_evidence_identifier_ambiguity_fails_closed(migrated_db: Engine) -> None:
    _clean(migrated_db)
    viewer = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:evidence:read",
    )
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO attempt_result "
                "(organization_id, campaign_run_id, attempt_id, content_hash) VALUES "
                "(:org, 'run-ambiguous-a', 'attempt-ambiguous', :hash_a), "
                "(:org, 'run-ambiguous-b', 'attempt-ambiguous', :hash_b)"
            ),
            {"org": ORG_ID, "hash_a": "a" * 64, "hash_b": "b" * 64},
        )

    response = TestClient(_app(migrated_db, viewer)).get(
        "/api/v1/attempts/attempt-ambiguous/evidence"
    )

    assert response.status_code == 200
    assert response.json()["state"] == "unavailable"
    assert response.json()["reason_code"] == "attempt_evidence_identifier_ambiguous"


def test_authoritative_coverage_is_empty_without_verified_persisted_evidence(
    migrated_db: Engine,
) -> None:
    _clean(migrated_db)
    viewer = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:findings:read",
    )

    response = TestClient(_app(migrated_db, viewer)).get("/api/v1/coverage")

    assert response.status_code == 200
    assert response.json() == {"state": "empty", "data": []}


def test_coverage_and_resilience_project_one_authoritative_regression(
    migrated_db: Engine,
) -> None:
    """The merged console surface keeps distinct evidence and regression projections."""

    _clean(migrated_db)
    viewer = _principal(
        LAUNCHER_ID,
        "org:console:read",
        "org:findings:read",
        "org:campaign:launch",
        "org:targets:manage",
    )
    _seed_ready_target(migrated_db, viewer)
    run, _, scope = _seed_scheduled_tool_attempt(migrated_db, viewer)
    regression = ControlPlaneStore(
        migrated_db,
        environment="staging",
    ).ensure_campaign_attempt(
        run_id=run.run_id,
        ordinal=1,
        case_id="regression-prompt-injection-0001",
        case_content_hash="e" * 64,
        category="prompt_injection",
        severity="high",
        attack_class="regression",
        owasp_mappings=[
            {
                "framework": "OWASP LLM",
                "version": "2025",
                "id": "LLM01",
                "name": "Prompt Injection",
            }
        ],
        fixture_provenance={
            "classification": "synthetic",
            "fixture_id": "coverage-regression-api-fixture",
            "fixture_version": "1.0.0",
            "source": "hand_authored",
            "contains_real_phi": False,
        },
    )
    client = TestClient(_app(migrated_db, viewer))

    pending_coverage = client.get("/api/v1/coverage")
    pending_regressions = client.get("/api/v1/resilience")

    assert pending_coverage.status_code == 200
    assert pending_coverage.json() == {"state": "empty", "data": []}
    assert pending_regressions.status_code == 200
    pending_body = pending_regressions.json()
    assert pending_body["state"] == "ready"
    assert len(pending_body["data"]) == 1
    pending_row = pending_body["data"][0]
    assert set(pending_row) == {"regression_id", "version", "status", "recorded_at"}
    assert pending_row["regression_id"] == regression.attempt_id
    assert pending_row["version"] == "copilot-api@1.0.0"
    assert pending_row["status"] == "pending"
    assert pending_row["recorded_at"]

    executed_at = "2026-07-24T12:00:00+00:00"
    with migrated_db.begin() as connection:
        ExecutionRecorder().record(
            {
                "schema_version": "1",
                "campaign_run_id": run.run_id,
                "attempt_id": regression.attempt_id,
                "campaign_id": run.run_id,
                "target_id": scope.target_id,
                "target_version": scope.target_version,
                "attack_attempt": {
                    "schema_version": "1",
                    "case_ref": "regression-prompt-injection-0001",
                    "input_sequence": ["Replay the approved synthetic regression fixture."],
                    "category": "prompt_injection",
                },
                "request_transcript": {
                    "turns": ["Replay the approved synthetic regression fixture."]
                },
                "response_transcript": "Synthetic regression response.",
                "policy_decision_id": "regression-policy-decision-0001",
                "executed_at": executed_at,
                "trace_id": None,
                "correlation_id": run.run_id,
                "recorder_identity": "recorder@1",
                "recorder_version": "1",
                "organization_id": ORG_ID,
                "surface_id": scope.surface_id,
                "surface_version": scope.surface_version,
                "authorization_scope_hash": run.scope_hash,
                "execution_profile": "live",
                "evidence_provenance": "live_target",
            },
            connection,
        )
        connection.execute(
            text(
                "INSERT INTO verdict "
                "(state, confidence, campaign_run_id, attempt_id, organization_id, "
                "reason_codes) VALUES "
                "('NO_EXPLOIT_OBSERVED', 1.0, :run, :attempt, :org, "
                "'[\"regression_passed\"]'::jsonb)"
            ),
            {
                "org": ORG_ID,
                "run": run.run_id,
                "attempt": regression.attempt_id,
            },
        )

    coverage = client.get("/api/v1/coverage")
    regressions = client.get("/api/v1/resilience")

    assert coverage.status_code == 200
    coverage_body = coverage.json()
    assert coverage_body["state"] == "ready"
    assert coverage_body["data"] == [
        {
            "target_version": "copilot-api@1.0.0",
            "verified_attempt_count": 1,
            "total_case_count": 1,
            "category_count": 1,
            "execution_profile": "live",
            "evidence_provenance": "live_target",
            "classifications": ["regression"],
            "owasp_web": [],
            "owasp_llm": ["LLM01"],
            "verdict_counts": {"NO_EXPLOIT_OBSERVED": 1},
            "covered": False,
            "as_of": coverage_body["data"][0]["as_of"],
        }
    ]
    assert regressions.status_code == 200
    regression_body = regressions.json()
    assert regression_body["state"] == "ready"
    assert regression_body["data"][0]["regression_id"] == regression.attempt_id
    assert regression_body["data"][0]["status"] == "NO_EXPLOIT_OBSERVED"


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
                "payload": json.dumps(
                    {
                        "caps": {"budget_usd": 2},
                        "execution_profile": "synthetic",
                    }
                ),
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


def _seed_agent_observations(engine: Engine, org_id: str, run_id: str) -> None:
    roles = ("orchestrator", "red_team", "judge", "documentation")
    delivery = ("exported", "queued", "error", "disabled")
    parent: str | None = None
    trace_id = campaign_trace_id(run_id)
    with engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        for index, (role, langfuse_status) in enumerate(zip(roles, delivery, strict=True), start=1):
            execution_id = f"agent-observation-{role}"
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, attempt_id, "
                    "parent_execution_id, agent_role, status, provider, model, execution_mode, "
                    "configuration_version, input_sha256, output_sha256, input_tokens, "
                    "output_tokens, measured_cost, trace_id, langfuse_status, "
                    "langfuse_verified_at, detail, "
                    "started_at, finished_at, duration_ms) VALUES "
                    "(:execution, :org, :run, :attempt, :parent, :role, 'succeeded', "
                    "'headshot', :model, 'deterministic', 1, :input_hash, :output_hash, "
                    ":input_tokens, :output_tokens, :cost, :trace, :langfuse_status, "
                    "CASE WHEN :langfuse_verified "
                    "THEN TIMESTAMPTZ '2026-07-21 10:00:02+00' ELSE NULL END, "
                    "'{}'::jsonb, TIMESTAMPTZ '2026-07-21 10:00:00+00' + "
                    ":index * INTERVAL '1 second', "
                    "TIMESTAMPTZ '2026-07-21 10:00:01+00' + :index * INTERVAL '1 second', "
                    ":duration_ms)"
                ),
                {
                    "execution": execution_id,
                    "org": org_id,
                    "run": run_id,
                    "attempt": f"agent-attempt-{index}",
                    "parent": parent,
                    "role": role,
                    "model": f"{role}-engine-v1",
                    "input_hash": f"{index:x}" * 64,
                    "output_hash": f"{index + 4:x}" * 64,
                    "input_tokens": index * 100,
                    "output_tokens": index * 10,
                    "cost": index / 100,
                    "trace": trace_id,
                    "langfuse_status": langfuse_status,
                    "langfuse_verified": langfuse_status == "exported",
                    "index": index,
                    "duration_ms": index * 25,
                },
            )
            parent = execution_id


def test_agent_observability_reconciles_agents_costs_and_traces(
    migrated_db: Engine,
) -> None:
    org_id = "org_M1dAgentObservability"
    run_id = "run-agent-observability-0001"
    _seed_run_summary(migrated_db, org_id, run_id)
    _seed_agent_observations(migrated_db, org_id, run_id)
    client = TestClient(_app_for(migrated_db, _reader(org_id)))

    agents = client.get("/api/v1/agents").json()
    activity = client.get("/api/v1/agent-activity").json()
    costs = client.get("/api/v1/costs").json()
    traces = client.get("/api/v1/traces").json()

    assert agents["state"] == activity["state"] == costs["state"] == traces["state"] == "ready"
    agents_by_role = {row["role"]: row for row in agents["data"]}
    assert agents_by_role["orchestrator"]["p50_duration_ms"] == 25.0
    assert agents_by_role["documentation"]["p95_duration_ms"] == 100.0
    assert agents_by_role["orchestrator"]["langfuse_exported_count"] == 1
    assert agents_by_role["red_team"]["langfuse_queued_count"] == 1
    assert agents_by_role["judge"]["langfuse_error_count"] == 1
    assert agents_by_role["documentation"]["langfuse_disabled_count"] == 1
    assert agents_by_role["documentation"]["input_tokens"] == 400
    assert agents_by_role["documentation"]["measured_cost"] == 0.04
    assert agents_by_role["documentation"]["accounting_status"] == "measured"
    activity_by_role = {row["agent_role"]: row for row in activity["data"]}
    assert activity_by_role["red_team"]["accounting_status"] == "measured"
    assert activity_by_role["red_team"]["measured_cost"] == 0.02

    agent_costs = [row for row in costs["data"] if row["record_kind"] == "agent"]
    assert len(agent_costs) == 4
    documentation_cost = next(row for row in agent_costs if row["agent_role"] == "documentation")
    assert documentation_cost["measured_cost"] == 0.04
    assert documentation_cost["accounting_status"] == "measured"
    assert documentation_cost["input_tokens"] == 400
    assert documentation_cost["output_tokens"] == 40
    assert documentation_cost["p50_duration_ms"] == 100.0
    assert documentation_cost["p95_duration_ms"] == 100.0

    agent_traces = [row for row in traces["data"] if row["agent_role"] is not None]
    assert len(agent_traces) == 4
    red_team_trace = next(row for row in agent_traces if row["agent_role"] == "red_team")
    assert red_team_trace["parent_execution_id"] == "agent-observation-orchestrator"
    assert red_team_trace["duration_ms"] == 50.0
    assert red_team_trace["measured_cost"] == 0.02
    assert red_team_trace["input_tokens"] == 200
    assert red_team_trace["p50_duration_ms"] == 50.0
    assert red_team_trace["p95_duration_ms"] == 50.0
    assert red_team_trace["langfuse_status"] == "queued"


def test_agent_role_percentiles_use_full_tenant_campaign_ledger_before_trace_limit(
    migrated_db: Engine,
) -> None:
    org_id = "org_M1dAuthoritativeRoleLatency"
    run_id = "run-authoritative-role-latency-0001"
    _seed_run_summary(migrated_db, org_id, run_id)
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, agent_role, status, "
                "provider, model, execution_mode, configuration_version, input_sha256, "
                "output_sha256, measured_cost, trace_id, detail, started_at, finished_at, "
                "duration_ms) "
                "SELECT 'role-latency-' || series::text, :org, :run, 'red_team', "
                "'succeeded', 'headshot', 'full-scan-corpus-v1', 'deterministic', 1, "
                "repeat('a', 64), repeat('b', 64), 0, repeat('c', 32), '{}'::jsonb, "
                "TIMESTAMPTZ '2026-07-21 10:00:00+00' + series * INTERVAL '1 second', "
                "TIMESTAMPTZ '2026-07-21 10:00:01+00' + series * INTERVAL '1 second', "
                "CASE WHEN series <= 100 THEN 10000 ELSE 10 END "
                "FROM generate_series(1, 1100) AS series"
            ),
            {"org": org_id, "run": run_id},
        )

    client = TestClient(_app_for(migrated_db, _reader(org_id)))
    traces = client.get("/api/v1/traces").json()
    costs = client.get("/api/v1/costs").json()

    agent_traces = [row for row in traces["data"] if row["agent_role"] == "red_team"]
    assert len(agent_traces) == 1000
    assert {row["p50_duration_ms"] for row in agent_traces} == {10.0}
    assert {row["p95_duration_ms"] for row in agent_traces} == {10000.0}
    assert all(row["duration_ms"] == 10.0 for row in agent_traces)

    role_cost = next(
        row
        for row in costs["data"]
        if row["record_kind"] == "agent" and row["agent_role"] == "red_team"
    )
    assert role_cost["execution_count"] == 1100
    assert role_cost["p50_duration_ms"] == 10.0
    assert role_cost["p95_duration_ms"] == 10000.0


def test_agent_activity_exposes_row_level_hosted_accounting_status(
    migrated_db: Engine,
) -> None:
    org_id = "org_M1dHostedAgentActivity"
    run_id = "run-hosted-agent-activity-0001"
    _seed_run_summary(migrated_db, org_id, run_id)
    with migrated_db.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = replica"))
        for index, accounting in enumerate(
            (
                {
                    "execution": "hosted-agent-accounted",
                    "role": "red_team",
                    "status": "succeeded",
                    "input_tokens": 120,
                    "output_tokens": 30,
                    "physical_attempts": None,
                    "cost": 0.012,
                },
                {
                    "execution": "hosted-agent-unaccounted",
                    "role": "documentation",
                    "status": "succeeded",
                    "input_tokens": None,
                    "output_tokens": None,
                    "physical_attempts": None,
                    "cost": 0,
                },
                {
                    "execution": "hosted-agent-partial",
                    "role": "orchestrator",
                    "status": "failed",
                    "input_tokens": None,
                    "output_tokens": None,
                    "physical_attempts": 2,
                    "cost": 0,
                },
            ),
            start=1,
        ):
            connection.execute(
                text(
                    "INSERT INTO agent_executions "
                    "(execution_id, organization_id, campaign_run_id, agent_role, status, "
                    "provider, model, execution_mode, configuration_version, input_sha256, "
                    "output_sha256, input_tokens, output_tokens, physical_attempts, "
                    "measured_cost, trace_id, detail, "
                    "started_at, finished_at, duration_ms) VALUES "
                    "(:execution, :org, :run, :role, :status, 'openrouter', "
                    "'provider/model', 'hosted_advisory', 1, :input_hash, :output_hash, "
                    ":input_tokens, :output_tokens, :physical_attempts, :cost, :trace, "
                    "'{}'::jsonb, "
                    "TIMESTAMPTZ '2026-07-21 10:00:00+00' + :index * INTERVAL '1 second', "
                    "TIMESTAMPTZ '2026-07-21 10:00:01+00' + :index * INTERVAL '1 second', 25)"
                ),
                {
                    **accounting,
                    "org": org_id,
                    "run": run_id,
                    "input_hash": f"{index:x}" * 64,
                    "output_hash": f"{index + 2:x}" * 64,
                    "trace": f"{index:x}" * 32,
                    "index": index,
                },
            )

    client = TestClient(_app_for(migrated_db, _reader(org_id)))
    body = client.get("/api/v1/agent-activity").json()

    assert body["state"] == "ready"
    activity_by_id = {row["execution_id"]: row for row in body["data"]}
    assert activity_by_id["hosted-agent-accounted"]["accounting_status"] == "measured"
    assert activity_by_id["hosted-agent-accounted"]["measured_cost"] == 0.012
    assert activity_by_id["hosted-agent-unaccounted"]["accounting_status"] == "unavailable"
    assert activity_by_id["hosted-agent-unaccounted"]["measured_cost"] == 0
    assert activity_by_id["hosted-agent-partial"]["accounting_status"] == "partial"
    assert activity_by_id["hosted-agent-partial"]["physical_attempts"] == 2

    agents = {row["role"]: row for row in client.get("/api/v1/agents").json()["data"]}
    assert agents["orchestrator"]["accounting_status"] == "partial"
    assert agents["orchestrator"]["physical_call_count"] == 2
    agent_cost = next(
        row
        for row in client.get("/api/v1/costs").json()["data"]
        if row["record_kind"] == "agent" and row["agent_role"] == "orchestrator"
    )
    assert agent_cost["accounting_status"] == "partial"
    assert agent_cost["physical_call_count"] == 2
    agent_trace = next(
        row
        for row in client.get("/api/v1/traces").json()["data"]
        if row["execution_id"] == "hosted-agent-partial"
    )
    assert agent_trace["accounting_status"] == "partial"
    assert agent_trace["physical_attempts"] == 2


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
        "agent_role",
        "record_kind",
        "measured_cost",
        "accounting_status",
        "currency",
        "request_count",
        "execution_count",
        "attempt_count",
        "confirmed_finding_count",
        "average_cost_per_request",
        "input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "token_observation_count",
        "physical_call_count",
        "provider_budget",
        "p50_duration_ms",
        "p95_duration_ms",
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
    assert row["agent_role"] is None
    assert row["record_kind"] == "campaign"
    # Numeric(14,6) must be projected as a JSON number, never a stringified Decimal.
    assert isinstance(row["measured_cost"], (int, float))
    assert row["measured_cost"] == 1.234567
    assert row["accounting_status"] == "measured"
    assert row["p50_duration_ms"] is None
    assert row["p95_duration_ms"] is None
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
        "execution_id",
        "parent_execution_id",
        "trace_id",
        "campaign_id",
        "attempt_id",
        "operation",
        "provider",
        "agent_role",
        "execution_mode",
        "returned_model",
        "upstream_provider",
        "provider_request_id",
        "configuration_set_sha256",
        "role_configuration_sha256",
        "generation_policy_sha256",
        "physical_attempts",
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
        "accounting_status",
        "currency",
        "input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "judge_calibration_id",
        "judge_calibration_state",
        "oracle_agreement",
        "decision_authority",
        "p50_duration_ms",
        "p95_duration_ms",
        "langfuse_status",
        "langfuse_verified_at",
        "request_preview",
        "response_preview",
        "request_sha256",
        "response_sha256",
        "inspection_flags",
        "inspection_owasp_mappings",
    }
    assert row["trace_id"] == "trace-projection-0001"
    assert row["operation"] == "attempt:copilot-api@1.0.0"
    assert row["agent_role"] is None
    assert row["execution_mode"] is None
    assert row["status"] == "NO_EXPLOIT_OBSERVED"
    # verdict.created_at (10:00:02.500) - attempt_result.executed_at (10:00:00) == 2500 ms.
    assert row["duration_ms"] == 2500.0
    assert row["accounting_status"] == "unavailable"
    assert row["p50_duration_ms"] is None
    assert row["p95_duration_ms"] is None
    assert row["started_at"].startswith("2026-07-21T10:00:00")
    assert row["campaign_id"] == "run-trace-projection-0001"
    assert row["attempt_id"] == "attempt-trace-0001"
    assert row["langfuse_status"] == "historical_not_instrumented"
    assert row["langfuse_verified_at"] is None
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
                "currency, langfuse_status, langfuse_verified_at, started_at, finished_at) VALUES "
                "('request-physical-0001', :org, :run, 'attempt-physical-0001', :trace, "
                "'target.http', 'openemr', 'POST', 'target.example.test', 'chat', "
                'CAST(\'{"turns":["synthetic"]}\' AS JSONB), \'{"answer":"safe"}\', '
                "'succeeded', 200, 24, 17, 125.5, 0.01, 'USD', 'exported', "
                "TIMESTAMPTZ '2026-07-21 10:00:01+00', "
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
