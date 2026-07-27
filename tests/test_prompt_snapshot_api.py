"""Protected prompt evidence and authoritative campaign-scoped observability contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, text

from agentforge.agents.prompts import load_prompt_registry
from agentforge.api.postgres import PostgresApiBackend
from agentforge.api.read_models import validate_ready_data
from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.dependencies import get_clerk_auth_config, require_authenticated
from agentforge.auth.permissions import CONSOLE_READ, EVIDENCE_READ
from agentforge.auth.principal import Principal
from agentforge.control_plane.serialization import canonical_json
from agentforge.web import WebSecurityConfig, create_web_app

_ORGANIZATION_ID = "org_PromptSnapshotApi"
_OTHER_ORGANIZATION_ID = "org_PromptSnapshotApiOther"
_REQUEST_ID = "request-prompt-snapshot-api"
_RUN_ID = "run-prompt-snapshot-api"
_EXECUTION_ID = "execution-prompt-snapshot-api"
_ORIGIN = "https://prompt-snapshot.example.test"
_PRIVATE_SENTINEL = "prompt-snapshot-private-sentinel"
_REDACTION_MARKER = "[REDACTED:SYNTHETIC_FIXTURE]"


def _principal(
    organization_id: str = _ORGANIZATION_ID,
    *,
    evidence: bool = True,
) -> Principal:
    permissions = {CONSOLE_READ}
    if evidence:
        permissions.add(EVIDENCE_READ)
    return Principal(
        user_id="user_PromptSnapshotApiReader",
        session_id="sess_PromptSnapshotApiReader",
        organization_id=organization_id,
        organization_role="org:operator",
        organization_permissions=frozenset(permissions),
    )


def _seed_prompt_snapshot_and_bounded_projection_history(engine: Engine) -> None:
    scope_payload = {
        "execution_profile": "live",
        "caps": {"budget_usd": 5.0},
    }
    prompt = next(record for record in load_prompt_registry() if record.role == "orchestrator")
    system_prompt = prompt.content
    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": canonical_json(
                {
                    "fixture": _REDACTION_MARKER,
                    "private_fixture": _PRIVATE_SENTINEL,
                }
            ),
        },
    ]
    transcript = canonical_json({"messages": messages})
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:request_id, :org, :scope_hash, CAST(:scope_payload AS jsonb), "
                "'user_PromptSnapshotApiLauncher', 'sess_PromptSnapshotApiLauncher', "
                "clock_timestamp() + interval '1 hour')"
            ),
            {
                "request_id": _REQUEST_ID,
                "org": _ORGANIZATION_ID,
                "scope_hash": "a" * 64,
                "scope_payload": json.dumps(scope_payload),
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) VALUES "
                "('decision-prompt-snapshot-api', :org, :request_id, :scope_hash, "
                "'approved', 'user_PromptSnapshotApiApprover', "
                "'sess_PromptSnapshotApiApprover')"
            ),
            {
                "org": _ORGANIZATION_ID,
                "request_id": _REQUEST_ID,
                "scope_hash": "a" * 64,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run_id, :org, :request_id, :scope_hash, "
                "'user_PromptSnapshotApiLauncher', 'sess_PromptSnapshotApiLauncher')"
            ),
            {
                "run_id": _RUN_ID,
                "org": _ORGANIZATION_ID,
                "request_id": _REQUEST_ID,
                "scope_hash": "a" * 64,
            },
        )
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, agent_role, status, "
                "provider, model, execution_mode, configuration_version, input_sha256, "
                "output_sha256, trace_id, detail, error_code, started_at, finished_at, "
                "duration_ms) VALUES "
                "(:execution_id, :org, :run_id, 'orchestrator', 'failed', 'openrouter', "
                "'openai/test-model', 'hosted_advisory', 1, :input_sha, :output_sha, "
                ":trace_id, CAST(:detail AS jsonb), 'fixture_terminal_failure', "
                "'2020-01-01T00:00:00Z'::timestamptz, "
                "'2020-01-01T00:00:01Z'::timestamptz, 1000)"
            ),
            {
                "execution_id": _EXECUTION_ID,
                "org": _ORGANIZATION_ID,
                "run_id": _RUN_ID,
                "input_sha": "b" * 64,
                "output_sha": "c" * 64,
                "trace_id": "d" * 32,
                "detail": json.dumps({"provider_lineage_state": "canonical_physical"}),
            },
        )
        connection.execute(
            text(
                "INSERT INTO agent_prompt_snapshots "
                "(organization_id, execution_id, campaign_run_id, attempt_id, agent_role, "
                "system_prompt_version, system_prompt_sha256, system_prompt_content, "
                "provider_messages, transcript_sha256, redactions) VALUES "
                "(:org, :execution_id, :run_id, NULL, 'orchestrator', :prompt_version, "
                ":system_sha, :system_prompt, CAST(:messages AS jsonb), :transcript_sha, "
                "CAST(:redactions AS jsonb))"
            ),
            {
                "org": _ORGANIZATION_ID,
                "execution_id": _EXECUTION_ID,
                "run_id": _RUN_ID,
                "prompt_version": prompt.version,
                "system_sha": prompt.sha256,
                "system_prompt": system_prompt,
                "messages": json.dumps(messages),
                "transcript_sha": hashlib.sha256(transcript.encode()).hexdigest(),
                "redactions": json.dumps(
                    [
                        {
                            "path": "$.messages[1].content.fixture",
                            "reason": "synthetic_fixture",
                            "replacement": _REDACTION_MARKER,
                        }
                    ]
                ),
            },
        )

        # 400 newer campaigns and 1,000 newer executions put the selected campaign outside all
        # bounded global projections (200 campaign rows, 400 cost groups, 1,000 activity rows).
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) "
                "SELECT 'request-prompt-scope-' || lpad(series::text, 4, '0'), :org, "
                "repeat('e', 64), "
                "jsonb_build_object('execution_profile', 'live', 'caps', "
                "jsonb_build_object('budget_usd', 5.0)), "
                "'user_PromptSnapshotApiLauncher', 'sess_PromptSnapshotApiLauncher', "
                "clock_timestamp() + interval '1 hour' FROM generate_series(1, 400) series"
            ),
            {"org": _ORGANIZATION_ID},
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) "
                "SELECT 'decision-prompt-scope-' || lpad(series::text, 4, '0'), :org, "
                "'request-prompt-scope-' || lpad(series::text, 4, '0'), repeat('e', 64), "
                "'approved', 'user_PromptSnapshotApiApprover', "
                "'sess_PromptSnapshotApiApprover' FROM generate_series(1, 400) series"
            ),
            {"org": _ORGANIZATION_ID},
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) "
                "SELECT 'run-prompt-scope-' || lpad(series::text, 4, '0'), :org, "
                "'request-prompt-scope-' || lpad(series::text, 4, '0'), repeat('e', 64), "
                "'user_PromptSnapshotApiLauncher', 'sess_PromptSnapshotApiLauncher' "
                "FROM generate_series(1, 400) series"
            ),
            {"org": _ORGANIZATION_ID},
        )
        connection.execute(
            text(
                "INSERT INTO agent_executions "
                "(execution_id, organization_id, campaign_run_id, agent_role, status, "
                "provider, model, execution_mode, configuration_version, input_sha256, "
                "output_sha256, trace_id, detail, error_code, started_at, finished_at, "
                "duration_ms) "
                "SELECT 'execution-prompt-scope-' || lpad(series::text, 4, '0'), :org, "
                "'run-prompt-scope-' || lpad((((series - 1) % 400) + 1)::text, 4, '0'), "
                "'orchestrator', 'failed', 'openrouter', 'openai/test-model', "
                "'hosted_advisory', 1, repeat('f', 64), repeat('1', 64), "
                "md5('prompt-scope-trace-' || series::text), "
                "jsonb_build_object('provider_lineage_state', 'canonical_physical'), "
                "'fixture_terminal_failure', "
                "clock_timestamp() + make_interval(secs => series), "
                "clock_timestamp() + make_interval(secs => series + 1), 1000 "
                "FROM generate_series(1, 1000) series"
            ),
            {"org": _ORGANIZATION_ID},
        )


@pytest.fixture(scope="module")
def prompt_api_db(migrated_db: Engine) -> Engine:
    _seed_prompt_snapshot_and_bounded_projection_history(migrated_db)
    return migrated_db


def _app(engine: Engine) -> Any:
    app = create_web_app(
        backend=PostgresApiBackend(engine, environment="staging"),
        readiness_check=lambda: True,
        security_config=WebSecurityConfig(
            environment="staging",
            allowed_origins=(_ORIGIN,),
            clerk_frontend_api_origin="https://prompt-snapshot.clerk.accounts.dev",
        ),
    )
    app.dependency_overrides[get_clerk_auth_config] = lambda: ClerkAuthConfig(
        environment="staging",
        publishable_key="public-test-identifier-not-used",
        jwt_key="public-test-verification-key-not-used",
        authorized_parties=(_ORIGIN,),
        required_organization_id=_ORGANIZATION_ID,
    )
    return app


def test_prompt_snapshot_route_requires_evidence_permission_and_organization_scope(
    prompt_api_db: Engine,
) -> None:
    app = _app(prompt_api_db)
    path = f"/api/v1/agent-executions/{_EXECUTION_ID}/prompt-snapshot"
    assert TestClient(app).get(path).status_code == 401

    app.dependency_overrides[require_authenticated] = lambda: _principal(evidence=False)
    assert TestClient(app).get(path).status_code == 403

    app.dependency_overrides[require_authenticated] = _principal
    response = TestClient(app).get(path)
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "ready", payload
    snapshot = payload["data"]
    assert snapshot["execution_id"] == _EXECUTION_ID
    assert snapshot["campaign_run_id"] == _RUN_ID
    expected_prompt = next(
        record for record in load_prompt_registry() if record.role == "orchestrator"
    )
    assert snapshot["system_prompt_content"] == expected_prompt.content
    assert [message["role"] for message in snapshot["provider_messages"]] == [
        "system",
        "user",
    ]
    assert snapshot["redactions"] == [
        {
            "path": "$.messages[1].content.fixture",
            "reason": "synthetic_fixture",
            "replacement": _REDACTION_MARKER,
        }
    ]

    cross_organization = PostgresApiBackend(
        prompt_api_db,
        environment="staging",
    ).read(
        "agent_prompt_snapshot",
        _principal(_OTHER_ORGANIZATION_ID),
        identifiers={"execution_id": _EXECUTION_ID},
    )
    assert cross_organization.state == "empty"


def test_prompt_snapshot_strict_decoder_recomputes_both_hashes(
    prompt_api_db: Engine,
) -> None:
    result = PostgresApiBackend(prompt_api_db, environment="staging").read(
        "agent_prompt_snapshot",
        _principal(),
        identifiers={"execution_id": _EXECUTION_ID},
    )
    assert result.state == "ready", result

    bad_system_hash = {**result.data, "system_prompt_sha256": "0" * 64}
    with pytest.raises(ValidationError, match="system prompt hash"):
        validate_ready_data("agent_prompt_snapshot", bad_system_hash)

    bad_transcript_hash = {**result.data, "transcript_sha256": "0" * 64}
    with pytest.raises(ValidationError, match="provider transcript hash"):
        validate_ready_data("agent_prompt_snapshot", bad_transcript_hash)


def test_prompt_content_never_leaks_into_aggregate_or_trace_resources(
    prompt_api_db: Engine,
) -> None:
    app = _app(prompt_api_db)
    app.dependency_overrides[require_authenticated] = _principal
    client = TestClient(app)
    for resource in ("agent-activity", "traces", "costs"):
        response = client.get(f"/api/v1/{resource}?campaign_id={_RUN_ID}")
        assert response.status_code == 200
        payload = response.json()
        assert payload["state"] == "ready", payload
        serialized = json.dumps(payload, sort_keys=True)
        assert _PRIVATE_SENTINEL not in serialized
        assert "system_prompt_content" not in serialized
        assert "provider_messages" not in serialized
        assert "transcript_sha256" not in serialized


def test_campaign_scoped_observability_bypasses_global_limits_and_is_org_isolated(
    prompt_api_db: Engine,
) -> None:
    backend = PostgresApiBackend(prompt_api_db, environment="staging")
    principal = _principal()
    identity_fields = {
        "agent_activity": "campaign_run_id",
        "traces": "campaign_id",
        "costs": "campaign_id",
    }
    for resource, campaign_field in identity_fields.items():
        global_result = backend.read(resource, principal)
        assert global_result.state == "ready", global_result
        assert all(row[campaign_field] != _RUN_ID for row in global_result.data), resource

        scoped_result = backend.read(
            resource,
            principal,
            identifiers={"campaign_id": _RUN_ID},
        )
        assert scoped_result.state == "ready", scoped_result
        assert scoped_result.data
        assert {row[campaign_field] for row in scoped_result.data} == {_RUN_ID}

        cross_organization = backend.read(
            resource,
            _principal(_OTHER_ORGANIZATION_ID),
            identifiers={"campaign_id": _RUN_ID},
        )
        assert cross_organization.state == "empty", resource
