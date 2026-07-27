"""Per-physical-call prompt and recorded-response evidence, and its aggregate-leak boundary."""

from __future__ import annotations

import datetime
import hashlib
import json
from decimal import Decimal
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, text

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.prompts import load_prompt_registry
from agentforge.api.postgres import PostgresApiBackend
from agentforge.api.read_models import validate_ready_data
from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.dependencies import get_clerk_auth_config, require_authenticated
from agentforge.auth.permissions import CONSOLE_READ, EVIDENCE_READ
from agentforge.auth.principal import Principal
from agentforge.control_plane.serialization import canonical_json
from agentforge.web import WebSecurityConfig, create_web_app

_ORGANIZATION_ID = "org_ProviderCallEvidenceApi"
_OTHER_ORGANIZATION_ID = "org_ProviderCallEvidenceApiOther"
_ORIGIN = "https://provider-call-evidence.example.test"
_REQUEST_ID = "request-provider-call-evidence"
_RUN_ID = "run-provider-call-evidence"
_LAUNCHER_USER_ID = "user_ProviderCallEvidenceLauncher"
_SCOPE_HASH = "a" * 64

_PROMPT_SENTINEL = "provider-call-evidence-prompt-sentinel"
_RESPONSE_SENTINEL = "provider-call-evidence-response-sentinel"
_REDACTION_MARKER = "[REDACTED:SYNTHETIC_FIXTURE]"

# Synthetic credentials, never real. A recorded response is provider-controlled text captured
# before any status check, so both of these shapes reach the column verbatim: a DSN out of an
# upstream 5xx connection error, and a secret reference echoed back in a model's own rationale.
_LEAKED_DSN = "postgres://user:hunter2@db.internal:5432/agentforge"
_LEAKED_DSN_PASSWORD = "hunter2"
_LEAKED_SECRET_REFERENCE = "secretref://staging/openrouter/judge/generation-1"
_CREDENTIAL_URL_MARKER = "***REDACTED_CREDENTIAL_URL***"
_CREDENTIAL_REFERENCE_MARKER = "***REDACTED_CREDENTIAL_REFERENCE***"

# Five physical calls, each on its own logical execution so every invocation is sequence 1.
_CASE_FULL = "full"  # snapshot + recorded response
_CASE_NO_SNAPSHOT = "no-snapshot"  # recorded response, no protected snapshot row
_CASE_NO_RESPONSE = "no-response"  # snapshot, no recorded response
_CASE_CREDENTIAL_DSN = "credential-dsn"  # response embeds a DSN; no snapshot to screen it
_CASE_CREDENTIAL_REFERENCE = "credential-reference"  # response embeds a secretref://

_CASE_ROLES = {
    _CASE_FULL: "orchestrator",
    _CASE_NO_SNAPSHOT: "red_team",
    # Deliberately not the Judge: a succeeded judge execution carries extra decision-authority
    # constraints that are irrelevant to this evidence contract.
    _CASE_NO_RESPONSE: "documentation",
    _CASE_CREDENTIAL_DSN: "red_team",
    _CASE_CREDENTIAL_REFERENCE: "documentation",
}

_RETURNED_UPSTREAM = {
    "anthropic": "Anthropic",
    "together": "Together",
    "google-vertex": "Google Vertex",
    "openai": "OpenAI",
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _execution_id(case: str) -> str:
    return _digest(f"execution:{_RUN_ID}:{case}")


def _invocation_id(case: str) -> str:
    return _digest(f"invocation:{_RUN_ID}:{case}")


def _event_id(case: str) -> str:
    return _digest(f"event:{_RUN_ID}:{case}")


def _response_text(case: str) -> str:
    """The bytes as STORED on the row -- what the provider actually said, unscreened."""

    if case == _CASE_CREDENTIAL_DSN:
        # An upstream error body, not JSON. The DSN sits mid-sentence with text on both sides
        # so the assertions can show the screen removes the credential and nothing else.
        return (
            f"upstream error {_RESPONSE_SENTINEL}:{case} - "
            f"could not reach {_LEAKED_DSN} after 3 attempts"
        )
    rationale = f"{_RESPONSE_SENTINEL}:{case}"
    if case == _CASE_CREDENTIAL_REFERENCE:
        rationale = f"{rationale} resolved via {_LEAKED_SECRET_REFERENCE} ok"
    return canonical_json(
        {
            "verdict": "fail",
            "rationale": rationale,
        }
    )


def _served_response_text(case: str) -> str:
    """The bytes the endpoint is allowed to serve: the stored text minus any credential."""

    return (
        _response_text(case)
        .replace(_LEAKED_DSN, _CREDENTIAL_URL_MARKER)
        .replace(_LEAKED_SECRET_REFERENCE, _CREDENTIAL_REFERENCE_MARKER)
    )


def _evidence_hosted_configuration() -> HostedConfigurationSet:
    prompts = {record.role: record for record in load_prompt_registry()}
    identities = {
        "orchestrator": ("anthropic/claude-opus-4.8", "anthropic"),
        "red_team": ("qwen/qwen3.5-397b-a17b", "together"),
        "judge": ("google/gemini-2.5-pro", "google-vertex"),
        "documentation": ("openai/gpt-5.4", "openai"),
    }
    return HostedConfigurationSet(
        roles=tuple(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=model,
                upstream_provider=upstream,
                credential_reference=f"secretref://staging/openrouter/{role}/generation-1",
                prompt_sha256=prompts[role].sha256,
                policy_sha256=_digest(f"{role}:provider-call-evidence-policy"),
                prices=TokenPrices(
                    input_usd_per_million_tokens=Decimal("1"),
                    output_usd_per_million_tokens=Decimal("2"),
                    reasoning_usd_per_million_tokens=Decimal("3"),
                ),
                limits=HostedLimits(
                    max_calls=3,
                    max_input_tokens=100_000,
                    max_output_tokens=20_000,
                    max_reasoning_tokens=20_000,
                    max_usd=Decimal("1"),
                    max_retries=1,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
            for role, (model, upstream) in identities.items()
        ),
        global_limits=HostedLimits(
            max_calls=12,
            max_input_tokens=400_000,
            max_output_tokens=80_000,
            max_reasoning_tokens=80_000,
            max_usd=Decimal("4"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _prompt_messages(agent_role: str) -> tuple[str, list[dict[str, str]]]:
    prompt = next(record for record in load_prompt_registry() if record.role == agent_role)
    messages = [
        {"role": "system", "content": prompt.content},
        {
            "role": "user",
            "content": canonical_json(
                {
                    "fixture": _REDACTION_MARKER,
                    "private_fixture": f"{_PROMPT_SENTINEL}:{agent_role}",
                }
            ),
        },
    ]
    return prompt.content, messages


def _seed_physical_call(
    connection: Any,
    *,
    case: str,
    configuration: HostedConfigurationSet,
    with_snapshot: bool,
    with_response: bool,
) -> None:
    agent_role = _CASE_ROLES[case]
    role = next(item for item in configuration.roles if item.role == agent_role)
    prompt = next(record for record in load_prompt_registry() if record.role == agent_role)
    execution_id = _execution_id(case)
    invocation_id = _invocation_id(case)
    event_id = _event_id(case)
    started_at = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=30)
    finished_at = started_at + datetime.timedelta(seconds=1)
    provider_request_id = f"provider-call-evidence-{case}"
    returned_upstream = _RETURNED_UPSTREAM[role.upstream_provider]

    connection.execute(
        text(
            "INSERT INTO agent_executions "
            "(execution_id, organization_id, campaign_run_id, agent_role, provider, model, "
            "execution_mode, configuration_version, input_sha256, trace_id, "
            "configuration_set_sha256, role_configuration_sha256, generation_policy_sha256, "
            "detail, started_at) VALUES "
            "(:execution, :org, :run, :role, 'openrouter', :model, 'hosted_advisory', 1, "
            ":input_sha, :trace, :configuration, :role_configuration, :generation_policy, "
            '\'{"provider_lineage_state":"canonical_physical"}\'::jsonb, :started_at)'
        ),
        {
            "execution": execution_id,
            "org": _ORGANIZATION_ID,
            "run": _RUN_ID,
            "role": agent_role,
            "model": role.model_id,
            "input_sha": _digest(f"input:{case}"),
            "trace": _digest(f"trace:{case}")[:32],
            "configuration": configuration.configuration_sha256,
            "role_configuration": role.configuration_sha256,
            "generation_policy": DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256,
            "started_at": started_at - datetime.timedelta(seconds=1),
        },
    )

    if with_snapshot:
        system_prompt, messages = _prompt_messages(agent_role)
        transcript = canonical_json({"messages": messages})
        connection.execute(
            text(
                "INSERT INTO agent_prompt_snapshots "
                "(organization_id, execution_id, campaign_run_id, attempt_id, agent_role, "
                "system_prompt_version, system_prompt_sha256, system_prompt_content, "
                "provider_messages, transcript_sha256, redactions) VALUES "
                "(:org, :execution, :run, NULL, :role, :prompt_version, :system_sha, "
                ":system_prompt, CAST(:messages AS jsonb), :transcript_sha, "
                "CAST(:redactions AS jsonb))"
            ),
            {
                "org": _ORGANIZATION_ID,
                "execution": execution_id,
                "run": _RUN_ID,
                "role": agent_role,
                "prompt_version": prompt.version,
                "system_sha": prompt.sha256,
                "system_prompt": system_prompt,
                "messages": json.dumps(messages),
                "transcript_sha": _digest(transcript),
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

    connection.execute(
        text(
            "INSERT INTO provider_call_invocations "
            "(invocation_id, organization_id, campaign_run_id, campaign_attempt_id, "
            "logical_execution_id, parent_execution_id, agent_role, physical_sequence, "
            "idempotency_key, requested_model, configured_upstream, prompt_version, "
            "prompt_sha256, configuration_set_sha256, role_configuration_sha256, "
            "generation_policy_sha256, started_at) VALUES "
            "(:invocation, :org, :run, NULL, :execution, NULL, :role, 1, :idempotency, "
            ":model, :upstream, :prompt_version, :prompt_sha, :configuration, "
            ":role_configuration, :generation_policy, :started_at)"
        ),
        {
            "invocation": invocation_id,
            "org": _ORGANIZATION_ID,
            "run": _RUN_ID,
            "execution": execution_id,
            "role": agent_role,
            "idempotency": f"provider-call:{invocation_id}",
            "model": role.model_id,
            "upstream": role.upstream_provider,
            "prompt_version": prompt.version,
            "prompt_sha": prompt.sha256,
            "configuration": configuration.configuration_sha256,
            "role_configuration": role.configuration_sha256,
            "generation_policy": DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256,
            "started_at": started_at,
        },
    )

    response_text = _response_text(case) if with_response else None
    connection.execute(
        text(
            "INSERT INTO provider_call_events "
            "(event_id, invocation_id, organization_id, campaign_run_id, campaign_attempt_id, "
            "logical_execution_id, agent_role, physical_sequence, status, returned_model, "
            "upstream_provider, provider_request_id, input_tokens, output_tokens, "
            "reasoning_tokens, cost_measurement_state, measured_cost_usd, finished_at, "
            "duration_ms, response_text, response_truncated, response_sha256) VALUES "
            "(:event, :invocation, :org, :run, NULL, :execution, :role, 1, 'succeeded', "
            ":model, :returned_upstream, :provider_request_id, 100, 40, 10, 'measured', "
            "0.001, :finished_at, 1000, :response_text, false, :response_sha)"
        ),
        {
            "event": event_id,
            "invocation": invocation_id,
            "org": _ORGANIZATION_ID,
            "run": _RUN_ID,
            "execution": execution_id,
            "role": agent_role,
            "model": role.model_id,
            "returned_upstream": returned_upstream,
            "provider_request_id": provider_request_id,
            "finished_at": finished_at,
            "response_text": response_text,
            "response_sha": None if response_text is None else _digest(response_text),
        },
    )

    connection.execute(
        text(
            "UPDATE agent_executions SET status = 'succeeded', output_sha256 = :output_sha, "
            "returned_model = :model, upstream_provider = :upstream, "
            "provider_request_id = :provider_request_id, input_tokens = 100, "
            "output_tokens = 40, reasoning_tokens = 10, measured_cost = 0.001, "
            "cost_measurement_state = 'measured', finished_at = :finished_at, "
            "duration_ms = 2000 WHERE organization_id = :org AND execution_id = :execution"
        ),
        {
            "output_sha": _digest(f"output:{case}"),
            "model": role.model_id,
            "upstream": returned_upstream,
            "provider_request_id": provider_request_id,
            "finished_at": finished_at,
            "org": _ORGANIZATION_ID,
            "execution": execution_id,
        },
    )


def _seed_provider_call_evidence(engine: Engine) -> None:
    configuration = _evidence_hosted_configuration()
    scope = {
        "target_id": "copilot-api",
        "target_version": "1.0.0",
        "surface_id": "chat-api",
        "surface_version": "1.0.0",
        "execution_profile": "live",
        "caps": {"budget_usd": 5.0},
    }
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO hosted_configuration_sets "
                "(organization_id, configuration_sha256, schema_version, release_sha256, "
                "payload, rationale, actor_user_id, actor_session_id) VALUES "
                "(:org, :configuration, :schema_version, :release, CAST(:payload AS jsonb), "
                "'Provider call evidence fixture.', :launcher, "
                "'sess_ProviderCallEvidenceFixture')"
            ),
            {
                "org": _ORGANIZATION_ID,
                "configuration": configuration.configuration_sha256,
                "schema_version": configuration.schema_version,
                "release": _digest(f"release:{_ORGANIZATION_ID}:{_RUN_ID}"),
                "payload": json.dumps(configuration.canonical_payload()),
                "launcher": _LAUNCHER_USER_ID,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:request_id, :org, :scope_hash, CAST(:scope AS jsonb), :launcher, "
                "'sess_ProviderCallEvidenceFixture', clock_timestamp() + interval '1 hour')"
            ),
            {
                "request_id": _REQUEST_ID,
                "org": _ORGANIZATION_ID,
                "scope_hash": _SCOPE_HASH,
                "scope": json.dumps(scope),
                "launcher": _LAUNCHER_USER_ID,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_decisions "
                "(decision_id, organization_id, request_id, scope_hash, decision, "
                "approver_user_id, approver_session_id) VALUES "
                "('decision-provider-call-evidence', :org, :request_id, :scope_hash, "
                "'approved', 'user_ProviderCallEvidenceApprover', "
                "'sess_ProviderCallEvidenceApprover')"
            ),
            {
                "org": _ORGANIZATION_ID,
                "request_id": _REQUEST_ID,
                "scope_hash": _SCOPE_HASH,
            },
        )
        connection.execute(
            text(
                "INSERT INTO campaign_runs "
                "(run_id, organization_id, authorization_request_id, scope_hash, "
                "launcher_user_id, launcher_session_id) VALUES "
                "(:run_id, :org, :request_id, :scope_hash, :launcher, "
                "'sess_ProviderCallEvidenceFixture')"
            ),
            {
                "run_id": _RUN_ID,
                "org": _ORGANIZATION_ID,
                "request_id": _REQUEST_ID,
                "scope_hash": _SCOPE_HASH,
                "launcher": _LAUNCHER_USER_ID,
            },
        )
        _seed_physical_call(
            connection,
            case=_CASE_FULL,
            configuration=configuration,
            with_snapshot=True,
            with_response=True,
        )
        _seed_physical_call(
            connection,
            case=_CASE_NO_SNAPSHOT,
            configuration=configuration,
            with_snapshot=False,
            with_response=True,
        )
        _seed_physical_call(
            connection,
            case=_CASE_NO_RESPONSE,
            configuration=configuration,
            with_snapshot=True,
            with_response=False,
        )
        _seed_physical_call(
            connection,
            case=_CASE_CREDENTIAL_DSN,
            configuration=configuration,
            with_snapshot=False,
            with_response=True,
        )
        _seed_physical_call(
            connection,
            case=_CASE_CREDENTIAL_REFERENCE,
            configuration=configuration,
            with_snapshot=True,
            with_response=True,
        )


def _principal(
    organization_id: str = _ORGANIZATION_ID,
    *,
    evidence: bool = True,
) -> Principal:
    permissions = {CONSOLE_READ}
    if evidence:
        permissions.add(EVIDENCE_READ)
    return Principal(
        user_id="user_ProviderCallEvidenceReader",
        session_id="sess_ProviderCallEvidenceReader",
        organization_id=organization_id,
        organization_role="org:operator",
        organization_permissions=frozenset(permissions),
    )


@pytest.fixture(scope="module")
def evidence_db(migrated_db: Engine) -> Engine:
    _seed_provider_call_evidence(migrated_db)
    return migrated_db


def _app(engine: Engine) -> Any:
    app = create_web_app(
        backend=PostgresApiBackend(engine, environment="staging"),
        readiness_check=lambda: True,
        security_config=WebSecurityConfig(
            environment="staging",
            allowed_origins=(_ORIGIN,),
            clerk_frontend_api_origin="https://provider-call-evidence.clerk.accounts.dev",
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


def _evidence_path(case: str) -> str:
    return f"/api/v1/provider-calls/{_invocation_id(case)}/evidence"


def test_provider_call_evidence_requires_evidence_permission_and_organization_scope(
    evidence_db: Engine,
) -> None:
    app = _app(evidence_db)
    path = _evidence_path(_CASE_FULL)
    assert TestClient(app).get(path).status_code == 401

    app.dependency_overrides[require_authenticated] = lambda: _principal(evidence=False)
    denied = TestClient(app)
    # Every member, not just the one that happens to have a protected prompt snapshot.
    for case in _CASE_ROLES:
        assert denied.get(_evidence_path(case)).status_code == 403, case

    app.dependency_overrides[require_authenticated] = _principal
    assert TestClient(app).get(path).status_code == 200

    cross_organization = PostgresApiBackend(evidence_db, environment="staging").read(
        "provider_call_evidence",
        _principal(_OTHER_ORGANIZATION_ID),
        identifiers={"invocation_id": _invocation_id(_CASE_FULL)},
    )
    assert cross_organization.state == "empty"


def test_provider_call_evidence_serves_the_exact_prompt_and_recorded_response(
    evidence_db: Engine,
) -> None:
    app = _app(evidence_db)
    app.dependency_overrides[require_authenticated] = _principal
    response = TestClient(app).get(_evidence_path(_CASE_FULL))
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "ready", payload
    data = payload["data"]

    assert data["invocation_id"] == _invocation_id(_CASE_FULL)
    assert data["campaign_run_id"] == _RUN_ID
    assert data["attempt_id"] is None
    assert data["agent_role"] == "orchestrator"
    assert data["physical_sequence"] == 1
    assert data["status"] == "succeeded"
    assert data["error_code"] is None

    expected_prompt, expected_messages = _prompt_messages("orchestrator")
    prompt = data["prompt"]
    assert prompt is not None
    assert prompt["system_prompt_content"] == expected_prompt
    assert prompt["provider_messages"] == expected_messages
    assert prompt["transcript_sha256"] == _digest(canonical_json({"messages": expected_messages}))
    assert prompt["redactions"] == [
        {
            "path": "$.messages[1].content.fixture",
            "reason": "synthetic_fixture",
            "replacement": _REDACTION_MARKER,
        }
    ]

    expected_response = _response_text(_CASE_FULL)
    assert data["response"] == {
        "text": expected_response,
        "truncated": False,
        "sha256": _digest(expected_response),
    }


def test_provider_call_evidence_prompt_is_null_when_no_snapshot_exists(
    evidence_db: Engine,
) -> None:
    app = _app(evidence_db)
    app.dependency_overrides[require_authenticated] = _principal
    response = TestClient(app).get(_evidence_path(_CASE_NO_SNAPSHOT))
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "ready", payload
    data = payload["data"]
    assert data["agent_role"] == "red_team"
    assert data["prompt"] is None
    assert data["response"] is not None
    assert data["response"]["text"] == _response_text(_CASE_NO_SNAPSHOT)


def test_provider_call_evidence_response_is_null_when_none_was_recorded(
    evidence_db: Engine,
) -> None:
    app = _app(evidence_db)
    app.dependency_overrides[require_authenticated] = _principal
    response = TestClient(app).get(_evidence_path(_CASE_NO_RESPONSE))
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "ready", payload
    data = payload["data"]
    assert data["agent_role"] == "documentation"
    assert data["response"] is None
    assert data["prompt"] is not None
    assert data["prompt"]["system_prompt_content"] == _prompt_messages("documentation")[0]


def test_provider_call_evidence_is_empty_for_an_unknown_invocation(
    evidence_db: Engine,
) -> None:
    backend = PostgresApiBackend(evidence_db, environment="staging")
    for invocation_id in ("0" * 64, "", "x" * 128):
        result = backend.read(
            "provider_call_evidence",
            _principal(),
            identifiers={"invocation_id": invocation_id},
        )
        assert result.state == "empty", invocation_id


def test_provider_call_evidence_decoder_recomputes_prompt_and_response_digests(
    evidence_db: Engine,
) -> None:
    result = PostgresApiBackend(evidence_db, environment="staging").read(
        "provider_call_evidence",
        _principal(),
        identifiers={"invocation_id": _invocation_id(_CASE_FULL)},
    )
    assert result.state == "ready", result

    tampered_response = {
        **result.data,
        "response": {**result.data["response"], "text": "tampered evidence"},
    }
    with pytest.raises(ValidationError, match="provider response hash"):
        validate_ready_data("provider_call_evidence", tampered_response)

    tampered_prompt = {
        **result.data,
        "prompt": {**result.data["prompt"], "transcript_sha256": "0" * 64},
    }
    with pytest.raises(ValidationError, match="provider transcript hash"):
        validate_ready_data("provider_call_evidence", tampered_prompt)


def test_provider_call_evidence_backend_refuses_without_evidence_permission(
    evidence_db: Engine,
) -> None:
    """The gate belongs to the resource, not to whichever members a row happens to carry.

    The refusal has to be identical for a call WITH a protected prompt snapshot and one
    WITHOUT: an unauthorized read must not turn on the presence of an optional member, or
    the unscreened member becomes the ungated one.
    """

    backend = PostgresApiBackend(evidence_db, environment="staging")
    console_only = _principal(evidence=False)
    assert EVIDENCE_READ not in console_only.organization_permissions

    for case in _CASE_ROLES:
        result = backend.read(
            "provider_call_evidence",
            console_only,
            identifiers={"invocation_id": _invocation_id(case)},
        )
        assert result.state == "unavailable", (case, result)
        assert result.reason_code == "evidence_authorization_required", case
        assert result.data is None, case
        serialized = json.dumps(result.model_dump(), sort_keys=True, default=str)
        for forbidden in (
            _RESPONSE_SENTINEL,
            _PROMPT_SENTINEL,
            _LEAKED_DSN_PASSWORD,
            _LEAKED_SECRET_REFERENCE,
        ):
            assert forbidden not in serialized, (case, forbidden)

    # A refusal must also not disclose which invocations exist, so an unknown identifier is
    # refused the same way rather than reported as empty.
    unknown = backend.read(
        "provider_call_evidence",
        console_only,
        identifiers={"invocation_id": "0" * 64},
    )
    assert unknown.state == "unavailable"
    assert unknown.reason_code == "evidence_authorization_required"


def test_provider_call_evidence_screens_a_dsn_out_of_the_recorded_response(
    evidence_db: Engine,
) -> None:
    """A digest proves the bytes were not altered; it proves nothing about a secret in them."""

    app = _app(evidence_db)
    app.dependency_overrides[require_authenticated] = _principal
    response = TestClient(app).get(_evidence_path(_CASE_CREDENTIAL_DSN))
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "ready", payload
    data = payload["data"]
    assert data["prompt"] is None  # the member with no store-side screen
    served = data["response"]

    stored = _response_text(_CASE_CREDENTIAL_DSN)
    assert _LEAKED_DSN in stored and _LEAKED_DSN_PASSWORD in stored

    assert served["text"] == _served_response_text(_CASE_CREDENTIAL_DSN)
    assert _CREDENTIAL_URL_MARKER in served["text"]
    # The screen removes the credential and nothing else.
    assert served["text"].startswith(
        f"upstream error {_RESPONSE_SENTINEL}:{_CASE_CREDENTIAL_DSN} - could not reach "
    )
    assert served["text"].endswith(" after 3 attempts")

    # The digest keeps describing the STORED bytes, so the row stays provable even though
    # what was served is deliberately not those bytes.
    assert served["sha256"] == _digest(stored)
    assert served["sha256"] != _digest(served["text"])

    body = json.dumps(payload, sort_keys=True)
    for forbidden in (_LEAKED_DSN, _LEAKED_DSN_PASSWORD, "db.internal"):
        assert forbidden not in body, forbidden


def test_provider_call_evidence_screens_a_secret_reference_and_leaves_the_prompt_exact(
    evidence_db: Engine,
) -> None:
    app = _app(evidence_db)
    app.dependency_overrides[require_authenticated] = _principal
    response = TestClient(app).get(_evidence_path(_CASE_CREDENTIAL_REFERENCE))
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "ready", payload
    data = payload["data"]
    served = data["response"]

    stored = _response_text(_CASE_CREDENTIAL_REFERENCE)
    assert _LEAKED_SECRET_REFERENCE in stored
    assert served["text"] == _served_response_text(_CASE_CREDENTIAL_REFERENCE)
    assert served["sha256"] == _digest(stored)

    # Only the reference is replaced: the body is still the JSON the model returned.
    decoded = json.loads(served["text"])
    assert decoded["verdict"] == "fail"
    assert decoded["rationale"] == (
        f"{_RESPONSE_SENTINEL}:{_CASE_CREDENTIAL_REFERENCE} resolved via "
        f"{_CREDENTIAL_REFERENCE_MARKER} ok"
    )

    # Screening the response does not weaken or touch the prompt half.
    expected_prompt, expected_messages = _prompt_messages("documentation")
    assert data["prompt"]["system_prompt_content"] == expected_prompt
    assert data["prompt"]["provider_messages"] == expected_messages
    assert data["prompt"]["transcript_sha256"] == _digest(
        canonical_json({"messages": expected_messages})
    )

    assert _LEAKED_SECRET_REFERENCE not in json.dumps(payload, sort_keys=True)


def test_provider_call_evidence_read_model_refuses_an_unscreened_credential(
    evidence_db: Engine,
) -> None:
    """The read model enforces the screen rather than witnessing it."""

    result = PostgresApiBackend(evidence_db, environment="staging").read(
        "provider_call_evidence",
        _principal(),
        identifiers={"invocation_id": _invocation_id(_CASE_CREDENTIAL_DSN)},
    )
    assert result.state == "ready", result
    assert validate_ready_data("provider_call_evidence", result.data) == result.data

    stored = _response_text(_CASE_CREDENTIAL_DSN)
    unscreened = {
        **result.data,
        "response": {"text": stored, "truncated": False, "sha256": _digest(stored)},
    }
    with pytest.raises(ValidationError, match="still contains a credential"):
        validate_ready_data("provider_call_evidence", unscreened)

    # A redaction marker is not a licence to serve anything: a digest mismatch with no
    # marker is still tampering, on a screened row as much as an exact one.
    tampered = {
        **result.data,
        "response": {**result.data["response"], "text": "tampered evidence"},
    }
    with pytest.raises(ValidationError, match="provider response hash"):
        validate_ready_data("provider_call_evidence", tampered)


def test_aggregate_provider_calls_never_exposes_prompt_or_response_content(
    evidence_db: Engine,
) -> None:
    app = _app(evidence_db)
    app.dependency_overrides[require_authenticated] = _principal
    client = TestClient(app)

    for path in (
        f"/api/v1/provider-calls?campaign_id={_RUN_ID}",
        "/api/v1/provider-calls",
    ):
        response = client.get(path)
        assert response.status_code == 200
        payload = response.json()
        assert payload["state"] in {"ready", "empty"}, payload
        serialized = json.dumps(payload, sort_keys=True)
        for forbidden in (
            "response_text",
            "response_sha256",
            "response_truncated",
            "system_prompt_content",
            "provider_messages",
            "transcript_sha256",
            _PROMPT_SENTINEL,
            _RESPONSE_SENTINEL,
            _LEAKED_DSN,
            _LEAKED_DSN_PASSWORD,
            _LEAKED_SECRET_REFERENCE,
            _CREDENTIAL_URL_MARKER,
            _CREDENTIAL_REFERENCE_MARKER,
        ):
            assert forbidden not in serialized, (path, forbidden)

    scoped = client.get(f"/api/v1/provider-calls?campaign_id={_RUN_ID}").json()
    assert scoped["state"] == "ready", scoped
    assert {row["invocation_id"] for row in scoped["data"]} == {
        _invocation_id(case) for case in _CASE_ROLES
    }
    for row in scoped["data"]:
        assert set(row) & {"prompt", "response", "response_text", "response_sha256"} == set()
