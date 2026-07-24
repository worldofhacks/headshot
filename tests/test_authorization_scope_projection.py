"""Authorization scope endpoints are reconstructed from trusted target definitions only."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import Engine, text

from agentforge.api.postgres import PostgresApiBackend, _scope_projection
from agentforge.auth.principal import Principal
from agentforge.policy.recorder import EvidenceIntegrityError


def _scope() -> dict[str, object]:
    return {
        "target_id": "copilot",
        "target_version": "1.0.0",
        "surface_id": "chat",
        "surface_version": "1.0.0",
        "adapter_kind": "openemr",
        "environment": "staging",
        "exact_host": "target.example.test",
        "auth_mode": "bearer",
        "credential_ref": "secretref://staging/copilot",
        "explicit_no_auth": False,
        "protocol": "https",
        "method": "POST",
        "relative_path": "apis/default/api/copilot/message",
        "corpus_id": "week-3",
        "corpus_hash": "a" * 64,
        "caps": {
            "budget_usd": 1,
            "max_attempts_per_run": 1,
            "target_requests_per_second": 0.5,
            "run_timeout_seconds": 60,
        },
        "run_nonce": "scope-projection-nonce",
        "execution_profile": "live",
    }


def test_scope_endpoint_is_reconstructed_from_matching_target_definition() -> None:
    projection = _scope_projection(
        _scope(),
        target_base_url="https://target.example.test/openemr",
    )

    assert projection["endpoint"] == (
        "https://target.example.test/openemr/apis/default/api/copilot/message"
    )
    assert "credential_ref" not in projection


@pytest.mark.parametrize(
    "target_base_url",
    (
        None,
        "",
        "https://other.example.test/openemr",
        "http://target.example.test/openemr",
        "https://user:password@target.example.test/openemr",
    ),
)
def test_scope_endpoint_refuses_missing_or_mismatched_target_definition(
    target_base_url: str | None,
) -> None:
    with pytest.raises(EvidenceIntegrityError):
        _scope_projection(_scope(), target_base_url=target_base_url)


def test_scope_endpoint_refuses_untrusted_absolute_relative_path() -> None:
    scope = _scope()
    scope["relative_path"] = "/attacker-controlled"

    with pytest.raises(EvidenceIntegrityError):
        _scope_projection(
            scope,
            target_base_url="https://target.example.test/openemr",
        )


def test_approval_projection_reports_typed_unavailable_without_target_definition(
    migrated_db: Engine,
) -> None:
    organization_id = "org_ScopeProjectionFixture"
    with migrated_db.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO campaign_authorization_requests "
                "(request_id, organization_id, scope_hash, scope_payload, launcher_user_id, "
                "launcher_session_id, expires_at) VALUES "
                "(:request_id, :org, :scope_hash, CAST(:scope AS jsonb), :user, :session, "
                "clock_timestamp() + INTERVAL '10 minutes')"
            ),
            {
                "request_id": "scope-projection-request",
                "org": organization_id,
                "scope_hash": "b" * 64,
                "scope": json.dumps(_scope()),
                "user": "user_ScopeProjection",
                "session": "sess_ScopeProjection",
            },
        )
    principal = Principal(
        user_id="user_ScopeProjection",
        session_id="sess_ScopeProjection",
        organization_id=organization_id,
        organization_role="org:operator",
        organization_permissions=frozenset(),
    )

    result = PostgresApiBackend(migrated_db, environment="staging").read(
        "approvals",
        principal,
    )

    assert result.state == "unavailable"
    assert result.reason_code == "authorization_scope_endpoint_unavailable"
    assert result.data is None
