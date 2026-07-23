"""M1d protected API, permission, event-stream, and no-client-authority contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi.testclient import TestClient

from agentforge.api.backend import ApiBackend
from agentforge.api.schemas import CommandResult, EventBatch, ResourceResult
from agentforge.web import WebSecurityConfig, create_web_app


class StubBackend(ApiBackend):
    def __init__(self) -> None:
        self.commands: list[tuple[str, str, Mapping[str, Any]]] = []

    def read(self, resource, principal, *, identifiers=None):
        if resource == "principal":
            return ResourceResult.ready(
                {
                    "user_id": principal.user_id,
                    "session_id": principal.session_id,
                    "organization_id": principal.organization_id,
                    "organization_role": principal.organization_role,
                    "organization_permissions": sorted(principal.organization_permissions),
                }
            )
        if resource in {"traces", "costs", "resilience"}:
            return ResourceResult.unavailable(f"{resource}_repository_missing")
        return ResourceResult.empty()

    def command(self, command, principal, payload, *, idempotency_key, identifiers=None):
        self.commands.append((command, idempotency_key, payload))
        return CommandResult.accepted("ack-real", resource_id="server-owned-id")

    def events(self, principal, *, after_cursor, limit):
        return EventBatch(
            events=({"cursor": 1, "type": "snapshot", "payload": {"state": "empty"}},),
            next_cursor=1,
            oldest_cursor=1,
            gap=False,
        )


class ReauthenticatingStreamBackend(StubBackend):
    def events(self, principal, *, after_cursor, limit):
        return EventBatch(
            events=(),
            next_cursor=after_cursor,
            oldest_cursor=after_cursor,
            gap=False,
            terminal=False,
        )


def _install_auth(monkeypatch, auth_environ) -> None:
    for name, value in auth_environ.items():
        monkeypatch.setenv(name, value)


def _app(backend: ApiBackend) -> Any:
    return create_web_app(
        backend=backend,
        readiness_check=lambda: True,
        security_config=WebSecurityConfig(
            environment="staging",
            allowed_origins=("https://staging.headshot.example",),
            clerk_frontend_api_origin="https://clerk.staging.headshot.example",
        ),
    )


def test_meaningful_api_is_default_deny(monkeypatch, auth_environ) -> None:
    _install_auth(monkeypatch, auth_environ)
    client = TestClient(_app(StubBackend()))

    for path in (
        "/api/v1/principal",
        "/api/v1/campaigns",
        "/api/v1/findings",
        "/api/v1/approvals",
        "/api/v1/targets",
        "/api/v1/configuration",
        "/api/v1/components",
        "/api/v1/birdseye",
        "/api/v1/events",
    ):
        response = client.get(path, headers={"Origin": "https://staging.headshot.example"})
        assert response.status_code == 401, path
        assert response.headers["cache-control"] == "no-store"


def test_verified_principal_and_capabilities_are_server_derived(
    monkeypatch, auth_environ, token_factory, auth_values
) -> None:
    _install_auth(monkeypatch, auth_environ)
    token = token_factory(permissions=("org:console:read", "org:findings:read"))

    response = TestClient(_app(StubBackend())).get(
        "/api/v1/principal",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Role": "org:approver",
            "X-Permissions": "org:campaign:authorize",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "ready"
    assert body["data"]["user_id"] == auth_values.user_id
    assert body["data"]["organization_permissions"] == [
        "org:console:read",
        "org:findings:read",
    ]
    assert "org:campaign:authorize" not in str(body)
    assert response.headers["cache-control"] == "no-store"


def test_wrong_org_and_missing_permission_are_forbidden(
    monkeypatch, auth_environ, token_factory
) -> None:
    _install_auth(monkeypatch, auth_environ)
    wrong_org = token_factory(
        permissions=("org:console:read",),
        organization_id="org_2OtherFixture",
    )
    no_findings = token_factory(permissions=("org:console:read",))
    client = TestClient(_app(StubBackend()))

    assert (
        client.get(
            "/api/v1/campaigns", headers={"Authorization": f"Bearer {wrong_org}"}
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/api/v1/findings", headers={"Authorization": f"Bearer {no_findings}"}
        ).status_code
        == 403
    )


def test_command_ignores_forged_identity_and_requires_idempotency(
    monkeypatch, auth_environ, token_factory
) -> None:
    _install_auth(monkeypatch, auth_environ)
    backend = StubBackend()
    token = token_factory(permissions=("org:campaign:launch",))
    payload = {
        "target_id": "target-real",
        "target_version": "1.0.0",
        "surface_id": "surface-real",
        "surface_version": "1.0.0",
        "corpus_hash": "a" * 64,
        "run_nonce": "nonce-1234567890abcd",
        "caps": {
            "budget_usd": 1.0,
            "max_attempts_per_run": 2,
            "target_requests_per_second": 1.0,
            "run_timeout_seconds": 60.0,
        },
    }
    client = TestClient(_app(backend))

    absent_key = client.post(
        "/api/v1/campaign-authorization-requests",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    forged = client.post(
        "/api/v1/campaign-authorization-requests",
        json={**payload, "launcher_user_id": "user_attacker"},
        headers={
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "idem-1234567890abcd",  # gitleaks:allow -- test nonce
            "X-Launcher-User-Id": "user_attacker",
            "X-Permissions": "org:campaign:authorize",
        },
    )

    assert absent_key.status_code == 400
    assert forged.status_code == 422
    assert backend.commands == []


def test_stream_requires_header_token_exact_origin_and_no_query_token(
    monkeypatch, auth_environ, token_factory
) -> None:
    _install_auth(monkeypatch, auth_environ)
    token = token_factory(permissions=("org:console:read",))
    client = TestClient(_app(StubBackend()))

    wrong_origin = client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}", "Origin": "https://evil.example"},
    )
    query_token = client.get(
        f"/api/v1/events?token={token}",
        headers={"Origin": "https://staging.headshot.example"},
    )
    accepted = client.get(
        "/api/v1/events",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": "https://staging.headshot.example",
            "Last-Event-ID": "0",
        },
    )
    browser_same_origin = client.get(
        "/api/v1/events",
        headers={
            "Authorization": f"Bearer {token}",
            "Host": "staging.headshot.example",
            "Sec-Fetch-Site": "same-origin",
        },
    )
    ambiguous_missing_origin = client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert wrong_origin.status_code == 403
    assert query_token.status_code == 400
    assert accepted.status_code == 200
    assert accepted.headers["content-type"].startswith("text/event-stream")
    assert accepted.headers["cache-control"] == "no-store, no-transform"
    assert "id: 1" in accepted.text
    assert "event: snapshot" in accepted.text
    assert token not in accepted.text
    assert browser_same_origin.status_code == 200
    assert ambiguous_missing_origin.status_code == 403


def test_stream_has_a_short_reauthentication_lifetime(
    monkeypatch, auth_environ, token_factory
) -> None:
    """A connected stream must not retain authority for the full browser session."""

    import importlib

    router_module = importlib.import_module("agentforge.api.router")
    monkeypatch.setattr(router_module, "_STREAM_REAUTHENTICATION_SECONDS", 0.01)
    _install_auth(monkeypatch, auth_environ)
    token = token_factory(permissions=("org:console:read",))

    response = TestClient(_app(ReauthenticatingStreamBackend())).get(
        "/api/v1/events",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": "https://staging.headshot.example",
        },
    )

    assert response.status_code == 200
    assert "event: snapshot" in response.text
    assert token not in response.text


def test_unavailable_read_model_is_typed_not_fabricated(
    monkeypatch, auth_environ, token_factory
) -> None:
    _install_auth(monkeypatch, auth_environ)
    token = token_factory(permissions=("org:console:read", "org:evidence:read"))

    response = TestClient(_app(StubBackend())).get(
        "/api/v1/traces", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert response.json() == {
        "state": "unavailable",
        "data": None,
        "reason_code": "traces_repository_missing",
    }
