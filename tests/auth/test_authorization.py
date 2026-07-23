"""Custom-permission and two-person authorization invariants."""

from __future__ import annotations

from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentforge.auth.dependencies import (
    require_authenticated,
    require_distinct_approver,
    require_headshot_organization,
    require_permissions,
)
from agentforge.auth.errors import AuthorizationError
from agentforge.auth.principal import Principal

CONSOLE_READ = "org:console:read"
CAMPAIGN_AUTHORIZE = "org:campaign:authorize"
FINDINGS_APPROVE = "org:findings:approve"


def _principal(auth_values, *, user_id=None, role="org:approver", permissions=()):
    return Principal(
        user_id=user_id or auth_values.other_user_id,
        session_id="sess_2AuthorizationFixture",
        organization_id=auth_values.staging_org_id,
        organization_role=role,
        organization_permissions=frozenset(permissions),
    )


def _assert_forbidden(exc: BaseException) -> None:
    assert getattr(exc, "status_code", None) == 403


def _protected_app() -> FastAPI:
    app = FastAPI()

    @app.get("/protected")
    def protected(
        principal: Annotated[Principal, Depends(require_permissions(CONSOLE_READ))],
    ) -> dict[str, str]:
        return {"user_id": principal.user_id}

    return app


def _approval_app(launcher_user_id: str | None = None) -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def install_server_workflow_state(request, call_next):
        if launcher_user_id is not None:
            request.state.launcher_user_id = launcher_user_id
        return await call_next(request)

    @app.post("/approve")
    def approve(
        principal: Annotated[Principal, Depends(require_distinct_approver)],
    ) -> dict[str, str]:
        return {"user_id": principal.user_id}

    return app


def _install_auth_environ(monkeypatch, auth_environ) -> None:
    for name, value in auth_environ.items():
        monkeypatch.setenv(name, value)


def test_require_authenticated_returns_verified_principal(
    auth_config, auth_values, token_factory, request_factory
) -> None:
    principal = require_authenticated(request_factory(token_factory()), auth_config)

    assert principal.user_id == auth_values.user_id
    assert principal.organization_id == auth_values.staging_org_id


def test_request_dependency_config_failure_fails_closed(monkeypatch) -> None:
    for name in (
        "CLERK_PUBLISHABLE_KEY",
        "CLERK_JWT_KEY",
        "CLERK_AUTHORIZED_PARTIES",
        "CLERK_REQUIRED_ORG_ID",
    ):
        monkeypatch.delenv(name, raising=False)

    response = TestClient(_protected_app()).get("/protected")

    assert response.status_code == 503


def test_fastapi_dependency_exposes_no_principal_or_config_client_input(
    monkeypatch, auth_environ
) -> None:
    _install_auth_environ(monkeypatch, auth_environ)
    protected_operation = _protected_app().openapi()["paths"]["/protected"]["get"]
    approval_operation = _approval_app().openapi()["paths"]["/approve"]["post"]

    for operation in (protected_operation, approval_operation):
        assert "requestBody" not in operation
        assert not {
            parameter["name"] for parameter in operation.get("parameters", [])
        }.intersection({"request", "config", "principal", "launcher_user_id"})


def test_fastapi_missing_token_maps_to_401(monkeypatch, auth_environ) -> None:
    _install_auth_environ(monkeypatch, auth_environ)

    response = TestClient(_protected_app()).get("/protected")

    assert response.status_code == 401


def test_forged_principal_body_cannot_create_permission_or_approval_authority(
    monkeypatch, auth_environ, auth_values
) -> None:
    _install_auth_environ(monkeypatch, auth_environ)
    forged_principal = {
        "user_id": auth_values.other_user_id,
        "session_id": auth_values.session_id,
        "organization_id": auth_values.staging_org_id,
        "organization_role": "org:approver",
        "organization_permissions": [CAMPAIGN_AUTHORIZE, FINDINGS_APPROVE],
    }

    protected = TestClient(_protected_app()).request("GET", "/protected", json=forged_principal)
    approval = TestClient(_approval_app()).post(
        "/approve",
        params={"launcher_user_id": auth_values.user_id},
        json=forged_principal,
    )

    assert protected.status_code == 401
    assert approval.status_code == 401


def test_fastapi_distinct_approver_uses_only_server_workflow_state(
    monkeypatch, auth_environ, auth_values, token_factory
) -> None:
    _install_auth_environ(monkeypatch, auth_environ)
    token = token_factory(permissions=(CAMPAIGN_AUTHORIZE,))
    headers = {"Authorization": f"Bearer {token}"}

    distinct = TestClient(_approval_app(auth_values.other_user_id)).post(
        "/approve", headers=headers
    )
    same_user = TestClient(_approval_app(auth_values.user_id)).post("/approve", headers=headers)
    absent_server_state = TestClient(_approval_app()).post("/approve", headers=headers)

    assert distinct.status_code == 200
    assert distinct.json() == {"user_id": auth_values.user_id}
    assert same_user.status_code == 403
    assert absent_server_state.status_code == 403


def test_fastapi_godmode_may_use_audited_self_approval_exception(
    monkeypatch, auth_environ, auth_values, token_factory
) -> None:
    _install_auth_environ(monkeypatch, auth_environ)
    token = token_factory(permissions=(CAMPAIGN_AUTHORIZE,), role="godmode")

    response = TestClient(_approval_app(auth_values.user_id)).post(
        "/approve", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert response.json() == {"user_id": auth_values.user_id}


def test_require_headshot_organization_accepts_exact_match(auth_config, auth_values) -> None:
    principal = _principal(auth_values, permissions=(CONSOLE_READ,))

    assert require_headshot_organization(principal, auth_config) is principal


def test_require_headshot_organization_denies_other_org(auth_config, auth_values) -> None:
    principal = Principal(
        user_id=auth_values.other_user_id,
        session_id="sess_2WrongOrgFixture",
        organization_id="org_2OtherFixture",
        organization_role="org:approver",
        organization_permissions=frozenset({CAMPAIGN_AUTHORIZE}),
    )

    with pytest.raises(AuthorizationError) as excinfo:
        require_headshot_organization(principal, auth_config)

    _assert_forbidden(excinfo.value)


def test_missing_custom_permission_maps_to_403(auth_values) -> None:
    principal = _principal(auth_values, permissions=(CONSOLE_READ,))

    with pytest.raises(AuthorizationError) as excinfo:
        require_permissions(FINDINGS_APPROVE)(principal)

    _assert_forbidden(excinfo.value)


def test_correct_custom_permission_succeeds(auth_values) -> None:
    principal = _principal(auth_values, permissions=(FINDINGS_APPROVE,))

    assert require_permissions(FINDINGS_APPROVE)(principal) is principal


def test_permission_checker_requires_every_requested_permission(auth_values) -> None:
    principal = _principal(auth_values, permissions=(CONSOLE_READ,))

    with pytest.raises(AuthorizationError):
        require_permissions(CONSOLE_READ, FINDINGS_APPROVE)(principal)


def test_role_text_cannot_create_a_custom_permission(
    auth_config, token_factory, request_factory
) -> None:
    token = token_factory(
        permissions=(),
        role="approver",
        claim_overrides={"role": FINDINGS_APPROVE},
    )
    principal = require_authenticated(request_factory(token), auth_config)

    assert principal.organization_role == "org:approver"
    with pytest.raises(AuthorizationError):
        require_permissions(FINDINGS_APPROVE)(principal)


def test_client_supplied_permission_header_is_ignored(
    auth_config, token_factory, request_factory
) -> None:
    request = request_factory(
        token_factory(permissions=()),
        extra_headers={"X-Permissions": FINDINGS_APPROVE},
    )
    principal = require_authenticated(request, auth_config)

    with pytest.raises(AuthorizationError):
        require_permissions(FINDINGS_APPROVE)(principal)


def test_launcher_cannot_approve_own_operation(auth_values) -> None:
    principal = _principal(
        auth_values,
        user_id=auth_values.user_id,
        permissions=(CAMPAIGN_AUTHORIZE,),
    )

    with pytest.raises(AuthorizationError) as excinfo:
        require_distinct_approver(auth_values.user_id, principal)

    _assert_forbidden(excinfo.value)


def test_different_approver_with_permission_succeeds(auth_values) -> None:
    principal = _principal(
        auth_values,
        user_id=auth_values.other_user_id,
        permissions=(CAMPAIGN_AUTHORIZE,),
    )

    assert require_distinct_approver(auth_values.user_id, principal) is principal


def test_different_user_without_authorize_permission_is_not_an_approver(
    auth_values,
) -> None:
    principal = _principal(
        auth_values,
        user_id=auth_values.other_user_id,
        permissions=(),
    )

    with pytest.raises(AuthorizationError):
        require_distinct_approver(auth_values.user_id, principal)
