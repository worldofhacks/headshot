"""Composable FastAPI-facing authentication and authorization helpers."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from typing import Annotated

from fastapi import Depends, Request

from agentforge.auth.clerk import ClerkAuthenticator
from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.errors import (
    AuthConfigurationError,
    AuthenticationUnavailableError,
    AuthorizationError,
)
from agentforge.auth.permissions import (
    CAMPAIGN_AUTHORIZE,
    ORGANIZATION_CUSTOM_PERMISSIONS,
    ROLE_GODMODE,
)
from agentforge.auth.principal import Principal


def get_clerk_auth_config() -> ClerkAuthConfig:
    """Load server-owned auth configuration or fail closed without exception chaining."""

    config = None
    with suppress(AuthConfigurationError):
        config = ClerkAuthConfig.from_env()
    if config is None:
        raise AuthenticationUnavailableError()
    return config


def require_authenticated(
    request: Request,
    config: Annotated[ClerkAuthConfig, Depends(get_clerk_auth_config)],
) -> Principal:
    """Require a valid Headshot Clerk session and return its reduced Principal."""

    return ClerkAuthenticator(config).authenticate(request)


def require_headshot_organization(
    principal: Annotated[Principal, Depends(require_authenticated)],
    config: Annotated[ClerkAuthConfig, Depends(get_clerk_auth_config)],
) -> Principal:
    """Require exact membership in this environment's Headshot Organization."""

    if principal.organization_id != config.required_organization_id:
        raise AuthorizationError()
    return principal


def require_permissions(*required_permissions: str) -> Callable[[Principal], Principal]:
    """Build an all-of custom-permission dependency.

    Role labels are intentionally not consulted and never synthesize authority.
    """

    required = frozenset(required_permissions)
    if not required or not required.issubset(ORGANIZATION_CUSTOM_PERMISSIONS):
        raise AuthConfigurationError("permission dependency is empty or unknown")

    def checker(
        principal: Annotated[Principal, Depends(require_headshot_organization)],
    ) -> Principal:
        if not principal.organization_id or not required.issubset(
            principal.organization_permissions
        ):
            raise AuthorizationError()
        return principal

    return checker


def _launcher_user_id_from_server_state(
    request: Request,
    _principal: Annotated[Principal, Depends(require_headshot_organization)],
) -> str:
    """Read the launcher only from server-resolved workflow state, never client input."""

    launcher_user_id = getattr(request.state, "launcher_user_id", None)
    if (
        not isinstance(launcher_user_id, str)
        or not launcher_user_id.startswith("user_")
        or launcher_user_id == "user_"
    ):
        raise AuthorizationError()
    return launcher_user_id


def require_distinct_approver(
    launcher_user_id: Annotated[str, Depends(_launcher_user_id_from_server_state)],
    principal: Annotated[Principal, Depends(require_headshot_organization)],
) -> Principal:
    """Require a separately identified human with campaign-authorization authority."""

    require_permissions(CAMPAIGN_AUTHORIZE)(principal)
    if not launcher_user_id or (
        principal.user_id == launcher_user_id and principal.organization_role != ROLE_GODMODE
    ):
        raise AuthorizationError()
    return principal
