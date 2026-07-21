"""Networkless Clerk session-token authentication."""

from __future__ import annotations

import time
from collections.abc import Callable
from contextlib import suppress
from typing import Any

from clerk_backend_api.security import (
    AuthenticateRequestOptions,
)
from clerk_backend_api.security import (
    authenticate_request as clerk_authenticate_request,
)

from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.errors import (
    AuthenticationError,
    AuthenticationUnavailableError,
    AuthorizationError,
)
from agentforge.auth.permissions import (
    ORGANIZATION_CUSTOM_PERMISSIONS,
    ORGANIZATION_ROLES,
)
from agentforge.auth.principal import Principal

Verifier = Callable[[Any, AuthenticateRequestOptions], Any]


def _scrub_request_state(state: Any) -> None:
    """Best-effort removal of the SDK's credential-bearing request state."""

    with suppress(Exception):
        state.token = None
    with suppress(Exception):
        state.payload = None


def _required_claim(payload: dict[str, Any], name: str, prefix: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.startswith(prefix) or len(value) == len(prefix):
        raise AuthenticationError()
    return value


class ClerkAuthenticator:
    """Turn a verified Clerk human session into a reduced immutable Principal."""

    def __init__(
        self,
        config: ClerkAuthConfig,
        *,
        verifier: Verifier = clerk_authenticate_request,
    ) -> None:
        self._config = config
        self._verifier = verifier

    def authenticate(self, request: Any) -> Principal:
        """Authenticate one request without a Clerk/JWKS network call."""

        options = AuthenticateRequestOptions(
            jwt_key=self._config.jwt_key,
            authorized_parties=list(self._config.authorized_parties),
            accepts_token=["session_token"],
            clock_skew_in_ms=self._config.clock_skew_in_ms,
        )

        state = None
        with suppress(Exception):
            state = self._verifier(request, options)
        # Do not retain a credential-bearing request in an exception frame.
        request = None
        if state is None:
            # Raised after leaving the verifier's exception context so a leaky SDK
            # exception cannot survive as ``__context__`` on the public error.
            raise AuthenticationUnavailableError()

        state_read = False
        is_authenticated = False
        raw_payload = None
        try:
            with suppress(Exception):
                is_authenticated = state.is_authenticated
                raw_payload = state.payload
                state_read = True
        finally:
            _scrub_request_state(state)

        if not state_read:
            raise AuthenticationUnavailableError()
        if not is_authenticated:
            raise AuthenticationError()
        if not isinstance(raw_payload, dict):
            raise AuthenticationUnavailableError()
        payload = dict(raw_payload)

        principal = None
        try:
            principal = self._principal_from_payload(payload)
        except (AuthenticationError, AuthorizationError):
            raise
        except Exception:
            pass
        if principal is None:
            payload.clear()
            raise AuthenticationUnavailableError()
        return principal

    def _principal_from_payload(self, payload: dict[str, Any]) -> Principal:
        user_id = _required_claim(payload, "sub", "user_")
        session_id = _required_claim(payload, "sid", "sess_")

        expiration = payload.get("exp")
        if isinstance(expiration, bool) or not isinstance(expiration, (int, float)):
            raise AuthenticationError()
        skew_seconds = self._config.clock_skew_in_ms / 1_000
        now = time.time()
        if expiration < now - skew_seconds:
            raise AuthenticationError()

        not_before = payload.get("nbf")
        if not_before is not None and (
            isinstance(not_before, bool)
            or not isinstance(not_before, (int, float))
            or not_before > now + skew_seconds
        ):
            raise AuthenticationError()

        issued_at = payload.get("iat")
        if issued_at is not None and (
            isinstance(issued_at, bool)
            or not isinstance(issued_at, (int, float))
            or issued_at > now + skew_seconds
        ):
            raise AuthenticationError()

        session_status = payload.get("sts")
        if session_status is not None and session_status != "active":
            raise AuthenticationError()

        # Actor/impersonation sessions do not prove the human identity separation
        # required by Headshot's two-person controls.
        if payload.get("act") is not None:
            raise AuthorizationError()

        organization_id = payload.get("org_id")
        if organization_id != self._config.required_organization_id:
            raise AuthorizationError()

        raw_role = payload.get("org_role")
        if not isinstance(raw_role, str) or not raw_role:
            raise AuthorizationError()
        organization_role = raw_role if raw_role.startswith("org:") else f"org:{raw_role}"
        if organization_role not in ORGANIZATION_ROLES:
            raise AuthorizationError()

        raw_permissions = payload.get("org_permissions", ())
        if raw_permissions is None:
            raw_permissions = ()
        if not isinstance(raw_permissions, (list, tuple, set, frozenset)):
            raise AuthorizationError()
        organization_permissions = frozenset(
            permission
            for permission in raw_permissions
            if isinstance(permission, str) and permission in ORGANIZATION_CUSTOM_PERMISSIONS
        )

        return Principal(
            user_id=user_id,
            session_id=session_id,
            organization_id=organization_id,
            organization_role=organization_role,
            organization_permissions=organization_permissions,
        )
