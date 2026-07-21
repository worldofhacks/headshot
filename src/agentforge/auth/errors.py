"""Fail-closed, credential-free authentication and authorization errors."""

from __future__ import annotations

from fastapi import HTTPException, status


class AuthConfigurationError(ValueError):
    """Raised when the Clerk request-authentication contract is unsafe or incomplete."""


class AuthenticationError(HTTPException):
    """A missing, invalid, expired, or otherwise unacceptable session token."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )


class AuthorizationError(HTTPException):
    """A verified identity that is not authorized for the requested operation."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden",
        )


class AuthenticationUnavailableError(HTTPException):
    """Authentication could not be evaluated safely, so the request is denied."""

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication unavailable",
        )
