"""Clerk-backed human identity and custom-permission authorization foundation."""

from agentforge.auth.clerk import ClerkAuthenticator
from agentforge.auth.config import ClerkAuthConfig
from agentforge.auth.dependencies import (
    require_authenticated,
    require_distinct_approver,
    require_headshot_organization,
    require_permissions,
)
from agentforge.auth.principal import Principal

__all__ = [
    "ClerkAuthConfig",
    "ClerkAuthenticator",
    "Principal",
    "require_authenticated",
    "require_distinct_approver",
    "require_headshot_organization",
    "require_permissions",
]
