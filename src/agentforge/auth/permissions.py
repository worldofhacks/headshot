"""Headshot Organization roles and custom-permission vocabulary.

The matrix is provisioning/documentation metadata. Runtime authorization always
checks the verified custom permissions carried by :class:`Principal`; it never
derives authority from a role label.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final

ROLE_OBSERVER: Final = "org:observer"
ROLE_OPERATOR: Final = "org:operator"
ROLE_APPROVER: Final = "org:approver"
ROLE_AUDITOR: Final = "org:auditor"
ROLE_GODMODE: Final = "org:godmode"

ORGANIZATION_ROLES: Final = frozenset(
    {ROLE_OBSERVER, ROLE_OPERATOR, ROLE_APPROVER, ROLE_AUDITOR, ROLE_GODMODE}
)

CONSOLE_READ: Final = "org:console:read"
FINDINGS_READ: Final = "org:findings:read"
EVIDENCE_READ: Final = "org:evidence:read"
CAMPAIGN_LAUNCH: Final = "org:campaign:launch"
CAMPAIGN_ABORT: Final = "org:campaign:abort"
CAMPAIGN_AUTHORIZE: Final = "org:campaign:authorize"
TARGETS_MANAGE: Final = "org:targets:manage"
CONFIG_MANAGE: Final = "org:config:manage"
FINDINGS_APPROVE: Final = "org:findings:approve"
FINDINGS_RESOLVE: Final = "org:findings:resolve"
AUDIT_READ: Final = "org:audit:read"

ORGANIZATION_CUSTOM_PERMISSIONS: Final = frozenset(
    {
        CONSOLE_READ,
        FINDINGS_READ,
        EVIDENCE_READ,
        CAMPAIGN_LAUNCH,
        CAMPAIGN_ABORT,
        CAMPAIGN_AUTHORIZE,
        TARGETS_MANAGE,
        CONFIG_MANAGE,
        FINDINGS_APPROVE,
        FINDINGS_RESOLVE,
        AUDIT_READ,
    }
)

_READ_PERMISSIONS = frozenset({CONSOLE_READ, FINDINGS_READ, EVIDENCE_READ})

ROLE_PERMISSION_MATRIX: Final = MappingProxyType(
    {
        ROLE_OBSERVER: _READ_PERMISSIONS,
        ROLE_OPERATOR: _READ_PERMISSIONS
        | frozenset(
            {
                CAMPAIGN_LAUNCH,
                CAMPAIGN_ABORT,
                TARGETS_MANAGE,
                CONFIG_MANAGE,
            }
        ),
        ROLE_APPROVER: _READ_PERMISSIONS
        | frozenset({CAMPAIGN_AUTHORIZE, FINDINGS_APPROVE, FINDINGS_RESOLVE}),
        ROLE_AUDITOR: _READ_PERMISSIONS | frozenset({AUDIT_READ}),
        # Demo/grader role. Runtime authority still comes only from verified Clerk custom-
        # permission claims. Campaign self-approval is allowed only for this verified role and
        # is persisted as an explicit override for database/Runner revalidation.
        ROLE_GODMODE: ORGANIZATION_CUSTOM_PERMISSIONS,
    }
)
