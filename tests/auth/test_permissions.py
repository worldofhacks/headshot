"""The Headshot human authorization model has exactly two Clerk roles."""

from agentforge.auth.permissions import (
    AUDIT_READ,
    CAMPAIGN_AUTHORIZE,
    CAMPAIGN_LAUNCH,
    ORGANIZATION_ROLES,
    ROLE_APPROVER,
    ROLE_OPERATOR,
    ROLE_PERMISSION_MATRIX,
)


def test_exactly_two_organization_roles_are_supported() -> None:
    assert {ROLE_OPERATOR, ROLE_APPROVER} == ORGANIZATION_ROLES
    assert set(ROLE_PERMISSION_MATRIX) == {ROLE_OPERATOR, ROLE_APPROVER}


def test_both_roles_can_read_audit_and_mutation_authority_stays_separated() -> None:
    operator = ROLE_PERMISSION_MATRIX[ROLE_OPERATOR]
    approver = ROLE_PERMISSION_MATRIX[ROLE_APPROVER]

    assert AUDIT_READ in operator
    assert AUDIT_READ in approver
    assert CAMPAIGN_LAUNCH in operator
    assert CAMPAIGN_AUTHORIZE not in operator
    assert CAMPAIGN_AUTHORIZE in approver
    assert CAMPAIGN_LAUNCH not in approver
