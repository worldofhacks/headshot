"""Minimal immutable identity produced from a verified Clerk session token."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Principal:
    """Verified human identity with no credential-bearing fields.

    Tokens and request headers are deliberately absent, so ordinary ``repr`` and
    exception rendering cannot disclose them.
    """

    user_id: str
    session_id: str
    organization_id: str
    organization_role: str
    organization_permissions: frozenset[str]
