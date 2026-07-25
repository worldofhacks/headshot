"""RED tests for the SEPARATE active-scan authorization grant (WP-17).

An active (non-passive) scan is NEVER authorized by a campaign RunAuthorization. It requires its
own minted, expiring, content-addressed grant that binds the WHOLE active-scan identity:
exact origin + HTTP methods + path patterns + test principals + pinned container image digest +
addon digests + Automation-Framework active-rule digests + OAST callback domains + caps + nonce.

These tests are pure/offline (stdlib only, no Docker, no socket). They pin the grant's
content-addressing and its fail-closed verify() the same way test_campaign_authorization.py pins
RunAuthorization — a grant minted for one active-scan scope can never authorize a different one.
"""

from __future__ import annotations

import dataclasses

import pytest

from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanAuthorizationError,
    ActiveScanCaps,
    ActiveScanScope,
    active_scan_operation_hash,
)

HEX64_A = "a" * 64
HEX64_B = "b" * 64
HEX64_C = "c" * 64


def _caps() -> ActiveScanCaps:
    return ActiveScanCaps.parse(
        max_requests=200,
        requests_per_second=2.0,
        max_duration_seconds=600.0,
        max_findings=200,
    )


def _scope_kwargs() -> dict[str, object]:
    return {
        "origin": "https://copilot.example-hospital.test",
        "http_methods": ("GET", "POST"),
        "path_patterns": ("/api/copilot", "/api/copilot/*"),
        "principals": ("synthetic-clinician-a", "synthetic-clinician-b"),
        "image_sha256": HEX64_A,
        "addon_sha256s": (HEX64_B,),
        "rule_sha256s": (HEX64_C, "d" * 64),
        "callback_domains": ("oast-abc.agentforge.internal",),
        "caps": _caps(),
        "scope_nonce": "nonce-0123456789ab",
    }


def test_scope_operation_hash_matches_the_pure_function() -> None:
    kwargs = _scope_kwargs()
    scope = ActiveScanScope(**kwargs)
    assert scope.operation_hash() == active_scan_operation_hash(**kwargs)


def test_scope_is_frozen_immutable() -> None:
    scope = ActiveScanScope(**_scope_kwargs())
    with pytest.raises(dataclasses.FrozenInstanceError):
        scope.origin = "https://evil.test"  # type: ignore[misc]


def test_operation_hash_is_deterministic_and_order_independent() -> None:
    base = active_scan_operation_hash(**_scope_kwargs())
    again = active_scan_operation_hash(**_scope_kwargs())
    assert base == again
    assert len(base) == 64

    reordered = _scope_kwargs()
    reordered["http_methods"] = ("POST", "GET")
    reordered["rule_sha256s"] = ("d" * 64, HEX64_C)
    reordered["principals"] = ("synthetic-clinician-b", "synthetic-clinician-a")
    assert active_scan_operation_hash(**reordered) == base, (
        "method/rule/principal sets are order-independent; the grant is content-addressed"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("origin", "https://evil.example.test"),
        ("http_methods", ("GET",)),
        ("path_patterns", ("/api/other",)),
        ("principals", ("synthetic-clinician-a",)),
        ("image_sha256", "0" * 64),
        ("addon_sha256s", ("9" * 64,)),
        ("rule_sha256s", (HEX64_C,)),
        ("callback_domains", ("oast-xyz.agentforge.internal",)),
        ("scope_nonce", "nonce-ffffffffffff"),
    ],
)
def test_operation_hash_changes_when_any_bound_field_changes(field: str, value: object) -> None:
    base = active_scan_operation_hash(**_scope_kwargs())
    mutated = _scope_kwargs()
    mutated[field] = value
    assert active_scan_operation_hash(**mutated) != base, (
        f"changing {field} must rebind the grant (fail closed against scope creep)"
    )


def test_operation_hash_changes_when_any_cap_changes() -> None:
    base = active_scan_operation_hash(**_scope_kwargs())
    mutated = _scope_kwargs()
    mutated["caps"] = ActiveScanCaps.parse(
        max_requests=201,
        requests_per_second=2.0,
        max_duration_seconds=600.0,
        max_findings=200,
    )
    assert active_scan_operation_hash(**mutated) != base


def test_authorization_verify_passes_in_scope_and_unexpired() -> None:
    op = active_scan_operation_hash(**_scope_kwargs())
    grant = ActiveScanAuthorization(
        operation_hash=op, scope_nonce="nonce-0123456789ab", deadline=100.0
    )
    grant.verify(operation_hash=op, scope_nonce="nonce-0123456789ab", now=99.0)  # no raise


def test_authorization_blocks_expired() -> None:
    op = active_scan_operation_hash(**_scope_kwargs())
    grant = ActiveScanAuthorization(operation_hash=op, scope_nonce="n", deadline=100.0)
    with pytest.raises(ActiveScanAuthorizationError, match="EXPIRED"):
        grant.verify(operation_hash=op, scope_nonce="n", now=100.0)


def test_authorization_blocks_operation_hash_mismatch() -> None:
    op = active_scan_operation_hash(**_scope_kwargs())
    grant = ActiveScanAuthorization(operation_hash=op, scope_nonce="n", deadline=100.0)
    with pytest.raises(ActiveScanAuthorizationError, match="SCOPE"):
        grant.verify(operation_hash="0" * 64, scope_nonce="n", now=1.0)


def test_authorization_blocks_scope_nonce_mismatch() -> None:
    op = active_scan_operation_hash(**_scope_kwargs())
    grant = ActiveScanAuthorization(operation_hash=op, scope_nonce="n", deadline=100.0)
    with pytest.raises(ActiveScanAuthorizationError, match="SCOPE"):
        grant.verify(operation_hash=op, scope_nonce="other", now=1.0)


def test_verify_optional_blocks_missing_grant() -> None:
    op = active_scan_operation_hash(**_scope_kwargs())
    with pytest.raises(ActiveScanAuthorizationError, match="no active-scan authorization"):
        ActiveScanAuthorization.verify_optional(None, operation_hash=op, scope_nonce="n", now=1.0)


def test_authorization_is_frozen_immutable() -> None:
    grant = ActiveScanAuthorization(operation_hash=HEX64_A, scope_nonce="n", deadline=1.0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        grant.deadline = 2.0  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "max_requests": 0,
            "requests_per_second": 1.0,
            "max_duration_seconds": 1.0,
            "max_findings": 1,
        },
        {
            "max_requests": -1,
            "requests_per_second": 1.0,
            "max_duration_seconds": 1.0,
            "max_findings": 1,
        },
        {
            "max_requests": 1,
            "requests_per_second": 0.0,
            "max_duration_seconds": 1.0,
            "max_findings": 1,
        },
        {
            "max_requests": 1,
            "requests_per_second": float("inf"),
            "max_duration_seconds": 1.0,
            "max_findings": 1,
        },
        {
            "max_requests": 1,
            "requests_per_second": 1.0,
            "max_duration_seconds": -5.0,
            "max_findings": 1,
        },
        {
            "max_requests": 1,
            "requests_per_second": 1.0,
            "max_duration_seconds": 1.0,
            "max_findings": 0,
        },
    ],
)
def test_caps_parse_is_fail_closed(kwargs: dict[str, float]) -> None:
    with pytest.raises(ActiveScanAuthorizationError):
        ActiveScanCaps.parse(**kwargs)  # type: ignore[arg-type]
