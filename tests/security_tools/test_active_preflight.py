"""RED tests for WP-21A active-scan preflight — a ZERO-CALL readiness proof.

Before the private Runner executes an active scan (WP-21D), a preflight proves the whole plan is
ready WITHOUT touching the target: the grant is present/unexpired/in-scope, the origin passes the
deny-list and equals the owner-approved origin, the image + rule subset are the pinned ones, the
OAST domains are private, every principal is synthetic, at least one in-scope operation was
discovered, and the auth matrix carries markers not secrets. The result is structured (ok + a
per-check report), never an exception — a Runner reads it to decide whether to proceed.

Fully offline: the preflight composes only the offline active-scan modules; a socket patched to
raise proves it makes zero calls.
"""

from __future__ import annotations

import socket

import pytest

from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanCaps,
    ActiveScanScope,
)
from agentforge.security_tools.active_preflight import active_scan_preflight
from agentforge.security_tools.zap_profiles import (
    ACTIVE_ZAP_IMAGE_SHA256,
    active_scan_rule_subset_sha256,
)

APPROVED = "https://copilot.example-hospital.test"


def _scope(**over) -> ActiveScanScope:
    kwargs = dict(
        origin=APPROVED,
        http_methods=("GET", "POST"),
        path_patterns=("/api/copilot", "/api/copilot/*"),
        principals=("synthetic-anon", "synthetic-clinician-a"),
        image_sha256=ACTIVE_ZAP_IMAGE_SHA256,
        addon_sha256s=("b" * 64,),
        rule_sha256s=(active_scan_rule_subset_sha256(),),
        callback_domains=("oast.agentforge.internal",),
        caps=ActiveScanCaps.parse(
            max_requests=200, requests_per_second=2.0, max_duration_seconds=600.0, max_findings=200
        ),
        scope_nonce="nonce-0123456789ab",
    )
    kwargs.update(over)
    return ActiveScanScope(**kwargs)


def _grant(scope: ActiveScanScope, *, deadline: float = 1000.0) -> ActiveScanAuthorization:
    return ActiveScanAuthorization(
        operation_hash=scope.operation_hash(), scope_nonce=scope.scope_nonce, deadline=deadline
    )


def _spec() -> dict:
    return {
        "openapi": "3.0.0",
        "paths": {"/api/copilot": {"post": {"parameters": [{"name": "prompt"}]}, "get": {}}},
    }


def _entries():
    return [
        ("synthetic-anon", "none", None),
        ("synthetic-clinician-a", "bearer", "secretref://staging/clinician-a"),
    ]


def _preflight(scope, grant, **over):
    kwargs = dict(
        approved_origin=APPROVED,
        openapi_spec=_spec(),
        auth_matrix_entries=_entries(),
        now=1.0,
    )
    kwargs.update(over)
    return active_scan_preflight(scope, grant, **kwargs)


def test_preflight_passes_for_a_fully_authorized_synthetic_plan() -> None:
    scope = _scope()
    result = _preflight(scope, _grant(scope))
    assert result.ok, [c for c in result.checks if not c.passed]
    assert all(c.passed for c in result.checks)
    assert result.scope_operation_hash == scope.operation_hash()
    # A readiness proof names every gate it checked.
    names = {c.name for c in result.checks}
    assert {
        "authorization",
        "origin",
        "image_pinned",
        "rule_subset_pinned",
        "oast_private",
        "synthetic_principals",
        "discovered_surface",
        "auth_matrix",
    } <= names


def test_preflight_makes_zero_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("preflight opened a socket")

    monkeypatch.setattr(socket, "socket", _boom)
    scope = _scope()
    assert _preflight(scope, _grant(scope)).ok


def test_preflight_passes_with_oast_disabled_when_no_callback_domain() -> None:
    # OAST stays BLOCKED (not attempted) unless the owner provides a callback domain; the scan is
    # still ready without it, so the oast check passes as "disabled".
    scope = _scope(callback_domains=())
    result = _preflight(scope, _grant(scope))
    assert result.ok, [c for c in result.checks if not c.passed]
    oast = next(c for c in result.checks if c.name == "oast_private")
    assert oast.passed and "disabled" in oast.detail.lower()


def test_preflight_fails_without_a_grant_but_does_not_raise() -> None:
    result = _preflight(_scope(), None)
    assert result.ok is False
    auth = next(c for c in result.checks if c.name == "authorization")
    assert auth.passed is False


def test_preflight_fails_on_an_expired_grant() -> None:
    scope = _scope()
    result = _preflight(scope, _grant(scope, deadline=1.0), now=5.0)
    assert result.ok is False
    assert not next(c for c in result.checks if c.name == "authorization").passed


def test_preflight_fails_on_a_non_synthetic_principal() -> None:
    scope = _scope(principals=("synthetic-anon", "real-clinician-jane"))
    result = _preflight(
        scope,
        _grant(scope),
        auth_matrix_entries=[("synthetic-anon", "none", None)],
    )
    assert result.ok is False
    assert not next(c for c in result.checks if c.name == "synthetic_principals").passed


@pytest.mark.parametrize("field", ["image_sha256", "rule_sha256s"])
def test_preflight_fails_on_unpinned_image_or_rules(field: str) -> None:
    scope = _scope(**{field: ("z" * 64,) if field == "rule_sha256s" else "z" * 64})
    result = _preflight(scope, _grant(scope))
    assert result.ok is False


def test_preflight_fails_on_a_denied_origin() -> None:
    scope = _scope(origin="https://169.254.169.254")
    result = _preflight(scope, _grant(scope), approved_origin="https://169.254.169.254")
    assert result.ok is False
    assert not next(c for c in result.checks if c.name == "origin").passed


def test_preflight_fails_when_no_in_scope_operation_is_discovered() -> None:
    scope = _scope()
    spec = {"openapi": "3.0.0", "paths": {"/admin/users": {"delete": {}}}}
    result = _preflight(scope, _grant(scope), openapi_spec=spec)
    assert result.ok is False
    assert not next(c for c in result.checks if c.name == "discovered_surface").passed
