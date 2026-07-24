"""RED tests for WP-17 authenticated-scan matrix — principals x auth modes, markers never secrets.

An authenticated active scan probes the target as provisioned SYNTHETIC test principals across auth
modes (e.g. unauthenticated vs. clinician-scoped). The matrix binds each principal to a credential
*marker* — a sha256 of the credential reference, or an explicit no-auth marker — exactly like the
campaign operation hash. A raw secret value never enters the matrix, and a principal the scope did
not authorize is refused. The matrix is content-addressed so the authenticated surface is pinnable.

Offline; stdlib only; no secret resolution.
"""

from __future__ import annotations

import hashlib

import pytest

from agentforge.security_tools.active_authorization import ActiveScanCaps, ActiveScanScope
from agentforge.security_tools.auth_matrix import AuthenticationMatrix, build_auth_matrix


def _scope() -> ActiveScanScope:
    return ActiveScanScope(
        origin="https://copilot.example-hospital.test",
        http_methods=("GET", "POST"),
        path_patterns=("/api/copilot/*",),
        principals=("synthetic-anon", "synthetic-clinician-a"),
        image_sha256="a" * 64,
        addon_sha256s=("b" * 64,),
        rule_sha256s=("c" * 64,),
        callback_domains=("oast.agentforge.internal",),
        caps=ActiveScanCaps.parse(
            max_requests=100,
            requests_per_second=10.0,
            max_duration_seconds=600.0,
            max_findings=200,
        ),
        scope_nonce="nonce-0123456789ab",
    )


def _entries():
    return [
        ("synthetic-anon", "none", None),
        ("synthetic-clinician-a", "bearer", "secretref://staging/copilot-clinician-a"),
    ]


def test_matrix_binds_principals_to_markers_never_secrets() -> None:
    matrix = build_auth_matrix(_entries(), scope=_scope())
    assert isinstance(matrix, AuthenticationMatrix)
    assert matrix.marker("synthetic-anon", "none") == "no-auth"
    ref = "secretref://staging/copilot-clinician-a"
    expected = "cred-sha256:" + hashlib.sha256(ref.encode()).hexdigest()
    assert matrix.marker("synthetic-clinician-a", "bearer") == expected
    # The raw reference/value is nowhere in the serialized matrix.
    assert ref not in matrix.canonical_json()


def test_matrix_rejects_a_principal_outside_the_scope() -> None:
    entries = _entries() + [("intruder", "bearer", "secretref://x")]
    with pytest.raises(ValueError, match="principal"):
        build_auth_matrix(entries, scope=_scope())


def test_matrix_rejects_a_raw_credential_value() -> None:
    entries = [("synthetic-clinician-a", "bearer", "sid=live-session-abc123")]
    with pytest.raises(ValueError, match="reference"):
        build_auth_matrix(entries, scope=_scope())


def test_matrix_requires_a_reference_when_auth_mode_is_not_none() -> None:
    entries = [("synthetic-clinician-a", "bearer", None)]
    with pytest.raises(ValueError, match="reference"):
        build_auth_matrix(entries, scope=_scope())


def test_matrix_is_content_addressed_and_deterministic() -> None:
    a = build_auth_matrix(_entries(), scope=_scope())
    b = build_auth_matrix(list(reversed(_entries())), scope=_scope())
    assert a.matrix_sha256 == b.matrix_sha256, "order-independent content address"
    assert len(a.matrix_sha256) == 64
