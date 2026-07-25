"""RED tests for real (active, non-passive) ZAP scanning (WP-17).

zap.py stays passive-only forever (its invariant docstring forbids constructing an active-scan
command). Active scanning lives in the SEPARATE zap_profiles.py, which:

* constructs an active-scan docker argv (zap-api-scan.py) ONLY behind a verified
  ActiveScanAuthorization whose bound scope matches the command exactly;
* pins the container image + a fixed Automation-Framework active-rule subset by digest, and
  refuses a scope that did not authorize those exact pinned digests;
* denies identity-provider, cloud-metadata, private/loopback, and non-approved origins so an
  active scanner can never be turned into an SSRF or a credential-theft primitive.

All offline: these tests assert on the *constructed* argv and the origin gate; nothing is executed
(a live active scan runs only in the private Runner under owner authorization).
"""

from __future__ import annotations

import pytest

from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanAuthorizationError,
    ActiveScanCaps,
    ActiveScanScope,
)
from agentforge.security_tools.zap import ZAP_IMAGE
from agentforge.security_tools.zap_profiles import (
    ACTIVE_SCAN_RULE_SUBSET,
    ACTIVE_ZAP_IMAGE_SHA256,
    active_scan_argv,
    active_scan_rule_subset_sha256,
    validate_active_scan_target,
)

APPROVED = "https://copilot.example-hospital.test"


def _caps() -> ActiveScanCaps:
    return ActiveScanCaps.parse(
        max_requests=200,
        requests_per_second=2.0,
        max_duration_seconds=600.0,
        max_findings=200,
    )


def _scope(
    *,
    image_sha256: str | None = None,
    rule_sha256s: tuple[str, ...] | None = None,
    origin: str = APPROVED,
) -> ActiveScanScope:
    return ActiveScanScope(
        origin=origin,
        http_methods=("GET", "POST"),
        path_patterns=("/api/copilot", "/api/copilot/*"),
        principals=("synthetic-clinician-a",),
        image_sha256=image_sha256 or ACTIVE_ZAP_IMAGE_SHA256,
        addon_sha256s=("b" * 64,),
        rule_sha256s=rule_sha256s or (active_scan_rule_subset_sha256(),),
        callback_domains=("oast-abc.agentforge.internal",),
        caps=_caps(),
        scope_nonce="nonce-0123456789ab",
    )


def _grant(scope: ActiveScanScope, *, deadline: float = 1000.0) -> ActiveScanAuthorization:
    return ActiveScanAuthorization(
        operation_hash=scope.operation_hash(),
        scope_nonce=scope.scope_nonce,
        deadline=deadline,
    )


def _argv(scope: ActiveScanScope, grant: ActiveScanAuthorization | None, **over) -> tuple[str, ...]:
    kwargs = {
        "approved_origin": APPROVED,
        "openapi_spec_url": f"{APPROVED}/api/openapi.json",
        "report_path": "/reports/active.json",
        "now": 1.0,
    }
    kwargs.update(over)
    return active_scan_argv(scope, grant, **kwargs)


# --- pinned rule subset -------------------------------------------------------------------------


def test_active_rule_subset_digest_is_deterministic_and_covers_high_risk_classes() -> None:
    digest = active_scan_rule_subset_sha256()
    assert len(digest) == 64 and digest == active_scan_rule_subset_sha256()
    plugin_ids = {rule.plugin_id for rule in ACTIVE_SCAN_RULE_SUBSET}
    # SQL injection, reflected XSS, remote OS command injection, SSRF must be in the active subset.
    assert {"40018", "40012", "90020", "40046"} <= plugin_ids


def test_active_rule_subset_excludes_destructive_dos_rules() -> None:
    from agentforge.security_tools.zap_profiles import FORBIDDEN_ACTIVE_RULE_IDS

    plugin_ids = {rule.plugin_id for rule in ACTIVE_SCAN_RULE_SUBSET}
    # Buffer/format/integer-overflow (crash/DoS) and any delete/auth-mutating class are excluded.
    assert plugin_ids.isdisjoint(FORBIDDEN_ACTIVE_RULE_IDS)


# --- authorization gate -------------------------------------------------------------------------


def test_active_scan_argv_requires_a_verified_grant() -> None:
    scope = _scope()
    with pytest.raises(ActiveScanAuthorizationError, match="no active-scan authorization"):
        _argv(scope, None)
    wrong = ActiveScanAuthorization(
        operation_hash="0" * 64, scope_nonce=scope.scope_nonce, deadline=1000.0
    )
    with pytest.raises(ActiveScanAuthorizationError, match="SCOPE"):
        _argv(scope, wrong)


def test_active_scan_argv_refuses_an_expired_grant() -> None:
    scope = _scope()
    with pytest.raises(ActiveScanAuthorizationError, match="EXPIRED"):
        _argv(scope, _grant(scope, deadline=1.0), now=1.0)


# --- command construction -----------------------------------------------------------------------


def test_active_scan_argv_builds_a_pinned_isolated_active_command() -> None:
    scope = _scope()
    argv = _argv(scope, _grant(scope))
    assert argv[0] == "docker"
    assert ZAP_IMAGE in argv
    assert "--network=agentforge-zap-isolated" in argv
    assert "--read-only" in argv
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    # Active, never passive.
    assert "zap-api-scan.py" in argv
    assert "zap-baseline.py" not in argv
    assert "/reports/active.json" in argv


def test_active_scan_argv_encodes_the_pinned_rule_subset() -> None:
    scope = _scope()
    joined = " ".join(_argv(scope, _grant(scope)))
    for rule in ACTIVE_SCAN_RULE_SUBSET:
        assert rule.plugin_id in joined


def test_active_scan_argv_refuses_a_scope_that_did_not_authorize_the_pinned_rules() -> None:
    scope = _scope(rule_sha256s=("f" * 64,))
    with pytest.raises(ActiveScanAuthorizationError, match="rule subset"):
        _argv(scope, _grant(scope))


def test_active_scan_argv_refuses_an_unpinned_image() -> None:
    scope = _scope(image_sha256="e" * 64)
    with pytest.raises(ActiveScanAuthorizationError, match="image"):
        _argv(scope, _grant(scope))


def test_active_scan_argv_refuses_an_openapi_spec_off_the_approved_origin() -> None:
    scope = _scope()
    with pytest.raises(ValueError, match="approved origin"):
        _argv(scope, _grant(scope), openapi_spec_url="https://evil.example.test/openapi.json")


# --- origin deny-list ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        "https://copilot.clerk.accounts.dev",
        "https://tenant.okta.com",
        "https://login.microsoftonline.com",
        "https://accounts.google.com",
    ],
)
def test_validate_active_scan_target_rejects_identity_providers(origin: str) -> None:
    with pytest.raises(ValueError, match="identity-provider"):
        validate_active_scan_target(origin, approved_origin=origin)


@pytest.mark.parametrize(
    "origin",
    [
        "https://169.254.169.254",
        "https://metadata.google.internal",
        "https://100.100.200.200",
    ],
)
def test_validate_active_scan_target_rejects_cloud_metadata(origin: str) -> None:
    with pytest.raises(ValueError, match="metadata"):
        validate_active_scan_target(origin, approved_origin=origin)


@pytest.mark.parametrize(
    "origin",
    [
        "https://127.0.0.1",
        "https://10.0.0.5",
        "https://192.168.1.10",
        "https://[fd00::1]",
    ],
)
def test_validate_active_scan_target_rejects_private_and_loopback(origin: str) -> None:
    with pytest.raises(ValueError, match="private|loopback|internal"):
        validate_active_scan_target(origin, approved_origin=origin)


@pytest.mark.parametrize(
    "origin",
    [
        "http://copilot.example-hospital.test",  # not https
        "https://user:pw@copilot.example-hospital.test",  # credentials
        "https://copilot.example-hospital.test/path",  # non-root path
        "https://copilot.example-hospital.test/?q=1",  # query
    ],
)
def test_validate_active_scan_target_rejects_non_https_and_credentialed(origin: str) -> None:
    with pytest.raises(ValueError):
        validate_active_scan_target(origin, approved_origin=APPROVED)


def test_validate_active_scan_target_requires_the_exact_approved_origin() -> None:
    with pytest.raises(ValueError, match="approved origin"):
        validate_active_scan_target("https://other.example-hospital.test", approved_origin=APPROVED)


def test_validate_active_scan_target_returns_the_normalized_origin() -> None:
    assert validate_active_scan_target(APPROVED + "/", approved_origin=APPROVED) == APPROVED
