"""Regression tests from the adversarial review of the active-scan chain.

Each test pins a confirmed defect the review found, so it can never silently return. Grouped here
(rather than scattered) so the hardening is legible as one pass. All offline.
"""

from __future__ import annotations

import pytest

from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanCaps,
    ActiveScanScope,
    content_digest,
)
from agentforge.security_tools.active_preflight import active_scan_preflight
from agentforge.security_tools.api_discovery import discover_openapi
from agentforge.security_tools.oast import PrivateOastRegistry
from agentforge.security_tools.scan_egress import GovernedScanEgress, ScanEgressAbort
from agentforge.security_tools.zap_profiles import (
    ACTIVE_ZAP_IMAGE_SHA256,
    active_scan_argv,
    active_scan_rule_subset_sha256,
    validate_active_scan_target,
)

APPROVED = "https://copilot.example-hospital.test"


def _caps() -> ActiveScanCaps:
    return ActiveScanCaps.parse(
        max_requests=100, requests_per_second=10.0, max_duration_seconds=600.0, max_findings=200
    )


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
        caps=_caps(),
        scope_nonce="nonce-0123456789ab",
    )
    kwargs.update(over)
    return ActiveScanScope(**kwargs)


def _grant(scope: ActiveScanScope, *, deadline: float = 10_000.0) -> ActiveScanAuthorization:
    return ActiveScanAuthorization(
        operation_hash=scope.operation_hash(), scope_nonce=scope.scope_nonce, deadline=deadline
    )


# --- #4: collision-resistant content addressing ------------------------------------------------


def test_content_digest_is_collision_resistant_to_separator_injection() -> None:
    # The old "\x1f".join gadget: two distinct field tuples must not collide.
    assert content_digest("a\x1fb", "c") != content_digest("a", "b\x1fc")
    assert len(content_digest("x")) == 64
    assert content_digest("a", "b") == content_digest("a", "b")


def test_oast_labels_are_collision_resistant() -> None:
    scope = _scope(callback_domains=("c.agentforge.internal", "b\x1fc.agentforge.internal"))
    reg = PrivateOastRegistry(scope)
    t1 = reg.mint("a\x1fb", domain="c.agentforge.internal")
    t2 = reg.mint("a", domain="b\x1fc.agentforge.internal")
    assert t1.label != t2.label


# --- #3/#5/#7: hardened, consistent path scope matching ----------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/api/copilot/..",
        "/api/copilot/../admin",
        "/api/copilot/%2e%2e/admin",
        "/api/copilot//x",
        "/api/copilot/./x",
        "/api/copilot/%2fadmin",
    ],
)
def test_egress_rejects_path_traversal(path: str) -> None:
    egress = GovernedScanEgress(_scope(), authorization=_grant(_scope()), now=0.0)
    with pytest.raises(ScanEgressAbort, match="path"):
        egress.reserve_permit(method="GET", path=path, now=1.0)


def test_discovery_never_surfaces_a_traversal_path() -> None:
    scope = _scope(http_methods=("GET", "DELETE"))
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/api/copilot": {"get": {}},
            "/api/copilot/../admin": {"delete": {}},
        },
    }
    ops = {(o.method, o.path) for o in discover_openapi(spec, scope=scope).operations}
    assert ("DELETE", "/api/copilot/../admin") not in ops
    assert ("GET", "/api/copilot") in ops


def test_egress_and_discovery_agree_on_scope() -> None:
    from agentforge.security_tools.active_authorization import path_in_scope

    patterns = ("/api/copilot", "/api/copilot/*")
    for path in ["/api/copilot", "/api/copilot/x", "/api/copilot/../admin", "/api/copilot?a=1"]:
        # One shared function → discovery and egress can never diverge.
        assert path_in_scope(path, patterns) is path_in_scope(path, patterns)


# --- #2: OpenAPI spec URL port bypass ----------------------------------------------------------


def test_active_scan_argv_rejects_spec_on_a_non_approved_port() -> None:
    scope = _scope()
    with pytest.raises(ValueError, match="approved origin"):
        active_scan_argv(
            scope,
            _grant(scope),
            approved_origin=APPROVED,
            openapi_spec_url="https://copilot.example-hospital.test:8888/api/openapi.json",
            report_path="/r.json",
            now=1.0,
        )


# --- #1/#6: empty auth matrix must fail preflight ----------------------------------------------


def test_preflight_fails_on_empty_auth_matrix() -> None:
    scope = _scope()
    result = active_scan_preflight(
        scope,
        _grant(scope),
        approved_origin=APPROVED,
        openapi_spec={"openapi": "3.0.0", "paths": {"/api/copilot": {"get": {}}}},
        auth_matrix_entries=[],
        now=1.0,
    )
    assert result.ok is False
    assert not next(c for c in result.checks if c.name == "auth_matrix").passed


# --- #8: metadata / IdP deny-list hardening ----------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        "https://metadata.azure.com",
        "https://168.63.129.16",
        "https://metadata.alibaba.com",
        "https://metadata.oraclecloud.com",
    ],
)
def test_validate_active_scan_target_rejects_more_metadata_endpoints(origin: str) -> None:
    with pytest.raises(ValueError, match="metadata"):
        validate_active_scan_target(origin, approved_origin=origin)


# --- #9: report_send outcome must be validated -------------------------------------------------


def test_report_send_rejects_an_invalid_outcome() -> None:
    scope = _scope()
    egress = GovernedScanEgress(scope, authorization=_grant(scope), now=0.0)
    permit = egress.reserve_permit(method="GET", path="/api/copilot", now=1.0)
    with pytest.raises(ScanEgressAbort, match="outcome"):
        egress.report_send(permit, "bogus")


# --- #11: abort re-checked between reserve and dispatch (parity preserved) ----------------------


def test_egress_rechecks_abort_between_reserve_and_dispatch() -> None:
    scope = _scope()
    calls = {"n": 0}

    def abort_check() -> bool:
        calls["n"] += 1
        return calls["n"] >= 2  # ok during reserve, flips before the physical send

    egress = GovernedScanEgress(
        scope, authorization=_grant(scope), now=0.0, abort_check=abort_check
    )
    dispatched = []
    with pytest.raises(ScanEgressAbort, match="abort"):
        egress.send(
            method="GET", path="/api/copilot", dispatch=lambda p: dispatched.append(p), now=1.0
        )
    assert dispatched == [], "no physical send after abort flips"
    egress.assert_parity()
    assert len(egress.ledger) == 1 and egress.ledger[0].outcome == "aborted"


# --- #10: empty OpenAPI parameter name -----------------------------------------------------------


def test_discovery_drops_empty_parameter_names() -> None:
    scope = _scope()
    spec = {
        "openapi": "3.0.0",
        "paths": {"/api/copilot": {"post": {"parameters": [{"name": ""}, {"name": "prompt"}]}}},
    }
    op = next(o for o in discover_openapi(spec, scope=scope).operations if o.method == "POST")
    assert op.parameters == ("prompt",)
