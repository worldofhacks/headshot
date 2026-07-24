"""End-to-end (offline) composition of the active-scan chain — the WP-21D dry run.

This drives the whole active-scan subsystem exactly as the private Runner would, but with an
injected sender instead of a socket, proving the modules compose into one governed flow:

    grant -> preflight -> discover surface -> auth matrix -> per-attempt OAST -> governed egress
    (permit/ledger parity) -> OAST-correlated SSRF -> pinned active command -> per-tool evidence

No network is touched (socket patched to raise). A live run only swaps the injected sender for the
real Runner egress under the same grant.
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
from agentforge.security_tools.api_discovery import discover_openapi
from agentforge.security_tools.auth_matrix import build_auth_matrix
from agentforge.security_tools.oast import PrivateOastRegistry
from agentforge.security_tools.scan_egress import GovernedScanEgress
from agentforge.security_tools.tool_runtime import ToolExecutionEvidence
from agentforge.security_tools.zap_profiles import (
    ACTIVE_ZAP_IMAGE_SHA256,
    active_scan_argv,
    active_scan_rule_subset_sha256,
)

APPROVED = "https://copilot.example-hospital.test"


def _scope() -> ActiveScanScope:
    return ActiveScanScope(
        origin=APPROVED,
        http_methods=("GET", "POST"),
        path_patterns=("/api/copilot", "/api/copilot/*"),
        principals=("synthetic-anon", "synthetic-clinician-a"),
        image_sha256=ACTIVE_ZAP_IMAGE_SHA256,
        addon_sha256s=("b" * 64,),
        rule_sha256s=(active_scan_rule_subset_sha256(),),
        callback_domains=("oast.agentforge.internal",),
        caps=ActiveScanCaps.parse(
            max_requests=50, requests_per_second=10.0, max_duration_seconds=600.0, max_findings=200
        ),
        scope_nonce="nonce-0123456789ab",
    )


def _spec() -> dict:
    return {
        "openapi": "3.0.0",
        "paths": {
            "/api/copilot": {"post": {"parameters": [{"name": "prompt"}]}},
            "/api/copilot/history": {"get": {"parameters": [{"name": "since"}]}},
        },
    }


def test_active_scan_chain_composes_offline_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        socket, "socket", lambda *a, **k: (_ for _ in ()).throw(AssertionError("net"))
    )

    scope = _scope()
    grant = ActiveScanAuthorization(
        operation_hash=scope.operation_hash(), scope_nonce=scope.scope_nonce, deadline=10_000.0
    )
    entries = [
        ("synthetic-anon", "none", None),
        ("synthetic-clinician-a", "bearer", "secretref://staging/clinician-a"),
    ]

    # 1) Zero-call preflight proves readiness.
    pre = active_scan_preflight(
        scope,
        grant,
        approved_origin=APPROVED,
        openapi_spec=_spec(),
        auth_matrix_entries=entries,
        now=1.0,
    )
    assert pre.ok, [c for c in pre.checks if not c.passed]

    # 2) Discover the in-scope surface + 3) the authenticated matrix.
    api = discover_openapi(_spec(), scope=scope)
    assert len(api.operations) == 2
    matrix = build_auth_matrix(entries, scope=scope)
    assert len(matrix.cells) == 2

    # 4) The pinned active command that WOULD run in the Runner is constructible under the grant.
    argv = active_scan_argv(
        scope,
        grant,
        approved_origin=APPROVED,
        openapi_spec_url=f"{APPROVED}/api/openapi.json",
        report_path="/r/active.json",
        now=1.0,
    )
    assert "zap-api-scan.py" in argv and "zap-baseline.py" not in argv

    # 5) Drive governed egress over the discovered surface; every send crosses a fresh permit.
    oast = PrivateOastRegistry(scope)
    egress = GovernedScanEgress(scope, authorization=grant, now=0.0)
    sent = []
    now = 1.0
    for i, op in enumerate(api.operations):
        token = oast.mint(f"attempt-{i}")

        def _dispatch(permit, _token=token, _op=op):
            sent.append((permit.method, permit.path))
            # The first attempt coerces an SSRF that reaches our private OAST (blind proof).
            if _op.path == "/api/copilot":
                oast.observe_callback(f"{_token.callback_url}?src={_op.path}")
            return "200"

        egress.send(method=op.method, path=op.path, dispatch=_dispatch, now=now)
        now += 1.0

    # 6) Parity holds: scanner <-> permit <-> send <-> ledger is 1:1.
    egress.assert_parity()
    assert len(egress.permits) == len(egress.ledger) == len(api.operations)
    assert {e.outcome for e in egress.ledger} == {"returned"}

    # 7) The SSRF attempt is out-of-band confirmed.
    assert oast.confirmed_attempts() == ("attempt-0",)

    # 8) Emit per-tool execution evidence — the Tools page now shows real state, not zeros.
    evidence = ToolExecutionEvidence.evidenced(
        tool_id="zap",
        run_id="active-run-1",
        executed_attempt_count=len(egress.ledger),
        evidenced_finding_count=len(oast.confirmed_attempts()),
        last_executed_at="2026-07-24T12:00:00Z",
        evidence_uri="postgres://tool_findings?tool=zap&run=active-run-1",
    )
    fields = evidence.to_tool_scope_fields()
    assert fields["runtime_state"] == "evidenced"
    assert fields["executed_attempt_count"] == 2
    assert fields["evidenced_finding_count"] == 1
