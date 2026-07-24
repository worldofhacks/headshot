"""RED tests for WP-16D governed egress for active scanners.

Every physical request an active scanner issues must cross a governed seam that mints a FRESH
per-request permit, re-checks the abort flag and the caps/scope BEFORE the physical send, and
records a ledger entry AFTER it — preserving scanner<->permit<->send<->ledger parity. If parity
cannot be proven, active scanning is disabled (fail closed).

Offline: the "physical send" is an injected callable that records calls; no socket is opened.
"""

from __future__ import annotations

import pytest

from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanAuthorizationError,
    ActiveScanCaps,
    ActiveScanScope,
)
from agentforge.security_tools.scan_egress import (
    GovernedScanEgress,
    ScanEgressAbort,
)


def _scope(*, max_requests: int = 100, rps: float = 50.0) -> ActiveScanScope:
    return ActiveScanScope(
        origin="https://copilot.example-hospital.test",
        http_methods=("GET", "POST"),
        path_patterns=("/api/copilot", "/api/copilot/*"),
        principals=("synthetic-clinician-a",),
        image_sha256="a" * 64,
        addon_sha256s=("b" * 64,),
        rule_sha256s=("c" * 64,),
        callback_domains=("oast-abc.agentforge.internal",),
        caps=ActiveScanCaps.parse(
            max_requests=max_requests,
            requests_per_second=rps,
            max_duration_seconds=600.0,
            max_findings=200,
        ),
        scope_nonce="nonce-0123456789ab",
    )


def _grant(scope: ActiveScanScope, *, deadline: float = 1000.0) -> ActiveScanAuthorization:
    return ActiveScanAuthorization(
        operation_hash=scope.operation_hash(), scope_nonce=scope.scope_nonce, deadline=deadline
    )


def _egress(scope: ActiveScanScope, **over) -> GovernedScanEgress:
    kwargs = {"authorization": _grant(scope), "now": 1.0}
    kwargs.update(over)
    return GovernedScanEgress(scope, **kwargs)


class _Sender:
    def __init__(self, *, raises: bool = False) -> None:
        self.calls: list[str] = []
        self.raises = raises

    def __call__(self, permit) -> str:
        self.calls.append(permit.permit_id)
        if self.raises:
            raise RuntimeError("target unreachable")
        return "ok"


def test_egress_requires_a_verified_grant_at_construction() -> None:
    scope = _scope()
    with pytest.raises(ActiveScanAuthorizationError, match="no active-scan authorization"):
        GovernedScanEgress(scope, authorization=None, now=1.0)
    wrong = ActiveScanAuthorization(
        operation_hash="0" * 64, scope_nonce=scope.scope_nonce, deadline=1000.0
    )
    with pytest.raises(ActiveScanAuthorizationError, match="SCOPE"):
        GovernedScanEgress(scope, authorization=wrong, now=1.0)


def test_each_send_mints_a_fresh_permit_and_records_one_ledger_entry() -> None:
    scope = _scope()
    egress = _egress(scope)
    sender = _Sender()
    for i in range(3):
        assert egress.send(method="GET", path="/api/copilot", dispatch=sender, now=1.0 + i) == "ok"
    assert len(egress.permits) == 3
    assert len(egress.ledger) == 3
    permit_ids = {p.permit_id for p in egress.permits}
    assert len(permit_ids) == 3, "each request gets a distinct content-addressed permit"
    assert all(len(p.permit_id) == 64 for p in egress.permits)
    assert {e.outcome for e in egress.ledger} == {"returned"}
    egress.assert_parity()  # scanner<->permit<->send<->ledger 1:1


def test_request_cap_hard_aborts_before_the_over_limit_send() -> None:
    scope = _scope(max_requests=2)
    egress = _egress(scope)
    sender = _Sender()
    egress.send(method="GET", path="/api/copilot", dispatch=sender, now=1.0)
    egress.send(method="GET", path="/api/copilot", dispatch=sender, now=2.0)
    with pytest.raises(ScanEgressAbort, match="request cap"):
        egress.send(method="GET", path="/api/copilot", dispatch=sender, now=3.0)
    assert len(sender.calls) == 2, "the over-limit send never reached dispatch"
    assert len(egress.ledger) == 2
    egress.assert_parity()


def test_rate_cap_hard_aborts_when_sends_are_too_close() -> None:
    scope = _scope(rps=1.0)  # min interval 1.0s
    egress = _egress(scope)
    sender = _Sender()
    egress.send(method="GET", path="/api/copilot", dispatch=sender, now=10.0)
    with pytest.raises(ScanEgressAbort, match="rate"):
        egress.send(method="GET", path="/api/copilot", dispatch=sender, now=10.5)
    assert len(sender.calls) == 1


def test_abort_is_rechecked_before_every_physical_send() -> None:
    scope = _scope()
    flag = {"aborted": False}
    egress = _egress(scope, abort_check=lambda: flag["aborted"])
    sender = _Sender()
    egress.send(method="GET", path="/api/copilot", dispatch=sender, now=1.0)
    flag["aborted"] = True
    with pytest.raises(ScanEgressAbort, match="abort"):
        egress.send(method="GET", path="/api/copilot", dispatch=sender, now=2.0)
    assert len(sender.calls) == 1, "no physical send after abort"


def test_method_outside_scope_is_denied_before_dispatch() -> None:
    scope = _scope()
    egress = _egress(scope)
    sender = _Sender()
    with pytest.raises(ScanEgressAbort, match="method"):
        egress.send(method="DELETE", path="/api/copilot", dispatch=sender, now=1.0)
    assert sender.calls == []


def test_path_outside_scope_is_denied_before_dispatch() -> None:
    scope = _scope()
    egress = _egress(scope)
    sender = _Sender()
    with pytest.raises(ScanEgressAbort, match="path"):
        egress.send(method="GET", path="/admin/secrets", dispatch=sender, now=1.0)
    assert sender.calls == []


def test_a_failed_dispatch_still_records_a_ledger_entry_and_counts() -> None:
    scope = _scope()
    egress = _egress(scope)
    sender = _Sender(raises=True)
    with pytest.raises(RuntimeError, match="target unreachable"):
        egress.send(method="GET", path="/api/copilot", dispatch=sender, now=1.0)
    assert len(egress.ledger) == 1
    assert egress.ledger[0].outcome == "raised"
    egress.assert_parity()


def test_parity_breaks_when_a_permit_is_reserved_without_a_reported_send() -> None:
    scope = _scope()
    egress = _egress(scope)
    # Reserve a permit (pre_physical_send_gate) but never report the send: a scanner that egressed
    # without recording. Parity MUST detect it and fail closed.
    egress.reserve_permit(method="GET", path="/api/copilot", now=1.0)
    with pytest.raises(ScanEgressAbort, match="parity"):
        egress.assert_parity()


def test_reporting_a_send_for_an_unknown_permit_is_rejected() -> None:
    scope = _scope()
    egress = _egress(scope)

    class _Fake:
        permit_id = "z" * 64
        request_index = 1
        method = "GET"
        path = "/api/copilot"

    with pytest.raises(ScanEgressAbort, match="parity|no matching permit"):
        egress.report_send(_Fake(), "returned")
