"""RED tests for the real bounded HTTPS sender wired into GovernedScanEgress.

This is the ONLY thing that turns a governed active scan from constructed-command into a real
physical send. Every fail-closed gate is tested with an INJECTED resolver + connection opener, so
no socket is ever opened in tests:

* default-disabled (AGENTFORGE_ACTIVE_SCAN_ENABLED) — off => refuse, never open a connection;
* exact-origin + deny-list at physical-send time (defense in depth over the egress/scope gates);
* DNS resolved and every resolved IP validated against private/loopback/link-local/metadata, then
  the connection is PINNED to a validated IP (DNS-rebinding defense);
* redirects DENIED (never chased to another origin);
* bounded response; and
* the SID is injected on the wire but NEVER surfaced in the outcome (Secret redaction).
"""

from __future__ import annotations

import dataclasses

import pytest

from agentforge.secrets import Secret
from agentforge.security_tools.active_authorization import ActiveScanCaps, ActiveScanScope
from agentforge.security_tools.scan_egress import ScanPermit
from agentforge.security_tools.scan_sender import (
    ACTIVE_SCAN_ENABLED_ENV,
    ActiveScanSendError,
    BoundedHttpsSender,
)

ORIGIN = "https://copilot.example-hospital.test"
ENABLED = {ACTIVE_SCAN_ENABLED_ENV: "1"}


def _scope() -> ActiveScanScope:
    return ActiveScanScope(
        origin=ORIGIN,
        http_methods=("GET", "POST"),
        path_patterns=("/api/copilot", "/api/copilot/*"),
        principals=("synthetic-clinician-a",),
        image_sha256="a" * 64,
        addon_sha256s=("b" * 64,),
        rule_sha256s=("c" * 64,),
        callback_domains=(),
        caps=ActiveScanCaps.parse(
            max_requests=50, requests_per_second=5.0, max_duration_seconds=600.0, max_findings=200
        ),
        scope_nonce="nonce-0123456789ab",
    )


def _permit(method: str = "GET", path: str = "/api/copilot") -> ScanPermit:
    return ScanPermit(permit_id="p" * 64, request_index=1, method=method, path=path)


class _FakeResp:
    def __init__(self, *, status: int = 200, body: bytes = b"ok", location: str | None = None):
        self.status = status
        self._body = body
        self._location = location

    def getheader(self, name: str, default=None):
        if name.lower() == "location":
            return self._location
        return default

    def read(self, amt: int | None = None) -> bytes:
        return self._body if amt is None else self._body[:amt]


class _FakeConn:
    def __init__(self, resp: _FakeResp):
        self._resp = resp
        self.requests: list[tuple] = []
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.requests.append((method, path, dict(headers or {})))

    def getresponse(self):
        return self._resp

    def close(self):
        self.closed = True


class _Opener:
    def __init__(self, resp: _FakeResp):
        self._resp = resp
        self.calls: list[tuple] = []
        self.conns: list[_FakeConn] = []

    def __call__(self, ip, port, host):
        self.calls.append((ip, port, host))
        conn = _FakeConn(self._resp)
        self.conns.append(conn)
        return conn


def _sender(scope=None, *, env=ENABLED, resolver=None, opener=None, **over) -> BoundedHttpsSender:
    return BoundedHttpsSender(
        scope or _scope(),
        env=env,
        host_resolver=resolver or (lambda host: ["8.8.8.8"]),  # TEST-NET public
        connection_opener=opener or _Opener(_FakeResp()),
        **over,
    )


def test_sender_refuses_when_active_scanning_is_disabled() -> None:
    opener = _Opener(_FakeResp())
    sender = _sender(env={}, opener=opener)
    with pytest.raises(ActiveScanSendError, match="disabled"):
        sender(_permit())
    assert opener.calls == [], "no connection opened while disabled"


@pytest.mark.parametrize(
    "ip", ["10.0.0.5", "127.0.0.1", "192.168.1.9", "169.254.169.254", "168.63.129.16"]
)
def test_sender_rejects_a_host_resolving_to_private_or_metadata(ip: str) -> None:
    opener = _Opener(_FakeResp())
    sender = _sender(resolver=lambda host: [ip], opener=opener)
    with pytest.raises(ActiveScanSendError, match="private|internal|metadata|link-local"):
        sender(_permit())
    assert opener.calls == [], "no connection opened to a blocked address"


def test_sender_rejects_mixed_public_and_private_resolution() -> None:
    opener = _Opener(_FakeResp())
    sender = _sender(resolver=lambda host: ["8.8.8.8", "10.0.0.5"], opener=opener)
    with pytest.raises(ActiveScanSendError):
        sender(_permit())
    assert opener.calls == [], "any private answer poisons the whole resolution (rebinding defense)"


def test_sender_pins_the_validated_ip_and_sends_the_permit() -> None:
    opener = _Opener(_FakeResp(status=200, body=b"hello"))
    sender = _sender(resolver=lambda host: ["8.8.8.8"], opener=opener)
    outcome = sender(_permit(method="POST", path="/api/copilot"))
    assert opener.calls == [("8.8.8.8", 443, "copilot.example-hospital.test")]
    assert outcome.status_code == 200
    assert outcome.pinned_ip == "8.8.8.8"
    assert outcome.redirected is False
    method, path, _headers = opener.conns[0].requests[0]
    assert method == "POST" and path.startswith("/api/copilot")
    assert opener.conns[0].closed is True


def test_sender_denies_redirects() -> None:
    opener = _Opener(_FakeResp(status=302, location="https://evil.example.test/"))
    sender = _sender(opener=opener)
    outcome = sender(_permit())
    assert outcome.status_code == 302
    assert outcome.redirected is True
    assert len(opener.calls) == 1, "a redirect is terminal — never chased to another origin"


def test_sender_injects_the_sid_on_the_wire_but_never_surfaces_it() -> None:
    opener = _Opener(_FakeResp())
    secret_value = "SID=synthetic-session-abc123"
    sender = _sender(
        opener=opener,
        credential_ref="secretref://staging/copilot-clinician-a",
        credential_resolver=lambda ref: Secret(secret_value),
        auth_header="Cookie",
    )
    outcome = sender(_permit())
    # Injected into the actual request headers (the wire)...
    _m, _p, headers = opener.conns[0].requests[0]
    assert headers.get("Cookie") == secret_value
    # ...but never in the evidence outcome / its repr.
    assert secret_value not in repr(outcome)
    assert not any(
        secret_value in str(getattr(outcome, f.name)) for f in dataclasses.fields(outcome)
    )


def test_sender_bounds_the_response_body() -> None:
    opener = _Opener(_FakeResp(body=b"A" * 10_000))
    sender = _sender(opener=opener, max_response_bytes=1024)
    outcome = sender(_permit())
    assert outcome.bytes_read == 1024


def test_sender_rejects_an_off_scope_path() -> None:
    opener = _Opener(_FakeResp())
    sender = _sender(opener=opener)
    with pytest.raises(ActiveScanSendError, match="scope"):
        sender(_permit(path="/admin/secrets"))
    assert opener.calls == []


def test_sender_reports_a_reflected_synthetic_canary() -> None:
    opener = _Opener(_FakeResp(body=b"echo: af-probe-XYZ done"))
    sender = _sender(opener=opener, canary="af-probe-XYZ")
    outcome = sender(_permit())
    assert outcome.canary_reflected is True
    _m, path, _h = opener.conns[0].requests[0]
    assert "af-probe-XYZ" in path
