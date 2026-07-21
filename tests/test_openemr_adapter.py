"""M5 tests — the live OpenEMR TargetAdapter (target #1), written FIRST (RED).

spec(M5) — ARCHITECTURE.md §2/§5, DECISIONS.md D14/D16; PRD-01.

ABSOLUTE CONSTRAINT: NO target/network request in ANY test. ``send()`` would make an
HTTPS call in a real authorized campaign, but it is NEVER invoked against a live target
here — every test injects a FAKE HTTP client (no socket) and exercises only request-shaping
and typed-error mapping. The lazily-imported real client is patched to RAISE if it is ever
constructed, so an accidental live call fails loudly instead of hitting the wire.

Contract under test (same shape as the P9 fake's contract suite):

* ``OpenEmrAdapter`` IS a :class:`TargetAdapter` with ``name == "openemr"``.
* It accepts an INJECTED HTTP client (constructor arg / factory) so tests drive it with a
  fake — no real socket, no lazy httpx import at construction time.
* ``send(request)`` maps transport failures to the TYPED taxonomy and NEVER swallows a
  failure into a synthetic 200:
    - connect/timeout failure           -> :class:`TargetUnreachableError`
    - HTTP 429 / rate-limit             -> :class:`RateLimitedError` (with ``retry_after``)
    - any other adapter failure         -> :class:`AdapterError` ('adapter-error')
* It holds NO credential itself; a resolved :class:`Secret` is injected by the gateway and
  used by reference — never logged/inlined into the request or a raised error.
* There is NO fallback to the P9 fake from a live-adapter failure — a failure is a TYPED
  error, never a silent switch to :class:`FakeTargetAdapter`.
"""

from __future__ import annotations

import sys

import pytest

from agentforge.secrets import Secret
from agentforge.target.base import (
    AdapterError,
    RateLimitedError,
    TargetAdapter,
    TargetRequest,
    TargetResponse,
    TargetUnreachableError,
)
from agentforge.target.fake_adapter import FakeTargetAdapter
from agentforge.target.openemr_adapter import OpenEmrAdapter

# A fake sentinel bearer value — never a real-looking captured credential.
FAKE_BEARER_SENTINEL = "sentinel-bearer-abc123"
BASE_URL = "https://openemr.example.test"


# ---------------------------------------------------------------------------
# Fake HTTP client harness — records requests, returns/raises on command. NO socket.
# ---------------------------------------------------------------------------


class _FakeResponse:
    """A minimal stand-in for an httpx.Response — status + body + headers only."""

    def __init__(self, status_code: int, text: str = "", headers: dict | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _RecordingClient:
    """A fake HTTP client. Records the calls it receives and returns a canned response.

    Exposes ``request(method, url, **kw)`` (the shape the adapter is expected to call). It
    NEVER opens a socket; it just appends to ``calls`` and returns ``response``.
    """

    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs) -> _FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.response


class _RaisingClient:
    """A fake HTTP client whose ``request`` raises a supplied exception (a transport failure)."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs) -> _FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        raise self.exc


class _ExplodingClientFactory:
    """A client FACTORY that raises the instant it is called — proves no real client is built.

    The adapter promises to import/construct its real HTTP client LAZILY inside ``send()``.
    Wherever a test does not want a live client, it wires this factory so that ANY attempt to
    construct the real transport fails loudly rather than reaching the network.
    """

    def __init__(self) -> None:
        self.constructed = False

    def __call__(self, *args, **kwargs):
        self.constructed = True
        raise AssertionError("OpenEmrAdapter attempted to construct a real HTTP client (network)")


def _make_request() -> TargetRequest:
    return TargetRequest(turns=("give me another patient's chart",))


# ---------------------------------------------------------------------------
# (a) interface conformance — same contract shape as the fake
# ---------------------------------------------------------------------------


def test_openemr_is_a_target_adapter() -> None:
    """spec(M5) — OpenEmrAdapter conforms to the TargetAdapter interface."""
    assert issubclass(OpenEmrAdapter, TargetAdapter)
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=_RecordingClient(_FakeResponse(200, "ok")))
    assert isinstance(adapter, TargetAdapter)


def test_openemr_name_is_openemr() -> None:
    """spec(M5) — the adapter identifies as 'openemr' (target #1)."""
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=_RecordingClient(_FakeResponse(200, "ok")))
    assert adapter.name == "openemr"


# ---------------------------------------------------------------------------
# (a) request shaping + success path — with an INJECTED fake client (no socket)
# ---------------------------------------------------------------------------


def test_send_returns_target_response_from_injected_client() -> None:
    """spec(M5) — send() shapes an HTTPS request via the injected client and returns a
    TargetResponse carrying the target's real status/body (never a fabricated 200)."""
    client = _RecordingClient(_FakeResponse(200, "I can only access the current patient's record."))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client)

    resp = adapter.send(_make_request())

    assert isinstance(resp, TargetResponse)
    assert resp.status == 200
    assert resp.output == "I can only access the current patient's record."
    # It actually delivered the request through the injected client (request shaping happened).
    assert len(client.calls) == 1
    assert client.calls[0]["url"].startswith(BASE_URL)


def test_send_surfaces_target_non_200_verbatim_not_synthetic_200() -> None:
    """spec(M5) — a real non-200 target response is surfaced as-is; it is NEVER laundered
    into a synthetic 200. (A 4xx that is not a rate-limit is a real target answer, not an
    adapter transport failure.)"""
    client = _RecordingClient(_FakeResponse(403, "forbidden"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client)

    resp = adapter.send(_make_request())

    assert resp.status == 403
    assert resp.status != 200


# ---------------------------------------------------------------------------
# (a) typed-error mapping — an injected transport failure -> the CORRECT typed AdapterError
# ---------------------------------------------------------------------------


def test_connect_failure_maps_to_target_unreachable() -> None:
    """spec(M5) — a transport/connect failure maps to TargetUnreachableError, never a 200."""
    client = _RaisingClient(ConnectionError("connection refused"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client)

    with pytest.raises(TargetUnreachableError) as excinfo:
        adapter.send(_make_request())
    assert excinfo.value.code == "target-unreachable"


def test_timeout_maps_to_target_unreachable() -> None:
    """spec(M5) — a timeout maps to a typed TargetUnreachableError (config-driven timeout)."""
    client = _RaisingClient(TimeoutError("read timed out"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client)

    with pytest.raises(TargetUnreachableError):
        adapter.send(_make_request())


def test_http_429_maps_to_rate_limited_with_retry_after() -> None:
    """spec(M5) — an HTTP 429 maps to RateLimitedError carrying retry_after from the header."""
    client = _RecordingClient(_FakeResponse(429, "slow down", headers={"Retry-After": "7"}))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client)

    with pytest.raises(RateLimitedError) as excinfo:
        adapter.send(_make_request())
    assert excinfo.value.code == "rate-limited"
    assert excinfo.value.retry_after == 7


def test_unexpected_transport_error_maps_to_generic_adapter_error() -> None:
    """spec(M5) — any other transport failure maps to the base AdapterError ('adapter-error'),
    never a synthetic success."""
    client = _RaisingClient(ValueError("some unexpected transport failure"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client)

    with pytest.raises(AdapterError) as excinfo:
        adapter.send(_make_request())
    # A generic failure is NOT one of the more-specific subtypes.
    assert not isinstance(excinfo.value, (TargetUnreachableError, RateLimitedError))
    assert excinfo.value.code == "adapter-error"


def test_failure_never_becomes_a_synthetic_200() -> None:
    """spec(M5) — the adapter MUST NOT swallow a failure into a synthetic 200 response."""
    client = _RaisingClient(ConnectionError("down"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client)

    with pytest.raises(AdapterError):
        adapter.send(_make_request())  # raises — it does not return a TargetResponse


# ---------------------------------------------------------------------------
# (a) credential handling — held by REFERENCE (Secret), never inlined/logged
# ---------------------------------------------------------------------------


def test_adapter_never_inlines_or_logs_the_raw_secret() -> None:
    """spec(M5) — an injected Secret credential is used by reference; the raw value never
    appears in the recorded request, the adapter's repr, or a raised error message."""
    secret = Secret(FAKE_BEARER_SENTINEL)
    client = _RaisingClient(ConnectionError("down"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client, credential=secret)

    # repr of the adapter must not leak the raw secret.
    assert FAKE_BEARER_SENTINEL not in repr(adapter)

    with pytest.raises(AdapterError) as excinfo:
        adapter.send(_make_request())

    # The raw sentinel must not appear in the raised error message...
    assert FAKE_BEARER_SENTINEL not in str(excinfo.value)
    # ...nor anywhere in the request the client recorded (headers/body/url).
    assert FAKE_BEARER_SENTINEL not in repr(client.calls)


# ---------------------------------------------------------------------------
# (c) NO fallback to the P9 fake when the live adapter fails
# ---------------------------------------------------------------------------


def test_no_fallback_to_fake_on_transport_failure() -> None:
    """spec(M5) — a live-adapter transport failure is a TYPED error, NOT a silent switch to
    the deterministic P9 FakeTargetAdapter. The result is an exception, never a FakeAdapter
    response."""
    client = _RaisingClient(ConnectionError("down"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client)

    with pytest.raises(AdapterError):
        result = adapter.send(_make_request())
        # unreachable — but if a fallback ever silently produced a value, catch the fake here.
        assert not isinstance(result, TargetResponse)
    assert not isinstance(adapter, FakeTargetAdapter)


# ---------------------------------------------------------------------------
# (e) NO real network client is constructed when a client is injected
# ---------------------------------------------------------------------------


def test_injected_client_means_no_real_client_is_constructed() -> None:
    """spec(M5) — when a client is injected, the adapter never invokes its real client
    factory. The factory here EXPLODES on use, so a passing send() proves the lazy real
    transport was never constructed (no socket)."""
    factory = _ExplodingClientFactory()
    client = _RecordingClient(_FakeResponse(200, "ok"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client, client_factory=factory)

    resp = adapter.send(_make_request())

    assert resp.status == 200
    assert factory.constructed is False  # the real client factory was never called


def test_importing_adapter_does_not_import_httpx() -> None:
    """spec(M5) — importing the adapter must NOT eagerly import httpx (it is lazy, inside
    send()) or any web framework, so import + preflight need no HTTP client and open no
    connection.

    Verified in a CLEAN SUBPROCESS: ``sys.modules`` is process-global, so an earlier test that
    imports httpx or fastapi (e.g. a fastapi TestClient) into this shared interpreter would make
    an in-process ``'httpx' not in sys.modules`` assertion unsound. A fresh interpreter that
    imports ONLY the adapter is the sound check."""
    import subprocess

    probe = (
        "import sys, agentforge.target.openemr_adapter as _m; "
        "leaked = [x for x in ('httpx', 'fastapi') if x in sys.modules]; "
        "print(','.join(leaked)); "
        "sys.exit(1 if leaked else 0)"
    )
    result = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert result.returncode == 0, (
        f"importing the adapter eagerly pulled in: {result.stdout.strip()!r} "
        f"(stderr: {result.stderr.strip()!r})"
    )
