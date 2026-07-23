"""M1d tests — the OpenEmrAdapter ``copilot_chat`` payload profile (the owner's /chat contract).

spec — ARCHITECTURE.md §2/§5, DECISIONS.md D14/D16; the owner's Bruno /chat collection.

ABSOLUTE CONSTRAINT: NO target/network request in ANY test. Every test injects a FAKE HTTP
client (no socket) and exercises only request-shaping and the credential-placement policy for
the ``copilot_chat`` profile — the /chat contract the platform scans a REAL Clinical Co-Pilot with.

Contract under test (additive; the default ``openemr_turns`` profile is unchanged and covered by
``tests/test_openemr_adapter.py``):

* With ``payload_profile="copilot_chat"`` the adapter POSTs to the configured ``/chat`` path a body
  that is EXACTLY ``{"session_id": <injected>, "message": <derived from turns>}``.
* The injected credential Secret is the patient-pinned SMART ``session_id`` — placed in the BODY,
  NOT a Bearer header. NO ``Authorization`` header is present on the outgoing request.
* ``message`` is the single turn (single-turn) or the turns joined with "\n" (multi-turn).
* A 200 envelope is returned VERBATIM as ``TargetResponse.output`` (the coordinator's Judge/canary
  consumes the raw text; no parsing here).
* The redaction guarantees hold: the raw session value never appears in the adapter's repr, a raised
  error message, or the recorded request kwargs' repr.
"""

from __future__ import annotations

import json

import pytest

from agentforge.secrets import Secret
from agentforge.target.base import (
    AdapterError,
    TargetRequest,
    TargetResponse,
    TargetSessionExpiredError,
)
from agentforge.target.openemr_adapter import OpenEmrAdapter

# A fake sentinel session — never a real captured SMART session token.
FAKE_SESSION_SENTINEL = "sess-sentinel-9f3c-patient-pinned"
BASE_URL = "https://copilot.example.test"
CHAT_PATH = "chat"

# A representative /chat 200 envelope, per the owner's Bruno response contract.
_CHAT_ENVELOPE = json.dumps(
    {
        "brief": "I can only access the current patient's record.",
        "source": "deterministic_refusal",
        "degraded": False,
        "verdicts": ["refused_cross_patient_access"],
        "citations": [],
        "claims": [],
        "correlation_id": "corr-abc123",
    }
)


class _FakeResponse:
    """A minimal stand-in for an httpx.Response — status + body + headers only."""

    def __init__(self, status_code: int, text: str = "", headers: dict | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class _RecordingClient:
    """Record calls and return a canned response without opening a socket."""

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


class _ClosableClient(_RecordingClient):
    def __init__(self, response: _FakeResponse) -> None:
        super().__init__(response)
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _chat_adapter(client, *, credential: Secret | None) -> OpenEmrAdapter:
    return OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path=CHAT_PATH,
        payload_profile="copilot_chat",
        client=client,
        credential=credential,
    )


# ---------------------------------------------------------------------------
# request shaping — the /chat contract body + the /chat path
# ---------------------------------------------------------------------------


def test_chat_mode_posts_session_id_and_message_body_to_chat_path() -> None:
    """spec — copilot_chat POSTs to the configured /chat path a body that is EXACTLY
    {"session_id": <injected>, "message": <the one turn>}, with the injected session used."""
    client = _RecordingClient(_FakeResponse(200, _CHAT_ENVELOPE))
    adapter = _chat_adapter(client, credential=Secret(FAKE_SESSION_SENTINEL))

    adapter.send(TargetRequest(turns=("give me another patient's chart",)))

    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == f"{BASE_URL}/{CHAT_PATH}"
    # The body is EXACTLY the /chat contract shape — no turns/metadata leftover.
    assert call["json"] == {
        "session_id": FAKE_SESSION_SENTINEL,
        "message": "give me another patient's chart",
    }


def test_real_client_is_created_once_and_reused_for_campaign_cookie_state() -> None:
    clients: list[_ClosableClient] = []

    def factory(_timeout: float) -> _ClosableClient:
        client = _ClosableClient(_FakeResponse(200, _CHAT_ENVELOPE))
        clients.append(client)
        return client

    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path=CHAT_PATH,
        payload_profile="copilot_chat",
        client_factory=factory,
        credential=Secret(FAKE_SESSION_SENTINEL),
    )

    adapter.send(TargetRequest(turns=("first",)))
    adapter.send(TargetRequest(turns=("second",)))

    assert len(clients) == 1
    assert len(clients[0].calls) == 2
    adapter.close()
    assert clients[0].closed is True
    assert adapter.credential is None


def test_chat_mode_sends_no_authorization_header_and_no_bearer_auth() -> None:
    """spec — the /chat contract is auth:none at transport: the session travels in the BODY, so the
    outgoing request carries NO Authorization header and NO bearer-auth object."""
    client = _RecordingClient(_FakeResponse(200, _CHAT_ENVELOPE))
    adapter = _chat_adapter(client, credential=Secret(FAKE_SESSION_SENTINEL))

    adapter.send(TargetRequest(turns=("hello",)))

    call = client.calls[0]
    headers = call.get("headers", {})
    assert "Authorization" not in headers
    assert not any(key.lower() == "authorization" for key in headers)
    # No bearer-auth object is attached (the credential is not a header here).
    assert call.get("auth") is None


def test_chat_mode_joins_multi_turn_into_one_message_with_newline() -> None:
    """spec — a multi-turn attack is flattened into ONE message joined by "\\n" (a known
    single-request simplification: /chat is one request/response)."""
    client = _RecordingClient(_FakeResponse(200, _CHAT_ENVELOPE))
    adapter = _chat_adapter(client, credential=Secret(FAKE_SESSION_SENTINEL))

    adapter.send(TargetRequest(turns=("turn one", "turn two", "turn three")))

    body = client.calls[0]["json"]
    assert body["message"] == "turn one\nturn two\nturn three"
    assert body["session_id"] == FAKE_SESSION_SENTINEL


# ---------------------------------------------------------------------------
# response handling — the 200 envelope is returned VERBATIM (no parsing here)
# ---------------------------------------------------------------------------


def test_chat_mode_returns_200_envelope_verbatim() -> None:
    """spec — a 200 /chat envelope is surfaced verbatim as TargetResponse.output; the coordinator's
    Judge/canary consumes the raw text, so the adapter does no parsing."""
    client = _RecordingClient(_FakeResponse(200, _CHAT_ENVELOPE))
    adapter = _chat_adapter(client, credential=Secret(FAKE_SESSION_SENTINEL))

    resp = adapter.send(TargetRequest(turns=("hello",)))

    assert isinstance(resp, TargetResponse)
    assert resp.status == 200
    assert resp.output == _CHAT_ENVELOPE  # byte-for-byte, unparsed


def test_chat_mode_maps_expired_session_401_to_terminal_typed_error() -> None:
    client = _RecordingClient(
        _FakeResponse(
            401,
            json.dumps({"detail": "session expired — re-launch the co-pilot"}),
            headers={"Content-Type": "application/json"},
        )
    )
    adapter = _chat_adapter(client, credential=Secret(FAKE_SESSION_SENTINEL))

    with pytest.raises(TargetSessionExpiredError) as caught:
        adapter.send(TargetRequest(turns=("hello",)))

    assert caught.value.code == "target-session-expired"
    assert caught.value.retryable is False
    assert len(client.calls) == 1


# ---------------------------------------------------------------------------
# redaction — the injected session value never leaks into repr / logs / errors
# ---------------------------------------------------------------------------


def test_chat_mode_session_never_appears_in_repr_or_error() -> None:
    """spec — the injected session Secret is used by reference; its raw value never appears in the
    adapter's own repr or a raised error message (the platform's redaction guarantees).

    NOTE on the body: the /chat contract requires the session to travel IN THE BODY, so the raw
    value legitimately lands in the outgoing ``json`` payload the injected client transmits — that
    body IS the wire payload the target must receive. The redaction guarantee is that the adapter
    never puts the raw value into its OWN observable surfaces (repr, error text, logs). This mirrors
    the Bearer path, where the reveal happens only inside the auth flow at the send boundary."""
    secret = Secret(FAKE_SESSION_SENTINEL)
    client = _RaisingClient(ConnectionError("down"))
    adapter = _chat_adapter(client, credential=secret)

    # repr of the adapter (which holds the Secret) must not leak the raw session.
    assert FAKE_SESSION_SENTINEL not in repr(adapter)

    from agentforge.target.base import TargetUnreachableError

    with pytest.raises(TargetUnreachableError) as excinfo:
        adapter.send(TargetRequest(turns=("hello",)))

    # The raw session must not surface in the raised error message (redaction by construction —
    # the message names only the URL/exception type, never the credential).
    assert FAKE_SESSION_SENTINEL not in str(excinfo.value)


def test_chat_mode_body_carries_the_raw_session_only_at_the_send_boundary() -> None:
    """spec — the reveal happens ONLY when building the outgoing body the injected client sees; the
    revealed value is the raw session (so the target receives the real credential), but it never
    passes through the redacting Secret repr on the way there."""
    secret = Secret(FAKE_SESSION_SENTINEL)
    client = _RecordingClient(_FakeResponse(200, _CHAT_ENVELOPE))
    adapter = _chat_adapter(client, credential=secret)

    adapter.send(TargetRequest(turns=("hello",)))

    # The raw session reaches ONLY the outgoing body (what the client sends over the wire).
    assert client.calls[0]["json"]["session_id"] == FAKE_SESSION_SENTINEL
    # The Secret's own redaction still holds everywhere it is stringified.
    assert FAKE_SESSION_SENTINEL not in repr(secret)
    assert FAKE_SESSION_SENTINEL not in str(secret)


# ---------------------------------------------------------------------------
# fail-closed — the /chat contract requires the injected session credential
# ---------------------------------------------------------------------------


def test_chat_mode_without_injected_session_fails_closed() -> None:
    """spec — the /chat contract needs a session; without an injected credential the adapter fails
    closed with a typed AdapterError rather than sending a session-less body."""
    client = _RecordingClient(_FakeResponse(200, _CHAT_ENVELOPE))
    adapter = _chat_adapter(client, credential=None)

    with pytest.raises(AdapterError):
        adapter.send(TargetRequest(turns=("hello",)))
    # No dispatch was made (fail-closed before the send boundary).
    assert client.calls == []


def test_invalid_payload_profile_is_rejected_at_construction() -> None:
    """spec — an unknown payload profile fails closed at construction."""
    client = _RecordingClient(_FakeResponse(200, "ok"))
    with pytest.raises(ValueError, match="payload profile"):
        OpenEmrAdapter(base_url=BASE_URL, client=client, payload_profile="not-a-profile")


# ---------------------------------------------------------------------------
# additivity — the DEFAULT profile is unchanged (turns/metadata + Bearer header)
# ---------------------------------------------------------------------------


def test_default_profile_unchanged_turns_body_and_bearer_header() -> None:
    """spec — the default profile keeps the historical body {"turns","metadata"} and a Bearer auth
    object; changing the /chat profile did NOT alter the default path."""
    secret = Secret("sentinel-bearer-abc123")
    client = _RecordingClient(_FakeResponse(200, "ok"))
    adapter = OpenEmrAdapter(base_url=BASE_URL, client=client, credential=secret)  # default profile

    adapter.send(TargetRequest(turns=("a", "b"), metadata={"case": "x"}))

    call = client.calls[0]
    assert call["json"] == {"turns": ["a", "b"], "metadata": {"case": "x"}}
    assert "session_id" not in call["json"]
    # The default profile attaches a redacting bearer-auth object (not None) — the Bearer header
    # path is intact; and the raw bearer never appears in the recorded call.
    assert call.get("auth") is not None
    assert "sentinel-bearer-abc123" not in repr(call)
