"""The live OpenEMR TargetAdapter (target #1) — API-primary, typed-error-mapping.

spec(M5) — ARCHITECTURE.md §2/§5, DECISIONS.md D14/D16; PRD-01.

This is the ONLY live-target adapter in this wave. It is reached EXCLUSIVELY through the
trusted Policy Gateway (``agentforge.policy.gateway``) — never directly by an agent. The Runner
injects one campaign-scoped :class:`Secret`; the adapter retains it only for that campaign, uses it
at the HTTPS call boundary, and clears it during close without logging it.

``send()`` would make a real HTTPS request in an *authorized* live campaign, but the transport
is fully injectable: a test drives it with a fake client (no socket), and the real client
(``httpx``) is imported LAZILY *inside* ``send()`` only when no client was injected — so a bare
``import agentforge.target.openemr_adapter`` (and the activation preflight) pull in no HTTP
client and open no connection.

Transport failures are mapped onto the typed taxonomy in ``agentforge.target.base`` — a
connect/timeout failure -> :class:`TargetUnreachableError`, an HTTP 429 -> :class:`RateLimitedError`
(carrying ``retry_after``), and an expired delegated /chat session ->
:class:`TargetSessionExpiredError`. A failure is NEVER swallowed into a synthetic 200, and there
is NO fallback to the P9 fake: retryable failures become backoff -> queue -> abort, while expired
human delegation aborts after the first request.

Framework-neutral (D10): imports base/secrets only — never a web framework, never httpx at
import time.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from agentforge.secrets import Secret
from agentforge.target.base import (
    AdapterError,
    RateLimitedError,
    TargetAdapter,
    TargetRequest,
    TargetResponse,
    TargetSessionExpiredError,
    TargetUnreachableError,
)

# Default per-request timeout (seconds) and retry/backoff base — config-driven, mapped to a
# typed error on breach. Kept here so import + preflight need no httpx; the values only reach
# the transport at the ``send()`` call boundary.
_DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_BACKOFF_SECONDS = 1.0

# The single API path the adapter POSTs an attack turn-sequence to. API-primary: the adapter
# talks to the target over its HTTP API, not a scraped UI.
_API_PATH = "apis/default/api/copilot/message"

# The two supported payload/credential-placement profiles (additive; the default is unchanged):
#
#   "openemr_turns" (DEFAULT) — the historical body ``{"turns", "metadata"}`` with the credential
#       carried in an ``Authorization: Bearer`` header (a bearer-auth target).
#   "copilot_chat"            — the owner's Bruno /chat contract: body ``{"session_id", "message"}``
#       with NO Authorization header. ``session_id`` is the injected credential Secret (a
#       patient-pinned SMART session, revealed only at the send boundary) placed in the BODY, not a
#       header. Each adapter send accepts exactly one conversational turn; the Policy Gateway
#       sequences a multi-turn attempt so every physical /chat request is separately gated.
_PROFILE_OPENEMR_TURNS = "openemr_turns"
_PROFILE_COPILOT_CHAT = "copilot_chat"
_PAYLOAD_PROFILES = frozenset({_PROFILE_OPENEMR_TURNS, _PROFILE_COPILOT_CHAT})


class _BearerAuth:
    """A redacting bearer-auth applier compatible with httpx's ``auth_flow`` protocol.

    The raw credential is held inside a :class:`Secret` and revealed ONLY inside
    :meth:`auth_flow` — the point httpx serializes the outgoing request over the wire. It is
    never inlined into a header string the caller records, and ``repr`` redacts, so logging the
    auth object (or a client's recorded kwargs) leaks nothing.
    """

    __slots__ = ("_secret",)

    def __init__(self, secret: Secret) -> None:
        self._secret = secret

    def auth_flow(self, request: Any) -> Any:
        """Attach ``Authorization: Bearer <token>`` at the httpx send boundary, then yield."""
        request.headers["Authorization"] = f"Bearer {self._secret.reveal()}"
        yield request

    def __repr__(self) -> str:
        # Redact — the wrapped Secret must never surface in a log/traceback/recorded kwarg.
        return f"_BearerAuth({self._secret!r})"


def _default_client_factory(timeout: float) -> Any:
    """Construct the real HTTP client — imported LAZILY so import/preflight need no httpx.

    This is the ONLY place ``httpx`` is imported. It is reached solely from ``send()`` when no
    client was injected (an authorized live campaign). Tests inject a fake client, so this
    factory is never called under test and no socket is opened.
    """
    import httpx  # lazy: never at module import time (D10) — no connection on import/preflight

    return httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        verify=True,
        trust_env=False,
    )


@dataclass
class OpenEmrAdapter(TargetAdapter):
    """Live OpenEMR adapter. ``name == "openemr"`` (target #1).

    The HTTP transport is fully injectable: pass ``client`` (any object exposing
    ``request(method, url, **kwargs)``) to drive it in tests with no socket; pass a
    ``client_factory`` to override how the real client is built. Only when NO ``client`` is
    injected does ``send()`` lazily build one via the factory (real network path).

    ``credential`` is a :class:`Secret` the gateway/coordinator injects by reference; the adapter
    reveals it ONLY at the outgoing-request boundary and never logs/inlines the raw value. WHERE it
    is placed depends on ``payload_profile``: the default ``openemr_turns`` profile carries it in an
    ``Authorization: Bearer`` header, while the ``copilot_chat`` profile (the owner's /chat
    contract) places the revealed session credential in the request BODY as ``session_id`` and
    sends NO Authorization header. Either way the dataclass ``repr`` renders the Secret redacted.
    """

    base_url: str = ""
    client: Any | None = None
    client_factory: Callable[[float], Any] = field(default=_default_client_factory)
    credential: Secret | None = None
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS
    method: str = "POST"
    relative_path: str = _API_PATH
    # Payload/credential-placement profile — selects how the body is shaped and where the credential
    # is placed. Defaults to the historical turns/Bearer profile (existing behavior byte-for-byte);
    # set to "copilot_chat" for the owner's /chat contract (session_id in the body, no auth header).
    payload_profile: str = _PROFILE_OPENEMR_TURNS
    redirect_policy: str = "deny"
    response_size_limit_bytes: int = 1_048_576
    allowed_content_types: tuple[str, ...] = ()
    destination_validator: Callable[[str], None] | None = field(default=None, repr=False)
    telemetry: Any | None = field(default=None, repr=False)
    _owned_client: Any | None = field(default=None, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)
    name: str = "openemr"

    @property
    def turn_delivery(self) -> str:
        """Tell the Policy Gateway when this target requires turn-by-turn delivery."""

        return "sequential" if self.payload_profile == _PROFILE_COPILOT_CHAT else "atomic"

    def __post_init__(self) -> None:
        parts = urlsplit(self.base_url)
        if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
            raise ValueError("OpenEMR adapter requires an exact HTTPS base URL")
        if self.method not in {"GET", "POST"}:
            raise ValueError("OpenEMR adapter method is not allowed")
        if self.payload_profile not in _PAYLOAD_PROFILES:
            raise ValueError("OpenEMR adapter payload profile is not allowed")
        if (
            not self.relative_path
            or self.relative_path.startswith("/")
            or any(value in self.relative_path for value in ("..", "?", "#", "%", "\\"))
        ):
            raise ValueError("OpenEMR adapter relative path is invalid")
        if self.redirect_policy != "deny":
            raise ValueError("OpenEMR adapter redirects must be denied")
        if not 1 <= self.response_size_limit_bytes <= 10_485_760:
            raise ValueError("OpenEMR adapter response limit is invalid")

    def send(self, request: TargetRequest) -> TargetResponse:
        """Deliver ``request`` to the live target over HTTPS and return its response.

        Maps transport/HTTP failures onto the typed taxonomy and NEVER launders a failure into
        a synthetic 200:

        * a connect/timeout failure   -> :class:`TargetUnreachableError`
        * an HTTP 429                  -> :class:`RateLimitedError` (``retry_after`` from header)
        * an expired /chat session    -> :class:`TargetSessionExpiredError` (no blind retry)
        * any other transport failure  -> the base :class:`AdapterError` ('adapter-error')

        A real non-200 target *answer* (e.g. a 403 refusal) is surfaced verbatim — it is a
        genuine target response, not an adapter transport failure.
        """
        client = self._client()
        url = self._build_url()
        headers = self._build_headers()
        body = self._build_body(request)
        auth = self._auth()

        telemetry_handle = None
        try:
            if self.destination_validator is not None:
                self.destination_validator(self.base_url)
            if self.telemetry is not None:
                redactions = (self.credential.reveal(),) if self.credential is not None else ()
                telemetry_handle = self.telemetry.begin(
                    request=request,
                    method=self.method,
                    url=url,
                    provider=self.name,
                    redactions=redactions,
                )
            response = client.request(self.method, url, headers=headers, json=body, auth=auth)
        except (TimeoutError, ConnectionError, OSError) as exc:
            if telemetry_handle is not None:
                telemetry_handle.finish(
                    response_text=None,
                    status_code=None,
                    error_code="target-unreachable",
                )
            # Transport-layer failure: the target could not be reached. Redact by construction —
            # the message names only the URL, never the credential.
            raise TargetUnreachableError(
                f"OpenEMR target unreachable at {url!r}: {type(exc).__name__}"
            ) from exc
        except (TargetUnreachableError, RateLimitedError, AdapterError) as exc:
            # Already a typed adapter error (e.g. from an injected fake) — never re-wrap.
            if telemetry_handle is not None:
                telemetry_handle.finish(
                    response_text=None,
                    status_code=None,
                    error_code=exc.code,
                )
            raise
        except Exception as exc:  # noqa: BLE001 — any other failure is a typed adapter error
            if telemetry_handle is not None:
                telemetry_handle.finish(
                    response_text=None,
                    status_code=None,
                    error_code="adapter-error",
                )
            raise AdapterError(
                f"OpenEMR adapter failure talking to {url!r}: {type(exc).__name__}"
            ) from exc

        status: int | None = None
        output: str | None = None
        try:
            status = int(response.status_code)
            output = response.text
            if 300 <= status < 400:
                raise AdapterError("OpenEMR target redirect refused by exact-scope policy")
            if status == 429:
                # Rate-limited: map to the typed error carrying retry_after (never a synthetic 200).
                raise RateLimitedError(
                    "OpenEMR target rate-limited (HTTP 429)",
                    retry_after=self._parse_retry_after(response.headers),
                )
            if len(output.encode("utf-8")) > self.response_size_limit_bytes:
                raise AdapterError("OpenEMR target response exceeded the configured byte limit")
            if self.allowed_content_types:
                try:
                    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
                except AttributeError as exc:
                    raise AdapterError(
                        "OpenEMR target response content type is unavailable"
                    ) from exc
                if content_type not in self.allowed_content_types:
                    raise AdapterError("OpenEMR target response content type is outside policy")
            if self._is_expired_session_response(status, output):
                raise TargetSessionExpiredError(
                    "OpenEMR delegated session expired; a fresh SMART launch is required"
                )
        except (RateLimitedError, AdapterError) as exc:
            if telemetry_handle is not None:
                telemetry_handle.finish(
                    response_text=output,
                    status_code=status,
                    error_code=exc.code,
                )
            raise
        except Exception as exc:  # noqa: BLE001 — response decoding remains a typed error
            if telemetry_handle is not None:
                telemetry_handle.finish(
                    response_text=output,
                    status_code=status,
                    error_code="adapter-error",
                )
            raise AdapterError(
                f"OpenEMR adapter response failure at {url!r}: {type(exc).__name__}"
            ) from exc
        assert status is not None and output is not None
        if telemetry_handle is not None:
            telemetry_handle.finish(response_text=output, status_code=status)
        # Any other status — including a non-200 target answer — is surfaced verbatim. The
        # adapter NEVER fabricates a 200.
        return TargetResponse(
            output=output,
            status=status,
            metadata={
                "adapter": self.name,
                "url": url,
                **({"trace_id": telemetry_handle.trace_id} if telemetry_handle is not None else {}),
            },
        )

    # ------------------------------------------------------------------ helpers

    def _client(self) -> Any:
        """Return one campaign-persistent client (connection pool + cookie jar)."""
        if self._closed:
            raise AdapterError("OpenEMR adapter is closed")
        if self.client is not None:
            return self.client
        if self._owned_client is None:
            self._owned_client = self.client_factory(self.timeout_seconds)
        return self._owned_client

    def close(self) -> None:
        """Release owned transport state and the in-memory credential; safe to call twice."""

        owned = self._owned_client
        self._owned_client = None
        self.credential = None
        self._closed = True
        close = getattr(owned, "close", None)
        if callable(close):
            close()

    def _build_url(self) -> str:
        """Join the configured base URL with the API path (no double slash)."""
        return f"{self.base_url.rstrip('/')}/{self.relative_path}"

    def _build_headers(self) -> dict[str, str]:
        """Build the non-credential request headers.

        The credential is NEVER inlined here — it flows through :meth:`_auth` as a redacting
        auth object so the raw value never lands in a recorded/logged header string.
        """
        return {"Content-Type": "application/json", "Accept": "application/json"}

    def _auth(self) -> _BearerAuth | None:
        """Wrap the injected Secret in a redacting auth object, or ``None`` when unauthenticated.

        The raw credential is revealed ONLY inside the auth object's outgoing-request flow (the
        HTTPS call boundary), never in a header string that a client would record. The auth
        object's ``repr`` redacts, so it is safe even if a client logs its kwargs.

        In the ``copilot_chat`` profile there is NO Authorization header at all — the scoped
        session credential travels in the request BODY (see :meth:`_build_body`), so this returns
        ``None`` regardless of whether a credential is present.
        """
        if self.payload_profile == _PROFILE_COPILOT_CHAT:
            return None
        if self.credential is None:
            return None
        return _BearerAuth(self.credential)

    def _build_body(self, request: TargetRequest) -> dict[str, Any]:
        """Shape the request into the target's API body per the configured payload profile.

        * ``openemr_turns`` (default) — ``{"turns", "metadata"}`` (credential in the Bearer header).
        * ``copilot_chat`` — ``{"session_id", "message"}`` per the owner's /chat contract. The
          injected credential Secret is REVEALED here (at the send boundary only) as
          ``session_id`` in the BODY. The Policy Gateway passes exactly one turn per physical
          request and retains one campaign-persistent client/session across the sequence.

        The revealed session value never lands in a log/repr: it is placed into the outgoing body
        dict that only the injected client sees at the HTTPS boundary, exactly as the Bearer header
        reveal happens only inside the auth flow.
        """
        if self.payload_profile == _PROFILE_COPILOT_CHAT:
            if self.credential is None:
                raise AdapterError(
                    "OpenEMR /chat contract requires an injected session credential (session_id)"
                )
            return {
                # Reveal the scoped SMART session ONLY here, at the send boundary — never logged,
                # never inlined into a recorded header, never in the adapter's repr.
                "session_id": self.credential.reveal(),
                "message": self._message_from_turns(request),
            }
        return {"turns": list(request.turns), "metadata": dict(request.metadata)}

    @staticmethod
    def _message_from_turns(request: TargetRequest) -> str:
        """Return the one /chat message supplied by the gateway-owned turn sequencer."""

        if len(request.turns) != 1:
            raise AdapterError(
                "OpenEMR /chat requires gateway-owned sequential delivery of exactly one turn"
            )
        return request.turns[0]

    @staticmethod
    def _parse_retry_after(headers: Any) -> float | None:
        """Parse a numeric ``Retry-After`` header value, if present and numeric."""
        try:
            value = headers.get("Retry-After")
        except AttributeError:
            return None
        if value is None:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_expired_session_response(status: int, output: str) -> bool:
        """Recognize the target's typed 401 without retaining or echoing its body."""

        if status != 401:
            return False
        try:
            payload = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            return False
        if not isinstance(payload, dict):
            return False
        detail = payload.get("detail")
        return isinstance(detail, str) and detail.strip().lower().startswith("session expired")
