"""The live OpenEMR TargetAdapter (target #1) — API-primary, typed-error-mapping.

spec(M5) — ARCHITECTURE.md §2/§5, DECISIONS.md D14/D16; PRD-01.

This is the ONLY live-target adapter in this wave. It is reached EXCLUSIVELY through the
trusted Policy Gateway (``agentforge.policy.gateway``) — never directly by an agent — and it
holds NO credential of its own: the gateway resolves a scoped :class:`Secret` by reference and
injects it, and the adapter uses it only at the HTTPS call boundary, never logging or inlining
it.

``send()`` would make a real HTTPS request in an *authorized* live campaign, but the transport
is fully injectable: a test drives it with a fake client (no socket), and the real client
(``httpx``) is imported LAZILY *inside* ``send()`` only when no client was injected — so a bare
``import agentforge.target.openemr_adapter`` (and the activation preflight) pull in no HTTP
client and open no connection.

Transport failures are mapped onto the typed taxonomy in ``agentforge.target.base`` — a
connect/timeout failure -> :class:`TargetUnreachableError`, an HTTP 429 -> :class:`RateLimitedError`
(carrying ``retry_after``), anything else -> the base :class:`AdapterError`. A failure is NEVER
swallowed into a synthetic 200, and there is NO fallback to the P9 fake: a failure surfaces as
a typed error the gateway turns into backoff -> queue -> abort.

Framework-neutral (D10): imports base/secrets only — never a web framework, never httpx at
import time.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from agentforge.secrets import Secret
from agentforge.target.base import (
    AdapterError,
    RateLimitedError,
    TargetAdapter,
    TargetRequest,
    TargetResponse,
    TargetUnreachableError,
)

# Default per-request timeout (seconds) and retry/backoff base — config-driven, mapped to a
# typed error on breach. Kept here so import + preflight need no httpx; the values only reach
# the transport at the ``send()`` call boundary.
_DEFAULT_TIMEOUT_SECONDS = 30.0
_DEFAULT_BACKOFF_SECONDS = 1.0

# The single API path the adapter POSTs an attack turn-sequence to. API-primary: the adapter
# talks to the target over its HTTP API, not a scraped UI.
_API_PATH = "/apis/default/api/copilot/message"


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

    return httpx.Client(timeout=timeout)


@dataclass
class OpenEmrAdapter(TargetAdapter):
    """Live OpenEMR adapter. ``name == "openemr"`` (target #1).

    The HTTP transport is fully injectable: pass ``client`` (any object exposing
    ``request(method, url, **kwargs)``) to drive it in tests with no socket; pass a
    ``client_factory`` to override how the real client is built. Only when NO ``client`` is
    injected does ``send()`` lazily build one via the factory (real network path).

    ``credential`` is a :class:`Secret` the gateway injects by reference; the adapter reveals it
    ONLY at the outgoing-request boundary (an ``Authorization`` header) and never logs/inlines
    the raw value. The dataclass ``repr`` renders the Secret redacted.
    """

    base_url: str = ""
    client: Any | None = None
    client_factory: Callable[[float], Any] = field(default=_default_client_factory)
    credential: Secret | None = None
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS
    name: str = "openemr"

    def send(self, request: TargetRequest) -> TargetResponse:
        """Deliver ``request`` to the live target over HTTPS and return its response.

        Maps transport/HTTP failures onto the typed taxonomy and NEVER launders a failure into
        a synthetic 200:

        * a connect/timeout failure   -> :class:`TargetUnreachableError`
        * an HTTP 429                  -> :class:`RateLimitedError` (``retry_after`` from header)
        * any other transport failure  -> the base :class:`AdapterError` ('adapter-error')

        A real non-200 target *answer* (e.g. a 403 refusal) is surfaced verbatim — it is a
        genuine target response, not an adapter transport failure.
        """
        client = self._client()
        url = self._build_url()
        headers = self._build_headers()
        body = self._build_body(request)
        auth = self._auth()

        try:
            response = client.request("POST", url, headers=headers, json=body, auth=auth)
        except (TimeoutError, ConnectionError, OSError) as exc:
            # Transport-layer failure: the target could not be reached. Redact by construction —
            # the message names only the URL, never the credential.
            raise TargetUnreachableError(
                f"OpenEMR target unreachable at {url!r}: {type(exc).__name__}"
            ) from exc
        except (TargetUnreachableError, RateLimitedError, AdapterError):
            # Already a typed adapter error (e.g. from an injected fake) — never re-wrap.
            raise
        except Exception as exc:  # noqa: BLE001 — any other failure is a typed adapter error
            raise AdapterError(
                f"OpenEMR adapter failure talking to {url!r}: {type(exc).__name__}"
            ) from exc

        status = int(response.status_code)
        if status == 429:
            # Rate-limited: map to the typed error carrying retry_after (never a synthetic 200).
            raise RateLimitedError(
                "OpenEMR target rate-limited (HTTP 429)",
                retry_after=self._parse_retry_after(response.headers),
            )
        # Any other status — including a non-200 target answer — is surfaced verbatim. The
        # adapter NEVER fabricates a 200.
        return TargetResponse(
            output=response.text,
            status=status,
            metadata={"adapter": self.name, "url": url},
        )

    # ------------------------------------------------------------------ helpers

    def _client(self) -> Any:
        """Return the injected client, or lazily build the real one (network path only)."""
        if self.client is not None:
            return self.client
        return self.client_factory(self.timeout_seconds)

    def _build_url(self) -> str:
        """Join the configured base URL with the API path (no double slash)."""
        return f"{self.base_url.rstrip('/')}{_API_PATH}"

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
        """
        if self.credential is None:
            return None
        return _BearerAuth(self.credential)

    @staticmethod
    def _build_body(request: TargetRequest) -> dict[str, Any]:
        """Shape the multi-turn attack sequence into the target's API body."""
        return {"turns": list(request.turns), "metadata": dict(request.metadata)}

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
