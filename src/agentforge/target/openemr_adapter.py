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

import hashlib
import json
import re
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
# Additive profiles for the rest of the Clinical Co-Pilot Bruno surface set:
#   "copilot_public_get"       — GET liveness/readiness; no credential, no body, no auth header.
#   "copilot_evidence_search"  — POST anonymous guideline retrieval; body {"query","k"}, no
#                                credential.
#   "copilot_document_upload"  — POST multipart synthetic document; session_id in the FORM, a
#                                synthetic fixture as the file part, no Authorization header.
#   "copilot_document_read"    — GET a document sub-resource; the uploaded document_id (and page)
#                                are substituted into the path and session_id travels in the QUERY.
_PROFILE_COPILOT_PUBLIC_GET = "copilot_public_get"
_PROFILE_COPILOT_EVIDENCE_SEARCH = "copilot_evidence_search"
_PROFILE_COPILOT_DOCUMENT_UPLOAD = "copilot_document_upload"
_PROFILE_COPILOT_DOCUMENT_READ = "copilot_document_read"
_PAYLOAD_PROFILES = frozenset(
    {
        _PROFILE_OPENEMR_TURNS,
        _PROFILE_COPILOT_CHAT,
        _PROFILE_COPILOT_PUBLIC_GET,
        _PROFILE_COPILOT_EVIDENCE_SEARCH,
        _PROFILE_COPILOT_DOCUMENT_UPLOAD,
        _PROFILE_COPILOT_DOCUMENT_READ,
    }
)
# Profiles whose HTTP method is fixed by the owner's reviewed Bruno contract. openemr_turns stays
# flexible (GET or POST) for backward compatibility; the copilot_* profiles are pinned.
_GET_ONLY_PROFILES = frozenset({_PROFILE_COPILOT_PUBLIC_GET, _PROFILE_COPILOT_DOCUMENT_READ})
_POST_ONLY_PROFILES = frozenset(
    {
        _PROFILE_COPILOT_CHAT,
        _PROFILE_COPILOT_EVIDENCE_SEARCH,
        _PROFILE_COPILOT_DOCUMENT_UPLOAD,
    }
)
# Content types the adapter keeps verbatim; anything else is summarized (digest + size) so a binary
# body (e.g. an image/png page preview) never lands as mojibake in the recorded transcript.
_TEXTUAL_CONTENT_TYPES = frozenset({"", "application/json", "text/plain"})
# One {name} placeholder segment — mirrors target.spec so the adapter needs no cross-module import.
_PATH_PARAM_RE = re.compile(r"\A\{[a-z][a-z0-9_]*\}\Z")


def _relative_path_parameters(relative_path: str) -> tuple[str, ...]:
    """Ordered ``{param}`` names in a relative path (``()`` when fully static)."""

    return tuple(
        segment[1:-1]
        for segment in relative_path.split("/")
        if _PATH_PARAM_RE.fullmatch(segment) is not None
    )


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
    # Resolves a synthetic-only ``fixture://`` reference to (filename, bytes, content_type) for the
    # ``copilot_document_upload`` profile. Injected by the trusted composition root; the adapter
    # reads only synthetic fixtures by reference and never touches an arbitrary local path.
    fixture_resolver: Callable[[str], tuple[str, bytes, str]] | None = field(
        default=None, repr=False
    )
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
        if self.payload_profile in _GET_ONLY_PROFILES and self.method != "GET":
            raise ValueError("OpenEMR adapter payload profile requires GET")
        if self.payload_profile in _POST_ONLY_PROFILES and self.method != "POST":
            raise ValueError("OpenEMR adapter payload profile requires POST")
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
        url = self._build_url(request)
        headers = self._build_headers()
        request_kwargs = self._build_request_kwargs(request)
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
            response = client.request(
                self.method, url, headers=headers, auth=auth, **request_kwargs
            )
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
            content_type = ""
            try:
                header_value = response.headers.get("Content-Type", "")
            except AttributeError as exc:
                if self.allowed_content_types:
                    raise AdapterError(
                        "OpenEMR target response content type is unavailable"
                    ) from exc
                header_value = ""
            if isinstance(header_value, str):
                content_type = header_value.split(";", 1)[0].strip()
            if self.allowed_content_types and content_type not in self.allowed_content_types:
                raise AdapterError("OpenEMR target response content type is outside policy")
            raw_body = getattr(response, "content", None)
            byte_length = (
                len(raw_body)
                if isinstance(raw_body, (bytes, bytearray))
                else len(output.encode("utf-8"))
            )
            if byte_length > self.response_size_limit_bytes:
                raise AdapterError("OpenEMR target response exceeded the configured byte limit")
            if content_type not in _TEXTUAL_CONTENT_TYPES and isinstance(
                raw_body, (bytes, bytearray)
            ):
                # Summarize a non-textual body (e.g. an image/png page preview) into a stable JSON
                # digest so the recorder/Judge never store undecodable bytes.
                output = json.dumps(
                    {
                        "binary_response": True,
                        "content_type": content_type,
                        "byte_length": byte_length,
                        "sha256": hashlib.sha256(bytes(raw_body)).hexdigest(),
                    }
                )
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

    def _build_url(self, request: TargetRequest) -> str:
        """Join the base URL with the API path, substituting any ``{param}`` placeholders.

        For a document-read surface the path carries the uploaded ``document_id`` (and page) as
        ``{name}`` placeholders. Each is filled from the authorized attempt's ``path_params`` and
        strictly validated — a missing, malformed, or unsafe value (traversal / a second authority
        / URL-override syntax) is a fail-closed :class:`AdapterError`, never a partially-templated
        URL.
        """
        path = self.relative_path
        parameters = _relative_path_parameters(path)
        if parameters:
            supplied = self._path_params(request)
            for name in parameters:
                value = supplied.get(name)
                if (
                    not isinstance(value, str)
                    or not value
                    or any(bad in value for bad in ("/", "?", "#", "%", "\\", " ", "..", "{", "}"))
                ):
                    raise AdapterError("OpenEMR document path parameter is missing or unsafe")
                path = path.replace("{" + name + "}", value)
        return f"{self.base_url.rstrip('/')}/{path}"

    @staticmethod
    def _path_params(request: TargetRequest) -> dict[str, Any]:
        """Decode the attempt's ``path_params`` metadata (a JSON object string) fail-closed."""
        raw = dict(request.metadata or {}).get("path_params")
        if raw is None:
            return {}
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError) as exc:
            raise AdapterError("OpenEMR document path parameters are malformed") from exc
        if not isinstance(parsed, dict):
            raise AdapterError("OpenEMR document path parameters are malformed")
        return parsed

    def _build_headers(self) -> dict[str, str]:
        """Build the non-credential request headers for the active payload profile.

        The credential is NEVER inlined here — it flows through the profile-specific body/form/query
        (or the redacting :meth:`_auth` bearer object), so the raw value never lands in a recorded
        header string. A multipart upload declares no Content-Type so the client owns the boundary.
        """
        if self.payload_profile == _PROFILE_COPILOT_DOCUMENT_UPLOAD:
            return {"Accept": "application/json"}
        if self.payload_profile in _GET_ONLY_PROFILES:
            return {"Accept": "application/json, image/png, text/plain"}
        return {"Content-Type": "application/json", "Accept": "application/json"}

    def _auth(self) -> _BearerAuth | None:
        """Wrap the injected Secret in a redacting auth object, or ``None`` when unauthenticated.

        The raw credential is revealed ONLY inside the auth object's outgoing-request flow (the
        HTTPS call boundary), never in a header string that a client would record. The auth
        object's ``repr`` redacts, so it is safe even if a client logs its kwargs.

        Only the default ``openemr_turns`` profile authenticates with an ``Authorization: Bearer``
        header. Every ``copilot_*`` profile carries the scoped session credential elsewhere (in the
        body, the multipart form, or the query string) or needs none at all, so this returns
        ``None`` for them regardless of whether a credential is present.
        """
        if self.payload_profile != _PROFILE_OPENEMR_TURNS:
            return None
        if self.credential is None:
            return None
        return _BearerAuth(self.credential)

    def _build_request_kwargs(self, request: TargetRequest) -> dict[str, Any]:
        """Shape the outgoing request per the configured payload profile.

        Returns the keyword arguments (``json`` / ``data`` + ``files`` / ``params`` / none) passed
        to the injected client alongside ``method``/``url``/``headers``/``auth``. Where a credential
        is required it is REVEALED here — at the send boundary only — into the outgoing structure
        the client transmits, never into a header string, log, or the adapter's repr.

        * ``openemr_turns``            — ``json={"turns","metadata"}`` (credential in the Bearer
                                         header).
        * ``copilot_chat``             — ``json={"session_id","message"}`` (session in the body).
        * ``copilot_public_get``       — no body, no credential (liveness/readiness).
        * ``copilot_evidence_search``  — ``json={"query","k"}``, no credential (anonymous
                                         retrieval).
        * ``copilot_document_upload``  — ``data={"session_id","doc_type"}`` + a synthetic fixture as
                                         ``files={"file": ...}`` (session in the form).
        * ``copilot_document_read``    — ``params={"session_id": ...}`` (session in the query; the
                                         document_id is already substituted into the URL path).
        """
        profile = self.payload_profile
        if profile == _PROFILE_COPILOT_PUBLIC_GET:
            return {}
        if profile == _PROFILE_COPILOT_EVIDENCE_SEARCH:
            return {
                "json": {"query": self._message_from_turns(request), "k": self._search_k(request)}
            }
        if profile == _PROFILE_COPILOT_CHAT:
            return {
                "json": {
                    "session_id": self._require_credential("/chat").reveal(),
                    "message": self._message_from_turns(request),
                }
            }
        if profile == _PROFILE_COPILOT_DOCUMENT_UPLOAD:
            credential = self._require_credential("document upload")
            if self.fixture_resolver is None:
                raise AdapterError(
                    "OpenEMR document upload requires an injected synthetic fixture resolver"
                )
            metadata = dict(request.metadata or {})
            doc_type = metadata.get("doc_type")
            fixture_ref = metadata.get("fixture_ref")
            if not isinstance(doc_type, str) or not doc_type:
                raise AdapterError("OpenEMR document upload requires a doc_type")
            if not isinstance(fixture_ref, str) or not fixture_ref.startswith("fixture://"):
                raise AdapterError("OpenEMR document upload requires a synthetic fixture reference")
            filename, content, content_type = self.fixture_resolver(fixture_ref)
            return {
                "data": {"session_id": credential.reveal(), "doc_type": doc_type},
                "files": {"file": (filename, content, content_type)},
            }
        if profile == _PROFILE_COPILOT_DOCUMENT_READ:
            return {"params": {"session_id": self._require_credential("document read").reveal()}}
        return {"json": {"turns": list(request.turns), "metadata": dict(request.metadata)}}

    def _require_credential(self, surface: str) -> Secret:
        """Return the injected session credential or fail closed for a credentialed profile."""
        if self.credential is None:
            raise AdapterError(
                f"OpenEMR {surface} contract requires an injected session credential (session_id)"
            )
        return self.credential

    @staticmethod
    def _search_k(request: TargetRequest) -> int:
        """Parse the evidence-search ``k`` (default 5), fail-closed on a non-integer /
        out-of-range."""
        raw = dict(request.metadata or {}).get("k")
        if raw is None:
            return 5
        try:
            k = int(raw)
        except (TypeError, ValueError) as exc:
            raise AdapterError("OpenEMR evidence search k must be an integer") from exc
        if not 1 <= k <= 50:
            raise AdapterError("OpenEMR evidence search k is out of range")
        return k

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
