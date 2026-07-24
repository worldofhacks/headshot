"""The real bounded HTTPS sender — the last mile that makes a governed active scan physical.

This is the ``dispatch`` callable given to :class:`GovernedScanEgress`. The egress already gates
each send (abort, scope, caps, permit); this adds the physical-send guardrails and is the ONLY
place a socket to the target is opened:

* **default-disabled** — refuses unless ``AGENTFORGE_ACTIVE_SCAN_ENABLED`` is truthy (belt and
  suspenders with the grant gate; a sandbox without the flag can never send);
* **exact-origin + deny-list** re-checked at send time (defense in depth over the scope);
* **DNS-rebinding defense** — the host is resolved, EVERY resolved address is validated against
  private/loopback/link-local/reserved/metadata, and the connection is PINNED to a validated IP
  (with SNI/cert = the domain), so a name that answers with an internal address never connects;
* **redirects denied** — a 3xx is terminal, never chased to another origin;
* **bounded** — connect/read timeout and a hard response-byte cap;
* **credential hygiene** — the SID resolves ONLY via the sealed ``secretref`` binding into a
  :class:`Secret`, is injected on the wire, and never appears in the outcome, a log, or an argv.

The socket/TLS layer is injected (``connection_opener``) so every guardrail is tested offline; the
real opener runs only in the private Runner.
"""

from __future__ import annotations

import hashlib
import ipaddress
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from agentforge.secrets import Secret
from agentforge.security_tools.active_authorization import ActiveScanScope, path_in_scope
from agentforge.security_tools.zap_profiles import _METADATA_IPS, validate_active_scan_target

ACTIVE_SCAN_ENABLED_ENV = "AGENTFORGE_ACTIVE_SCAN_ENABLED"
_DEFAULT_MAX_RESPONSE_BYTES = 65_536
_DEFAULT_TIMEOUT_S = 10.0


class ActiveScanSendError(Exception):
    """Fail-closed refusal of a physical active-scan send (disabled / off-scope / unsafe target)."""


@dataclass(frozen=True, slots=True)
class SendOutcome:
    """Redacted evidence of one physical send. Carries no credential and no response body."""

    status_code: int
    pinned_ip: str
    bytes_read: int
    response_sha256: str
    redirected: bool
    canary_reflected: bool
    elapsed_ms: float


def _enabled(env: Mapping[str, str]) -> bool:
    return str(env.get(ACTIVE_SCAN_ENABLED_ENV, "")).strip().lower() in {"1", "true", "yes", "on"}


def _ip_is_safe(ip_text: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    if ip_text in _METADATA_IPS:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_unspecified
        or address.is_multicast
    )


def resolve_and_validate_ips(host: str, *, resolver: Callable[[str], list[str]]) -> tuple[str, ...]:
    """Resolve ``host`` and return its addresses only if EVERY one is a public unicast address.

    If the name answers with even a single private/loopback/link-local/reserved/metadata address,
    the whole resolution is refused (a DNS-rebinding answer poisons the set), fail-closed.
    """
    addresses = list(resolver(host))
    if not addresses:
        raise ActiveScanSendError(f"host {host!r} did not resolve to any address (fail closed)")
    for ip_text in addresses:
        if not _ip_is_safe(ip_text):
            raise ActiveScanSendError(
                f"host {host!r} resolves to a private/loopback/link-local/metadata address "
                f"{ip_text!r} — refused (SSRF / DNS-rebinding defense, fail closed)"
            )
    return tuple(addresses)


def _default_resolver(host: str) -> list[str]:  # pragma: no cover - real DNS, Runner only
    import socket

    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


def _default_opener(ip: str, port: int, host: str):  # pragma: no cover - real TLS, Runner only
    import http.client

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            import socket

            sock = socket.create_connection((ip, port), timeout=self.timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=host)

    context = ssl.create_default_context()
    return _PinnedHTTPSConnection(host, port, context=context, timeout=_DEFAULT_TIMEOUT_S)


class BoundedHttpsSender:
    """A bounded, exact-origin, permit-gated physical sender for one active scan."""

    def __init__(
        self,
        scope: ActiveScanScope,
        *,
        credential_ref: str | None = None,
        credential_resolver: Callable[[str | None], Secret | None] | None = None,
        auth_header: str = "Cookie",
        canary: str | None = None,
        canary_param: str = "agentforge_probe",
        env: Mapping[str, str] | None = None,
        host_resolver: Callable[[str], list[str]] | None = None,
        connection_opener: Callable[[str, int, str], Any] | None = None,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
    ) -> None:
        import os

        self._scope = scope
        self._credential_ref = credential_ref
        self._credential_resolver = credential_resolver
        self._auth_header = auth_header
        self._canary = canary
        self._canary_param = canary_param
        self._env = os.environ if env is None else env
        self._resolver = host_resolver or _default_resolver
        self._opener = connection_opener or _default_opener
        self._max_response_bytes = max_response_bytes
        self._timeout_s = timeout_s

    def __call__(self, permit: Any) -> SendOutcome:
        if not _enabled(self._env):
            raise ActiveScanSendError(
                f"active scanning is disabled ({ACTIVE_SCAN_ENABLED_ENV} is not set) — fail closed"
            )
        parts = urlsplit(self._scope.origin)
        if parts.scheme != "https":
            raise ActiveScanSendError("active-scan sender is https-only (fail closed)")
        # Defense in depth: re-validate origin deny-list and permit path scope at the send boundary.
        validate_active_scan_target(self._scope.origin, approved_origin=self._scope.origin)
        if not path_in_scope(permit.path, self._scope.path_patterns):
            raise ActiveScanSendError(
                f"path {permit.path!r} is outside the authorized active-scan scope (fail closed)"
            )
        host = parts.hostname or ""
        port = parts.port or 443
        pinned_ip = resolve_and_validate_ips(host, resolver=self._resolver)[0]

        headers = {
            "Host": host,
            "User-Agent": "AgentForge-ActiveScan",
            "Accept": "*/*",
            "Connection": "close",
        }
        if self._credential_ref is not None:
            resolver = self._credential_resolver
            secret = resolver(self._credential_ref) if resolver is not None else None
            if secret is not None:
                # reveal() ONLY here, at the authorized send boundary; never logged/returned.
                headers[self._auth_header] = secret.reveal()

        path = permit.path
        if self._canary is not None:
            joiner = "&" if "?" in path else "?"
            path = f"{path}{joiner}{self._canary_param}={self._canary}"

        started = time.monotonic()
        conn = self._opener(pinned_ip, port, host)
        try:
            body = b"{}" if permit.method in {"POST", "PUT", "PATCH"} else None
            conn.request(permit.method, path, body=body, headers=headers)
            response = conn.getresponse()
            payload = response.read(self._max_response_bytes) or b""
            status = int(response.status)
        finally:
            conn.close()
        elapsed_ms = (time.monotonic() - started) * 1000.0

        canary_reflected = bool(
            self._canary is not None and self._canary.encode("utf-8") in payload
        )
        return SendOutcome(
            status_code=status,
            pinned_ip=pinned_ip,
            bytes_read=len(payload),
            response_sha256=hashlib.sha256(payload).hexdigest(),
            redirected=300 <= status < 400,
            canary_reflected=canary_reflected,
            elapsed_ms=elapsed_ms,
        )


__all__ = [
    "ACTIVE_SCAN_ENABLED_ENV",
    "ActiveScanSendError",
    "BoundedHttpsSender",
    "SendOutcome",
    "resolve_and_validate_ips",
]
