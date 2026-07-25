"""WP-18A private, per-attempt OAST — prove SSRF / blind exfiltration out of band.

An out-of-band callback is the ground truth for blind SSRF and blind data exfiltration: the target
is coerced to reach a URL only the scanner knows, and a hit on that URL proves the coercion worked.

AgentForge runs its OWN private OAST. It never uses a public collaborator (that would send target
behaviour and any exfiltrated bytes to a third party). Each attempt mints a fresh callback
subdomain whose label is derived from the active-scan operation hash + attempt id + scope nonce, so
it is unpredictable without the nonce and correlates a received callback to exactly one attempt.

Fail-closed: the callback domain must be one the grant authorized AND a private (internal) domain;
a callback to an unminted label or an unauthorized domain is an escape. Offline — no DNS, no
listener; a real Runner wires an internal listener that calls :meth:`observe_callback`.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from agentforge.security_tools.active_authorization import ActiveScanScope, content_digest

# Only these suffixes are accepted as private OAST domains. A public collaborator or the target
# origin is never a valid callback domain (the callback would leave our trust boundary).
_PRIVATE_DOMAIN_SUFFIXES = (".internal", ".agentforge.local")


class OastEscape(Exception):
    """Fail-closed refusal of an OAST operation — unauthorized/public domain or unminted callback.

    A dedicated type so a governed refusal (the OAST registry doing its job) is distinguishable
    from an incidental bug; the message always names the reason.
    """


@dataclass(frozen=True, slots=True)
class OastToken:
    """A fresh per-attempt OAST callback binding."""

    attempt_id: str
    label: str
    domain: str

    @property
    def callback_host(self) -> str:
        return f"{self.label}.{self.domain}"

    @property
    def callback_url(self) -> str:
        return f"https://{self.callback_host}/cb/{self.attempt_id}"


def _is_private_domain(domain: str) -> bool:
    host = domain.rstrip(".").lower()
    return any(host.endswith(suffix) for suffix in _PRIVATE_DOMAIN_SUFFIXES)


class PrivateOastRegistry:
    """Mints per-attempt OAST callbacks and correlates received hits, fail-closed on any escape."""

    def __init__(self, scope: ActiveScanScope) -> None:
        authorized = tuple(d.rstrip(".").lower() for d in scope.callback_domains)
        for domain in authorized:
            if not _is_private_domain(domain):
                raise OastEscape(
                    f"OAST callback domain {domain!r} is not a private internal domain — a public "
                    "collaborator or the target is never a valid callback (fail closed)"
                )
        if not authorized:
            raise OastEscape("no OAST callback domain was authorized by the active-scan scope")
        self._scope = scope
        self._authorized_domains = frozenset(authorized)
        self._minted: dict[str, OastToken] = {}
        self._confirmed: list[str] = []

    def _label(self, attempt_id: str, domain: str) -> str:
        return content_digest(
            self._scope.operation_hash(), attempt_id, domain, self._scope.scope_nonce
        )[:32]

    def mint(self, attempt_id: str, *, domain: str | None = None) -> OastToken:
        """Mint a fresh callback for one attempt on an authorized private domain."""
        chosen = (domain or next(iter(sorted(self._authorized_domains)))).rstrip(".").lower()
        if chosen not in self._authorized_domains:
            raise OastEscape(
                f"OAST domain {chosen!r} is not authorized by the active-scan scope (fail closed)"
            )
        token = OastToken(
            attempt_id=attempt_id, label=self._label(attempt_id, chosen), domain=chosen
        )
        self._minted[token.callback_host] = token
        return token

    def observe_callback(self, url: str) -> OastToken:
        """Correlate a received callback to its minting attempt, or fail closed on any escape."""
        host = (urlsplit(url).hostname or "").rstrip(".").lower()
        if not host:
            raise OastEscape("OAST callback has no host (fail closed)")
        label, _, domain = host.partition(".")
        if domain not in self._authorized_domains:
            raise OastEscape(
                f"OAST callback domain {domain!r} is outside the authorized private domains — "
                "escape, fail closed"
            )
        token = self._minted.get(host)
        if token is None:
            raise OastEscape(
                f"OAST callback label {label!r} was never minted — unrecognized/unminted callback "
                "(fail closed)"
            )
        if token.attempt_id not in self._confirmed:
            self._confirmed.append(token.attempt_id)
        return token

    def confirmed_attempts(self) -> tuple[str, ...]:
        """Attempts whose OAST callback fired — out-of-band-confirmed SSRF/exfiltration."""
        return tuple(self._confirmed)


__all__ = ["OastEscape", "OastToken", "PrivateOastRegistry"]
