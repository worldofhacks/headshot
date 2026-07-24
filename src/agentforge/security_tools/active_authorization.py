"""ActiveScanAuthorization — a SEPARATE, expiring, content-addressed grant for active scanning.

Active (non-passive) scanning — ZAP active rules, API fuzzing, authenticated-matrix probing,
per-attempt OAST — is a materially higher-risk operation than a passive baseline or a
policy-gateway campaign dispatch. It is therefore NEVER authorized by a campaign
:class:`~agentforge.campaign.authorization.RunAuthorization`; a configured, credentialed,
even campaign-authorized box is not on its own authorized to *actively* scan a live origin.

An active scan is authorized only by a minted :class:`ActiveScanAuthorization` that binds a
canonical **operation hash** of the WHOLE active-scan identity:

* ``origin`` — the EXACT https origin under scan (a different origin is a different scan);
* ``http_methods`` — the exact set of methods the scan may issue;
* ``path_patterns`` — the exact set of URL path patterns in scope;
* ``principals`` — the provisioned synthetic test principals the scan authenticates as;
* ``image_sha256`` — the pinned scanner container image digest;
* ``addon_sha256s`` — the pinned scanner addon digests;
* ``rule_sha256s`` — the pinned Automation-Framework active-rule subset digests;
* ``callback_domains`` — the private OAST callback domains the scan may register;
* ``caps`` — every ceiling (max requests / rate / duration / findings); and
* ``scope_nonce`` — the single active-scan instance.

Mirrors the RunAuthorization design (content-addressed scope + absolute expiry + nonce pin +
frozen grant) so the two grants verify identically and neither can be widened after minting.
Sets (methods, principals, addon/rule digests, callback domains, path patterns) are canonicalised
order-independently so the grant is byte-reproducible. Stdlib only; no Docker, no network.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass


class ActiveScanAuthorizationError(Exception):
    """Raised when an active scan is NOT authorized — missing, expired, out of scope, or capped.

    A dedicated, catchable type so a fail-closed refusal (the gate doing its job) is
    distinguishable from an incidental bug. The message always names the reason.
    """


@dataclass(frozen=True, slots=True)
class ActiveScanCaps:
    """Immutable ceilings for one active scan. Every field is required and bounded (fail-closed)."""

    max_requests: int
    requests_per_second: float
    max_duration_seconds: float
    max_findings: int

    @classmethod
    def parse(
        cls,
        *,
        max_requests: int,
        requests_per_second: float,
        max_duration_seconds: float,
        max_findings: int,
    ) -> ActiveScanCaps:
        """Fail-closed parser: missing/zero/negative/non-finite/over-maximum raises."""

        def _positive_int(name: str, value: int, ceiling: int) -> int:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ActiveScanAuthorizationError(f"active-scan cap {name} must be an integer")
            if value <= 0:
                raise ActiveScanAuthorizationError(f"active-scan cap {name} must be positive")
            if value > ceiling:
                raise ActiveScanAuthorizationError(
                    f"active-scan cap {name}={value} exceeds the maximum {ceiling}"
                )
            return value

        def _positive_float(name: str, value: float, ceiling: float) -> float:
            number = float(value)
            if not math.isfinite(number):
                raise ActiveScanAuthorizationError(f"active-scan cap {name} must be finite")
            if number <= 0:
                raise ActiveScanAuthorizationError(f"active-scan cap {name} must be positive")
            if number > ceiling:
                raise ActiveScanAuthorizationError(
                    f"active-scan cap {name}={number} exceeds the maximum {ceiling}"
                )
            return number

        return cls(
            max_requests=_positive_int("max_requests", max_requests, 5000),
            requests_per_second=_positive_float("requests_per_second", requests_per_second, 50.0),
            max_duration_seconds=_positive_float(
                "max_duration_seconds", max_duration_seconds, 3600.0
            ),
            max_findings=_positive_int("max_findings", max_findings, 5000),
        )

    def payload(self) -> dict[str, float | int]:
        return {
            "max_requests": self.max_requests,
            "requests_per_second": self.requests_per_second,
            "max_duration_seconds": self.max_duration_seconds,
            "max_findings": self.max_findings,
        }


def active_scan_operation_hash(
    *,
    origin: str,
    http_methods: tuple[str, ...],
    path_patterns: tuple[str, ...],
    principals: tuple[str, ...],
    image_sha256: str,
    addon_sha256s: tuple[str, ...],
    rule_sha256s: tuple[str, ...],
    callback_domains: tuple[str, ...],
    caps: ActiveScanCaps,
    scope_nonce: str,
) -> str:
    """Return the canonical 64-hex operation hash scoping the grant to the WHOLE active scan.

    A pure function of the scope — every set field sorted (order-independent), then sorted-key
    JSON, then sha256-hexed — so the grant re-verifies independently and changing ANY bound field
    changes the hash (and thus refuses the grant). Methods are upper-cased for canonical identity.
    """

    payload = {
        "origin": origin,
        "http_methods": sorted({m.upper() for m in http_methods}),
        "path_patterns": sorted(set(path_patterns)),
        "principals": sorted(set(principals)),
        "image_sha256": image_sha256,
        "addon_sha256s": sorted(set(addon_sha256s)),
        "rule_sha256s": sorted(set(rule_sha256s)),
        "callback_domains": sorted(set(callback_domains)),
        "caps": caps.payload(),
        "scope_nonce": scope_nonce,
    }
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class ActiveScanScope:
    """The immutable, content-addressed scope of one active scan.

    A single value object shared by the grant minter and every active-scan executor
    (zap_profiles / scan_egress / api_discovery / auth_matrix / oast), so the operation hash is
    computed one way and can never drift between the grant and the command it authorizes.
    """

    origin: str
    http_methods: tuple[str, ...]
    path_patterns: tuple[str, ...]
    principals: tuple[str, ...]
    image_sha256: str
    addon_sha256s: tuple[str, ...]
    rule_sha256s: tuple[str, ...]
    callback_domains: tuple[str, ...]
    caps: ActiveScanCaps
    scope_nonce: str

    def operation_hash(self) -> str:
        return active_scan_operation_hash(
            origin=self.origin,
            http_methods=self.http_methods,
            path_patterns=self.path_patterns,
            principals=self.principals,
            image_sha256=self.image_sha256,
            addon_sha256s=self.addon_sha256s,
            rule_sha256s=self.rule_sha256s,
            callback_domains=self.callback_domains,
            caps=self.caps,
            scope_nonce=self.scope_nonce,
        )


@dataclass(frozen=True, slots=True)
class ActiveScanAuthorization:
    """A minted, immutable authorization for exactly one active scan.

    Frozen so its bound scope (``operation_hash`` / ``scope_nonce`` / ``deadline``) cannot be
    widened after minting — immutability is a structural property, not a convention.
    """

    operation_hash: str
    scope_nonce: str
    deadline: float

    def verify(self, *, operation_hash: str, scope_nonce: str, now: float) -> None:
        """BLOCK unless this grant is unexpired AND in-scope for the current active scan.

        Fail-closed, in order: expiry (``now >= deadline``), operation-hash scope, nonce scope.
        Raises :class:`ActiveScanAuthorizationError` on any; returns ``None`` only when the grant
        is present, live, and in scope.
        """
        if now >= self.deadline:
            raise ActiveScanAuthorizationError(
                f"active-scan authorization has EXPIRED: now={now} has reached "
                f"deadline={self.deadline} — a grant is a bounded window, never standing "
                "permission (fail closed)"
            )
        if self.operation_hash != operation_hash:
            raise ActiveScanAuthorizationError(
                "active-scan authorization SCOPE mismatch: the bound operation_hash does not match "
                "this scan's operation_hash — a grant minted for one scope can never authorize a "
                "different one (fail closed)"
            )
        if self.scope_nonce != scope_nonce:
            raise ActiveScanAuthorizationError(
                "active-scan authorization SCOPE mismatch: the bound scope_nonce does not match "
                "this scan's nonce — the grant rides exactly one scan instance (fail closed)"
            )

    @classmethod
    def verify_optional(
        cls,
        authorization: ActiveScanAuthorization | None,
        *,
        operation_hash: str,
        scope_nonce: str,
        now: float,
    ) -> None:
        """BLOCK a MISSING authorization, else delegate to :meth:`verify`."""
        if authorization is None:
            raise ActiveScanAuthorizationError(
                "no active-scan authorization was minted — a configured environment or a campaign "
                "grant is NOT active-scan authorization; a scan-scoped grant is required (fail "
                "closed)"
            )
        authorization.verify(operation_hash=operation_hash, scope_nonce=scope_nonce, now=now)


__all__ = [
    "ActiveScanAuthorization",
    "ActiveScanAuthorizationError",
    "ActiveScanCaps",
    "ActiveScanScope",
    "active_scan_operation_hash",
]
