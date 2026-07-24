"""WP-16D governed egress for active scanners — fresh per-request permit + parity ledger.

An active scanner never sends to a target directly. Every physical request crosses this governed
seam, which mirrors the PolicyGateway's ``pre_physical_send_gate`` / ``post_physical_send_observer``
contract for scanner traffic:

* :meth:`reserve_permit` is the pre-physical-send gate — it re-checks the abort flag, the scope
  (method + path), and the caps (max requests + rate) BEFORE minting a fresh, content-addressed
  permit. A breach is a HARD ABORT that reaches no physical send.
* :meth:`report_send` is the post-physical-send observer — it records exactly one ledger entry per
  permit (``returned`` / ``raised``); a failed send still counts and is still recorded.
* :meth:`assert_parity` proves scanner<->permit<->send<->ledger is 1:1. A permit that never
  reported a send, or a send with no permit, fails closed — "if parity cannot be proven, active
  scanning is disabled."

:meth:`send` composes the two around an injected ``dispatch`` callable. Offline and framework-
neutral; the dispatch is the only egress and is injected (a socket in the Runner, a fake in tests).
"""

from __future__ import annotations

import fnmatch
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanScope,
)


class ScanEgressAbort(Exception):
    """Fail-closed refusal of a scanner egress — abort flag, out-of-scope, capped, or parity break.

    A dedicated type so a governed refusal (the seam doing its job) is distinguishable from an
    incidental bug; the message always names the reason.
    """


@dataclass(frozen=True, slots=True)
class ScanPermit:
    """A fresh, content-addressed permit for exactly one physical scanner request."""

    permit_id: str
    request_index: int
    method: str
    path: str


@dataclass(frozen=True, slots=True)
class ScanEgressLedgerEntry:
    """One durable ledger record proving a permitted physical send occurred."""

    permit_id: str
    request_index: int
    method: str
    path: str
    outcome: str  # "returned" | "raised"


def _path_in_scope(path: str, patterns: tuple[str, ...]) -> bool:
    candidate = path.split("?", 1)[0].split("#", 1)[0]
    return any(candidate == pattern or fnmatch.fnmatch(candidate, pattern) for pattern in patterns)


def _mint_permit(scope: ActiveScanScope, request_index: int, method: str, path: str) -> ScanPermit:
    material = "\x1f".join(
        [scope.operation_hash(), str(request_index), method, path, scope.scope_nonce]
    ).encode("utf-8")
    return ScanPermit(
        permit_id=hashlib.sha256(material).hexdigest(),
        request_index=request_index,
        method=method,
        path=path,
    )


class GovernedScanEgress:
    """The sole egress seam for one active scan — mints permits and proves send/ledger parity."""

    def __init__(
        self,
        scope: ActiveScanScope,
        *,
        authorization: ActiveScanAuthorization | None,
        now: float,
        abort_check: Callable[[], bool] = lambda: False,
    ) -> None:
        ActiveScanAuthorization.verify_optional(
            authorization,
            operation_hash=scope.operation_hash(),
            scope_nonce=scope.scope_nonce,
            now=now,
        )
        self._scope = scope
        self._abort_check = abort_check
        self._allowed_methods = {m.upper() for m in scope.http_methods}
        self._min_interval = 1.0 / scope.caps.requests_per_second
        self._permits: dict[str, ScanPermit] = {}
        self._ledger: list[ScanEgressLedgerEntry] = []
        self._reported: set[str] = set()
        self._request_index = 0
        self._last_send_at: float | None = None

    @property
    def permits(self) -> tuple[ScanPermit, ...]:
        return tuple(self._permits.values())

    @property
    def ledger(self) -> tuple[ScanEgressLedgerEntry, ...]:
        return tuple(self._ledger)

    def reserve_permit(self, *, method: str, path: str, now: float) -> ScanPermit:
        """Pre-physical-send gate: re-check abort/scope/caps, then mint a fresh permit."""
        if self._abort_check():
            raise ScanEgressAbort(
                "active scan aborted — no physical send is admitted after abort (fail closed)"
            )
        upper = method.upper()
        if upper not in self._allowed_methods:
            raise ScanEgressAbort(
                f"method {upper} is outside the authorized active-scan scope (fail closed)"
            )
        if not _path_in_scope(path, self._scope.path_patterns):
            raise ScanEgressAbort(
                f"path {path} is outside the authorized active-scan scope (fail closed)"
            )
        if len(self._permits) >= self._scope.caps.max_requests:
            raise ScanEgressAbort("active-scan request cap reached (fail closed)")
        if self._last_send_at is not None and (now - self._last_send_at) < self._min_interval:
            raise ScanEgressAbort(
                "active-scan rate cap: sends are too close together (fail closed)"
            )

        self._request_index += 1
        permit = _mint_permit(self._scope, self._request_index, upper, path)
        self._permits[permit.permit_id] = permit
        self._last_send_at = now
        return permit

    def report_send(self, permit: Any, outcome: str) -> None:
        """Post-physical-send observer: record exactly one ledger entry for a minted permit."""
        permit_id = getattr(permit, "permit_id", None)
        if permit_id not in self._permits:
            raise ScanEgressAbort(
                "ledger entry has no matching permit — parity break, active scanning disabled "
                "(fail closed)"
            )
        if permit_id in self._reported:
            raise ScanEgressAbort(
                "permit already reported — double physical send, parity break (fail closed)"
            )
        self._reported.add(permit_id)
        minted = self._permits[permit_id]
        self._ledger.append(
            ScanEgressLedgerEntry(
                permit_id=minted.permit_id,
                request_index=minted.request_index,
                method=minted.method,
                path=minted.path,
                outcome=outcome,
            )
        )

    def send(
        self, *, method: str, path: str, dispatch: Callable[[ScanPermit], Any], now: float
    ) -> Any:
        """Reserve a permit, dispatch the single physical send, and record the ledger entry."""
        permit = self.reserve_permit(method=method, path=path, now=now)
        try:
            result = dispatch(permit)
        except BaseException:
            self.report_send(permit, "raised")
            raise
        self.report_send(permit, "returned")
        return result

    def assert_parity(self) -> None:
        """Prove scanner<->permit<->send<->ledger is 1:1, else fail closed."""
        issued = set(self._permits)
        recorded = {entry.permit_id for entry in self._ledger}
        if issued != recorded or len(self._ledger) != len(self._permits):
            missing = issued - recorded
            raise ScanEgressAbort(
                "scanner/permit/send/ledger parity broken — active scanning disabled (fail "
                f"closed); permits without a reported send: {sorted(missing)}"
            )


__all__ = [
    "GovernedScanEgress",
    "ScanEgressAbort",
    "ScanEgressLedgerEntry",
    "ScanPermit",
]
