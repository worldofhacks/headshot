"""WP-21A active-scan preflight — a ZERO-CALL readiness proof composed from the offline modules.

Before the private Runner executes an active scan (WP-21D), this preflight proves the whole plan
is ready WITHOUT touching the target: it re-runs every offline gate the executor will rely on and
returns a structured report (``ok`` + a per-check pass/fail with detail) rather than raising, so a
Runner can decide whether to proceed and log exactly why not.

Checks (all offline, all fail-closed at execution time):

* ``authorization`` — a present, unexpired, in-scope :class:`ActiveScanAuthorization`;
* ``origin`` — passes the deny-list and equals the owner-approved origin;
* ``image_pinned`` / ``rule_subset_pinned`` — the scope authorized the pinned image + rule subset;
* ``oast_private`` — the OAST callback domains are private (no public collaborator);
* ``synthetic_principals`` — every principal is a provisioned SYNTHETIC test principal;
* ``discovered_surface`` — at least one in-scope operation was discovered from the schema;
* ``auth_matrix`` — the auth matrix builds with markers, never raw secrets.

Composes only offline modules; a socket never opens here.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentforge.security_tools.active_authorization import (
    ActiveScanAuthorization,
    ActiveScanAuthorizationError,
    ActiveScanScope,
)
from agentforge.security_tools.api_discovery import discover_openapi
from agentforge.security_tools.auth_matrix import build_auth_matrix
from agentforge.security_tools.oast import PrivateOastRegistry
from agentforge.security_tools.zap_profiles import (
    ACTIVE_ZAP_IMAGE_SHA256,
    active_scan_rule_subset_sha256,
    validate_active_scan_target,
)

# A provisioned test principal must carry this marker — never a real clinician identity.
SYNTHETIC_PRINCIPAL_PREFIX = "synthetic-"


@dataclass(frozen=True, slots=True)
class PreflightCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class PreflightResult:
    ok: bool
    scope_operation_hash: str
    checks: tuple[PreflightCheck, ...]


def active_scan_preflight(
    scope: ActiveScanScope,
    authorization: ActiveScanAuthorization | None,
    *,
    approved_origin: str,
    openapi_spec: dict,
    auth_matrix_entries: list[tuple[str, str, str | None]],
    now: float,
) -> PreflightResult:
    """Return a zero-call readiness report for an active scan (never raises)."""
    op_hash = scope.operation_hash()
    checks: list[PreflightCheck] = []

    def _check(name: str, fn) -> None:
        try:
            detail = fn()
            checks.append(PreflightCheck(name=name, passed=True, detail=detail or "ok"))
        except Exception as exc:  # readiness report, not a control-flow exception
            checks.append(PreflightCheck(name=name, passed=False, detail=str(exc)))

    def _authorization() -> str:
        ActiveScanAuthorization.verify_optional(
            authorization, operation_hash=op_hash, scope_nonce=scope.scope_nonce, now=now
        )
        return "grant present, unexpired, in scope"

    def _origin() -> str:
        return validate_active_scan_target(scope.origin, approved_origin=approved_origin)

    def _image() -> str:
        if scope.image_sha256 != ACTIVE_ZAP_IMAGE_SHA256:
            raise ActiveScanAuthorizationError(
                "scope did not authorize the pinned ZAP image digest"
            )
        return "pinned image authorized"

    def _rules() -> str:
        if active_scan_rule_subset_sha256() not in scope.rule_sha256s:
            raise ActiveScanAuthorizationError("scope did not authorize the pinned rule subset")
        return "pinned rule subset authorized"

    def _oast() -> str:
        if not scope.callback_domains:
            # OAST stays blocked (never attempted) unless the owner provides a callback domain.
            return "OAST disabled (no callback domain provided)"
        PrivateOastRegistry(scope)  # raises OastEscape on a public/unauthorized domain
        return "callback domains are private"

    def _principals() -> str:
        bad = [p for p in scope.principals if not p.startswith(SYNTHETIC_PRINCIPAL_PREFIX)]
        if bad:
            raise ValueError(f"non-synthetic principals are not allowed: {bad}")
        return f"{len(scope.principals)} synthetic principals"

    def _surface() -> str:
        api = discover_openapi(openapi_spec, scope=scope)
        if not api.operations:
            raise ValueError("no in-scope operation was discovered from the schema")
        return f"{len(api.operations)} in-scope operations (surface {api.surface_sha256[:12]})"

    def _matrix() -> str:
        matrix = build_auth_matrix(auth_matrix_entries, scope=scope)
        if not matrix.cells:
            raise ValueError(
                "auth matrix is empty — an active scan needs at least one authenticated "
                "principal mapped (fail closed)"
            )
        return f"auth matrix {matrix.matrix_sha256[:12]} ({len(matrix.cells)} cells)"

    _check("authorization", _authorization)
    _check("origin", _origin)
    _check("image_pinned", _image)
    _check("rule_subset_pinned", _rules)
    _check("oast_private", _oast)
    _check("synthetic_principals", _principals)
    _check("discovered_surface", _surface)
    _check("auth_matrix", _matrix)

    return PreflightResult(
        ok=all(check.passed for check in checks),
        scope_operation_hash=op_hash,
        checks=tuple(checks),
    )


__all__ = [
    "PreflightCheck",
    "PreflightResult",
    "SYNTHETIC_PRINCIPAL_PREFIX",
    "active_scan_preflight",
]
