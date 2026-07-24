"""WP-17 authenticated-scan matrix — principals x auth modes, bound by markers not secrets.

An authenticated active scan exercises the target as provisioned SYNTHETIC test principals across
auth modes (unauthenticated, clinician-scoped, ...). This module binds each (principal, auth mode)
to a credential *marker* — ``no-auth`` or ``cred-sha256:<digest>`` of the credential reference —
exactly as the campaign operation hash and TargetBinding do. A raw secret VALUE never enters the
matrix (only a ``secretref://`` / ``env:`` handle is accepted, and only its digest is stored), a
principal the scope did not authorize is refused, and the matrix is content-addressed so the
authenticated surface can be pinned and reviewed.

Stdlib only; no secret resolution — the raw credential is resolved only at the governed dispatch
boundary in the Runner, never here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from agentforge.security_tools.active_authorization import ActiveScanScope

_REFERENCE_PREFIXES = ("secretref://", "env:")


def _credential_marker(auth_mode: str, credential_ref: str | None) -> str:
    if auth_mode == "none":
        if credential_ref is not None:
            raise ValueError("auth_mode 'none' must not carry a credential reference")
        return "no-auth"
    if not credential_ref or not credential_ref.startswith(_REFERENCE_PREFIXES):
        raise ValueError(
            "a credentialed principal must carry a credential reference (secretref:// or env:), "
            "never a raw secret value"
        )
    return "cred-sha256:" + hashlib.sha256(credential_ref.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthCell:
    principal_id: str
    auth_mode: str
    credential_marker: str


@dataclass(frozen=True, slots=True)
class AuthenticationMatrix:
    cells: tuple[AuthCell, ...]
    matrix_sha256: str

    def marker(self, principal_id: str, auth_mode: str) -> str:
        for cell in self.cells:
            if cell.principal_id == principal_id and cell.auth_mode == auth_mode:
                return cell.credential_marker
        raise KeyError(f"no matrix cell for ({principal_id!r}, {auth_mode!r})")

    def canonical_json(self) -> str:
        return json.dumps(
            [[c.principal_id, c.auth_mode, c.credential_marker] for c in self.cells],
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )


def build_auth_matrix(
    entries: list[tuple[str, str, str | None]],
    *,
    scope: ActiveScanScope,
) -> AuthenticationMatrix:
    """Build the content-addressed auth matrix, refusing off-scope principals and raw secrets."""
    authorized = set(scope.principals)
    cells: list[AuthCell] = []
    seen: set[tuple[str, str]] = set()
    for principal_id, auth_mode, credential_ref in entries:
        if principal_id not in authorized:
            raise ValueError(
                f"principal {principal_id!r} is not an authorized active-scan principal"
            )
        key = (principal_id, auth_mode)
        if key in seen:
            raise ValueError(f"duplicate matrix cell for {key!r}")
        seen.add(key)
        cells.append(
            AuthCell(
                principal_id=principal_id,
                auth_mode=auth_mode,
                credential_marker=_credential_marker(auth_mode, credential_ref),
            )
        )

    cells.sort(key=lambda c: (c.principal_id, c.auth_mode))
    canonical = json.dumps(
        [[c.principal_id, c.auth_mode, c.credential_marker] for c in cells],
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return AuthenticationMatrix(
        cells=tuple(cells), matrix_sha256=hashlib.sha256(canonical).hexdigest()
    )


__all__ = ["AuthCell", "AuthenticationMatrix", "build_auth_matrix"]
