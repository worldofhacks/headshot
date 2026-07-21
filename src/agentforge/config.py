"""Environment-separated settings + the O1 environment-isolation invariant.

spec(M1a:AC-2) spec(M1a:AC-5/O1)

This is framework-neutral core (ARCHITECTURE.md §12, DECISIONS.md D10): it imports
**no** web framework, no orchestration framework, and no secret manager. It models only:

* the deployment ``environment`` — an enumerated set {local, staging, production}
  (default ``local``), never free text; and
* ``resolve_target_credential`` — which, in *production*, returns a **secret reference
  string** (a lookup handle such as ``secretref://production/<target_id>``, never an
  inline secret) and, in *local*/*staging*, **refuses** by raising
  ``EnvironmentIsolationError``.

The refusal is the non-deferrable O1 invariant: a non-production box must never be able
to resolve a *production* live-target credential. The boundary is decided purely by the
``environment`` dimension — identical target ids resolve in production and refuse
everywhere else.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# The enumerated deployment environments. This is the *only* place the set is defined;
# widening it is a deliberate change, never an accident of a typo'd string.
_ALLOWED_ENVIRONMENTS: frozenset[str] = frozenset({"local", "staging", "production"})

# Only this environment may resolve production target credentials (O1).
_PRODUCTION = "production"


class EnvironmentIsolationError(Exception):
    """Raised when a non-production config attempts to resolve a production credential.

    A dedicated, catchable type so callers can distinguish a *policy refusal* (the O1
    isolation boundary doing its job) from an incidental bug.
    """


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings, keyed on the deployment ``environment``.

    ``environment`` defaults to ``local`` and is constrained to the enumerated set; an
    unknown value is rejected at construction time rather than silently becoming a fourth
    environment.
    """

    environment: str = field(default="local")

    def __post_init__(self) -> None:
        if self.environment not in _ALLOWED_ENVIRONMENTS:
            allowed = ", ".join(sorted(_ALLOWED_ENVIRONMENTS))
            raise ValueError(
                f"unknown environment {self.environment!r}; expected one of: {allowed}"
            )

    def resolve_target_credential(self, target_id: str) -> str:
        """Return a secret *reference* for ``target_id`` — production only (O1 invariant).

        In production this yields a lookup handle keyed to the target, e.g.
        ``secretref://production/<target_id>`` — a reference the secret manager
        dereferences at use time, **never** an inline secret value. In local/staging it
        raises :class:`EnvironmentIsolationError` and returns nothing at all: a
        non-production config must not be able to reach production target credentials.
        """
        if self.environment != _PRODUCTION:
            raise EnvironmentIsolationError(
                f"environment {self.environment!r} may not resolve production target "
                f"credentials (requested target_id={target_id!r}); only "
                f"{_PRODUCTION!r} is permitted (O1 isolation invariant)"
            )
        return f"secretref://{_PRODUCTION}/{target_id}"
