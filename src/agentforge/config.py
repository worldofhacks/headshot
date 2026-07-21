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

import os
import re
from dataclasses import dataclass, field

# The enumerated deployment environments. This is the *only* place the set is defined;
# widening it is a deliberate change, never an accident of a typo'd string.
_ALLOWED_ENVIRONMENTS: frozenset[str] = frozenset({"local", "staging", "production"})

# Only this environment may resolve production target credentials (O1).
_PRODUCTION = "production"

# Env var read by ``Settings.from_env`` to pin the deployment environment (AC-2).
_ENVIRONMENT_ENV_VAR = "AGENTFORGE_ENVIRONMENT"

# Strict, DNS-label-ish target-id grammar: lowercase alnum + hyphen, no leading/trailing
# hyphen, length 1-63. ``\A`` / ``\Z`` anchor the FULL string (NOT ``^``/``$``, which in
# Python match line boundaries and would let an embedded newline slip a bad id past the
# gate). This rejects path traversal, separators, url-encoding, whitespace, control/NUL
# bytes, empties, and over-length ids before any secret reference is constructed (AC-5).
_TARGET_ID_RE = re.compile(r"\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")


class EnvironmentIsolationError(Exception):
    """Raised when a non-production config attempts to resolve a production credential.

    A dedicated, catchable type so callers can distinguish a *policy refusal* (the O1
    isolation boundary doing its job) from an incidental bug.
    """


class InvalidTargetIdError(ValueError):
    """Raised when a ``target_id`` fails the strict identifier grammar (AC-5).

    A ``ValueError`` subclass so a generic ``except ValueError`` still catches it, while a
    dedicated type lets callers distinguish a malformed-id refusal from other failures.
    Raised BEFORE any ``secretref://`` string is built, so an attacker-controlled id (path
    traversal, separators, etc.) never leaks a secret reference.
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

    @classmethod
    def from_env(cls) -> Settings:
        """Construct ``Settings`` from the deployment environment variable (AC-2).

        Reads ``AGENTFORGE_ENVIRONMENT`` (default ``"local"``) so the isolation boundary
        is enforced from the *deployed* environment rather than accidentally-everywhere. An
        un-configured deployment is a fail-safe ``local`` and is therefore isolated from
        production credentials. Construction reuses ``__post_init__`` validation, so an
        unknown value (e.g. the near-miss ``"prod"``) raises ``ValueError`` here.
        """
        cls._load_dotenv()
        return cls(environment=os.environ.get(_ENVIRONMENT_ENV_VAR, "local"))

    @staticmethod
    def _load_dotenv() -> None:
        """Load ``.env.local`` and ``.env`` into the process env so file-provided variables
        are resolvable via ``os.environ``.

        Precedence: a **real process env var wins** over both files; ``.env.local`` wins over
        ``.env``. Enforced with ``override=False`` and loading ``.env.local`` first, so a
        container's real environment (and a test's monkeypatched env) always take priority,
        and a var set by ``.env.local`` is not clobbered by ``.env``.

        ``python-dotenv`` is imported *lazily* here so a bare ``import agentforge.config``
        stays framework-neutral (D10) and does not require the package. Missing files are a
        no-op — a production container sets its environment directly, and ``.env.local`` is
        gitignored (real secrets never enter git). Any secret loaded this way is resolved by
        **reference** at use time (a ``secretref://`` handle or a per-agent client reading
        its own env var) and is **never logged or inlined**.
        """
        try:
            from dotenv import load_dotenv
        except ImportError:  # optional at import; a directly-set environment still works
            return
        load_dotenv(".env.local", override=False)
        load_dotenv(".env", override=False)

    def resolve_target_credential(self, target_id: str) -> str:
        """Return a secret *reference* for ``target_id`` — production only (O1 invariant).

        In production this yields a lookup handle keyed to the target, e.g.
        ``secretref://production/<target_id>`` — a reference the secret manager
        dereferences at use time, **never** an inline secret value. In local/staging it
        raises :class:`EnvironmentIsolationError` and returns nothing at all: a
        non-production config must not be able to reach production target credentials.

        Ordering is defense-in-depth (AC-5): the **environment gate runs FIRST**, so a
        non-prod box refuses on the environment dimension alone and never reasons about
        whether a production target id is well-formed. Only in production is ``target_id``
        validated against the strict :data:`_TARGET_ID_RE` grammar; a malformed id raises
        :class:`InvalidTargetIdError` BEFORE any ``secretref://`` string is built.
        """
        if self.environment != _PRODUCTION:
            raise EnvironmentIsolationError(
                f"environment {self.environment!r} may not resolve production target "
                f"credentials (requested target_id={target_id!r}); only "
                f"{_PRODUCTION!r} is permitted (O1 isolation invariant)"
            )
        if _TARGET_ID_RE.match(target_id) is None:
            raise InvalidTargetIdError(
                f"invalid target_id {target_id!r}: must be a DNS-label-ish identifier "
                "(lowercase alphanumeric and hyphen, no leading/trailing hyphen, "
                "length 1-63)"
            )
        return f"secretref://{_PRODUCTION}/{target_id}"
