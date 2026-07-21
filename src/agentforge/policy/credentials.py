"""Scoped credential binding — a Secret-wrapped reference bound to ONE target (§5.3 #7).

A :class:`CredentialBinding` ties a target id to a secret *reference* (never an inline
value). Resolving it goes through :meth:`Settings.resolve_target_credential`, which in
local/staging RAISES :class:`EnvironmentIsolationError` (the O1 isolation invariant) and in
production returns a ``secretref://production/<id>`` handle — which this module wraps in a
:class:`Secret` so it never renders raw in a log, error, or evidence record.

Two structural guarantees:

* A binding for target A can NEVER yield target B's credential — a mismatched ``target_id``
  is refused with a ``ValueError`` BEFORE any resolve is attempted (cross-target use is
  impossible by construction).
* The raw reference is only ever held inside a :class:`Secret`; :meth:`reveal` is the sole
  way out, called only at the authorized use boundary — never inlined or logged.

Framework-neutral core (D10): imports config + secrets only, no framework.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentforge.config import Settings
from agentforge.secrets import Secret


@dataclass(frozen=True)
class CredentialBinding:
    """A scoped binding of one ``target_id`` to its secret reference.

    Frozen so the (target_id, secret_ref) pair cannot be mutated to point at another target
    after construction — the scope is immutable.
    """

    target_id: str
    secret_ref: str

    def resolve(self, target_id: str, settings: Settings) -> Secret:
        """Resolve this binding's credential for ``target_id`` as a :class:`Secret`.

        Ordering (defense-in-depth):

        1. **Scope check FIRST** — if ``target_id`` is not this binding's target, raise
           ``ValueError`` immediately. This runs before any environment reasoning, so a
           mismatched target is refused even in production (target A's binding can never
           surface target B's credential).
        2. Delegate to :meth:`Settings.resolve_target_credential`, which enforces O1: it
           raises :class:`EnvironmentIsolationError` in local/staging (a non-prod box can
           never reach a live credential) and only in production returns a secret *reference*
           string, which is wrapped in a :class:`Secret` before it is returned.
        """
        if target_id != self.target_id:
            raise ValueError(
                f"credential binding for target {self.target_id!r} refuses to resolve a "
                f"credential for a different target {target_id!r} (cross-target use is "
                "forbidden, §5.3 #7)"
            )
        reference = settings.resolve_target_credential(target_id)
        return Secret(reference)
