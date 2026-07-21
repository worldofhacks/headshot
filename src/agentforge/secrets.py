"""Redacted-secret type + redaction helpers — defense-in-depth so secrets never leak.

Framework-neutral core (ARCHITECTURE.md §12, DECISIONS.md D10): stdlib only, no web
framework and no secret manager. This module is the FOUNDATION that later milestones
(M4/M8/M9) build on to hold provider/target credentials as :class:`Secret` values and to
redact structured logs. ``Settings`` holds no secret fields today (only ``environment``),
so there is nothing in ``Settings`` itself to redact yet — this is the primitive those
milestones will reach for.

The primary control is *representational*: a secret is wrapped in a type whose every
stringifying dunder (``__repr__`` / ``__str__`` / ``__format__``) returns a fixed redaction
marker and NEVER the raw value, so f-strings, ``%``-format, ``str()``, ``repr()``, logging,
error messages, and tracebacks all redact automatically. :func:`redact_mapping` is the
structured-logging companion. :func:`looks_like_provider_key` is a SECONDARY backstop only.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# Fixed redaction markers. ``str``/``format`` yield the short marker so it composes cleanly
# inside larger strings and logs; ``repr`` wraps it so a bare ``repr`` still reads as a Secret.
_STR_MARKER = "***REDACTED***"
_REPR_MARKER = f"Secret({_STR_MARKER})"

# Substrings that, when found in a lowercased key name, mark that key's value as sensitive.
_SENSITIVE_KEY_HINTS: tuple[str, ...] = (
    "key",
    "token",
    "secret",
    "password",
    "cookie",
    "credential",
    "authorization",
    "api_key",
)

# Known provider key prefixes for the SECONDARY backstop (see ``looks_like_provider_key``).
_PROVIDER_KEY_PREFIXES: tuple[str, ...] = (
    "sk-ant-",
    "sk-or-",
    "sk-proj-",
    "sk-",
)


class Secret:
    """A wrapper around a raw string whose stringified forms ALWAYS redact.

    ``repr``, ``str``, and ``format`` (hence f-strings, ``%``-format, logging, error
    messages, and tracebacks) return a fixed redaction marker and NEVER the raw value.
    :meth:`reveal` is the ONLY way to obtain the raw value and is intended to be called
    solely by the component authorized to use the credential, at the call boundary.

    Equality compares the wrapped values without exposing them; ``__hash__`` is consistent
    with equality; ``__bool__`` reflects the wrapped value's truthiness.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """Return the raw wrapped value — the ONLY way out. Use at the authorized boundary."""
        return self._value

    def __repr__(self) -> str:
        return _REPR_MARKER

    def __str__(self) -> str:
        return _STR_MARKER

    def __format__(self, spec: str) -> str:
        # Ignore the format spec entirely so no width/precision trick can surface the value.
        return _STR_MARKER

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)


def redact_mapping(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``data`` safe to log: mask Secret values and sensitive-looking keys.

    Use this before logging any settings/config mapping — "never log a complete config
    object". Redaction is **deep**: it recurses into nested mappings and into lists / tuples
    / sets, so a :class:`Secret` or a value under a sensitive key is masked **at any depth**.
    A value is redacted when either:

    * it is a :class:`Secret` (replaced by its redaction marker), OR
    * its key's lowercased name contains a sensitive hint (``key``, ``token``, ``secret``,
      ``password``, ``cookie``, ``credential``, ``authorization``, ``api_key``) — in which
      case its whole value is masked regardless of shape (a sensitive sub-map is not walked
      into and partially exposed; it is masked wholesale).

    Non-sensitive keys pass through, recursing so nested sensitive material is still caught.
    The original mapping is **not** mutated (a new structure is returned).

    Limitation (honest): redaction is **key-and-type** based. A *bare* secret string that is
    neither a :class:`Secret` nor placed under a sensitive key — e.g. a raw token sitting as a
    plain list element under an innocuous key — has no signal to key off and passes through.
    The remedy is representational: wrap credentials in :class:`Secret` at the boundary they
    enter the process. :func:`looks_like_provider_key` is only a secondary backstop for a
    stray unwrapped key, not a substitute for this.
    """
    return {key: _redact_value(key, value) for key, value in data.items()}


def _redact_value(key: Any, value: Any) -> Any:
    """Redact one ``value`` given its ``key`` (``None`` for a container element with no key)."""
    # A sensitive KEY masks its entire value, regardless of shape or depth — a sensitive
    # sub-structure is never walked into and partially surfaced.
    if _is_sensitive_key(key):
        return _STR_MARKER
    # A Secret always redacts (belt-and-suspenders; its own repr redacts too).
    if isinstance(value, Secret):
        return _STR_MARKER
    # Recurse into nested containers so a sensitive key / Secret at any depth is caught.
    if isinstance(value, Mapping):
        return {k: _redact_value(k, v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        # Elements carry no key of their own, so pass key=None and let recursion catch any
        # nested mappings/Secrets. A set is returned as a list (redaction markers would
        # otherwise collapse, and dicts are unhashable) — order is irrelevant for a log copy.
        redacted_items = [_redact_value(None, item) for item in value]
        return tuple(redacted_items) if isinstance(value, tuple) else redacted_items
    return value


def _is_sensitive_key(key: Any) -> bool:
    """True if ``key`` names a sensitive value. Non-str keys are never treated as sensitive."""
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    return any(hint in lowered for hint in _SENSITIVE_KEY_HINTS)


def looks_like_provider_key(s: str) -> bool:
    """Heuristically detect a known provider key by prefix. SECONDARY control ONLY.

    Prefix matching is a BACKSTOP, not the primary control — the primary control is the
    :class:`Secret` type and the redaction tests, which prevent leakage regardless of a
    value's shape. This helper exists only to catch a stray raw key that slipped in
    unwrapped. It never raises; a non-string or non-matching input returns ``False``.

    Detects the ``sk-``, ``sk-or-``, ``sk-ant-``, and ``sk-proj-`` prefixes, plus a
    Together-style long-hex heuristic.
    """
    if not isinstance(s, str):
        return False
    if any(s.startswith(prefix) for prefix in _PROVIDER_KEY_PREFIXES):
        return True
    # Together-style keys are long lowercase-hex strings with no separators.
    stripped = s.strip()
    return len(stripped) >= 40 and all(c in "0123456789abcdef" for c in stripped)
