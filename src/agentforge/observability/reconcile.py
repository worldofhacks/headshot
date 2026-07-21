"""S9 evidence-hash reconciliation (ARCHITECTURE.md §9). STDLIB-ONLY, no network.

The invariant (S9): the authoritative content hash is the ``attempt_result``'s
``content_hash``. A span carries a ``transcript_hash`` that, BY CONSTRUCTION (§9), is the same
hash — so a divergence is *detectable*. When the span's hash diverges from the authoritative
one, the run is marked **DEGRADED**: not trusted, but not blocked/erased either (the evidence
is still readable — divergence is a signal, not a hard stop). Fail-closed: a missing or
malformed hash on EITHER side degrades, never silently passes as OK.

:func:`reconcile` accepts the authoritative side as a raw 64-hex hash OR as an
``attempt_result`` row/mapping (from which it reads ``content_hash``), and the span side as the
span's transcript hash. It returns :class:`ReconcileStatus` — ``OK`` or ``DEGRADED`` only.
There is deliberately NO ``BLOCKED`` member: a divergence degrades, it does not block.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import Enum
from typing import Any

# A well-formed content hash is 64 lowercase hex chars (a SHA-256 hexdigest). Anything else —
# empty, whitespace, wrong length, non-hex — is malformed and fails closed to DEGRADED.
_HASH_RE = re.compile(r"\A[0-9a-f]{64}\Z")


class ReconcileStatus(Enum):
    """The reconciliation outcome. Only OK vs DEGRADED — divergence degrades, never blocks (§9).

    A deliberate absence: there is NO ``BLOCKED`` member. A hash divergence marks the run
    untrusted (DEGRADED) while leaving it readable; it does not erase or hard-block the run.
    """

    OK = "ok"
    DEGRADED = "degraded"


def _normalize_hash(value: Any) -> str | None:
    """Return a well-formed lowercase-hex hash, or ``None`` if missing/malformed (fail-closed).

    Accepts a str; a leading/trailing-whitespace string is stripped first. Anything that is not
    a 64-hex string after stripping (None, empty, whitespace-only, wrong length, non-hex, a
    non-str) returns ``None`` so the caller degrades.
    """
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if not _HASH_RE.match(candidate):
        return None
    return candidate


def _authoritative_hash(source: Any) -> str | None:
    """Extract the authoritative content hash from a row/mapping or a raw hash string.

    * A :class:`~collections.abc.Mapping` (a fetched ``attempt_result`` row) → its
      ``content_hash`` value.
    * An object exposing a ``content_hash`` attribute → that attribute.
    * A plain string → the string itself.

    The extracted value is then normalized (and fails closed to ``None`` if malformed/missing).
    """
    if isinstance(source, Mapping):
        raw = source.get("content_hash")
    elif hasattr(source, "content_hash"):
        raw = source.content_hash
    else:
        raw = source
    return _normalize_hash(raw)


def reconcile(attempt_result_row_or_hash: Any, span_transcript_hash: Any) -> ReconcileStatus:
    """Reconcile the span's transcript hash against the authoritative content hash (S9).

    ``attempt_result_row_or_hash`` is the authoritative side — a raw 64-hex hash, an
    ``attempt_result`` mapping/row, or an object with ``content_hash``. ``span_transcript_hash``
    is the span's transcript hash.

    Returns :attr:`ReconcileStatus.OK` only when BOTH sides are well-formed and EQUAL; returns
    :attr:`ReconcileStatus.DEGRADED` when they diverge OR when either side is missing/malformed
    (fail-closed). Never raises, never blocks — a degraded run is still readable.
    """
    authoritative = _authoritative_hash(attempt_result_row_or_hash)
    span_hash = _normalize_hash(span_transcript_hash)
    if authoritative is None or span_hash is None:
        # Fail-closed: a missing/malformed hash on either side is never trusted as OK.
        return ReconcileStatus.DEGRADED
    if authoritative == span_hash:
        return ReconcileStatus.OK
    # Divergence is detectable (both carry the same hash by construction) → degrade, not block.
    return ReconcileStatus.DEGRADED


__all__ = ["ReconcileStatus", "reconcile"]
