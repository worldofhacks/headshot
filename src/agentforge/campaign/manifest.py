"""ManifestStore — IMMUTABLE, content-hashed, redacted run manifests under runs/<run_id>/.

M11-coordinator (ARCHITECTURE.md §5, §9; DECISIONS.md D14/D18). A run's durable record is a set
of immutable manifests written to a run-scoped directory ``<root>/runs/<run_id>/<kind>.json``:

* ``config``   — the immutable run config (redacted: no raw credential reference);
* ``evidence`` — the per-attempt evidence pointer (ids + content_hash + integrity flag, never the
  raw hostile transcript);
* ``verdict``  — the Judge's verdict for the attempt;
* ``abort``    — the abort-state manifest (why the run hard-aborted); and
* ``result``   — the run's terminal result summary.

Every manifest is content-hashed (a canonical sha256 over its payload) and NEVER mutated after
write: attempting to rewrite an existing ``(run_id, kind)`` manifest is a typed
:class:`ManifestImmutableError` (append/replace-forbidden). Diagnostics are QUARANTINED and
REDACTED before write — no raw secret, and no raw hostile/adversarial content (canary tokens,
injected instructions), is ever serialized to disk. Redaction is applied through
:func:`~agentforge.secrets.redact_mapping` (Secret + sensitive-key masking) PLUS a caller-supplied
set of literal redactions (the synthetic canary, the credential reference, hostile markers) that
are scrubbed from every string value at any depth.

Framework-neutral core: stdlib + secrets only; no web framework, no network.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from agentforge.secrets import redact_mapping

# The fixed marker a scrubbed literal is replaced with (matches the Secret redaction marker so a
# redacted manifest reads consistently).
_REDACTION_MARKER = "***REDACTED***"

# The manifest kinds this store recognizes. A forbidden kind (publication/remediation/regression/
# social) is simply never written by the coordinator — the store does not mint them.
_KNOWN_KINDS: frozenset[str] = frozenset({"config", "evidence", "verdict", "abort", "result"})


class ManifestImmutableError(Exception):
    """Raised when a write would mutate an already-written manifest.

    A written manifest is content-hashed and append/replace-forbidden — a second
    ``write(run_id, kind, ...)`` for an existing ``(run_id, kind)`` is refused with this typed
    error rather than silently overwriting the durable record (immutability, D14).
    """


class ManifestStore:
    """Writes immutable, content-hashed, redacted manifests under ``<root>/runs/<run_id>/``.

    Constructed with ``root`` (a directory path); each manifest lands at
    ``<root>/runs/<run_id>/<kind>.json``. The store holds no credentials and performs no network
    I/O — it only serializes redacted dicts to disk and reads them back.
    """

    def __init__(self, root: Any) -> None:
        self._root = Path(root)

    def _run_dir(self, run_id: str) -> Path:
        return self._root / "runs" / run_id

    def _path(self, run_id: str, kind: str, attempt_id: str | None) -> Path:
        """Run-level manifests (config/result/abort) live at the run root; per-attempt manifests
        (evidence/verdict) live under ``attempts/<attempt_id>/`` so multiple attempts in one run
        never collide on an immutable ``<kind>.json``."""
        if attempt_id is None:
            return self._run_dir(run_id) / f"{kind}.json"
        return self._run_dir(run_id) / "attempts" / attempt_id / f"{kind}.json"

    def write(
        self,
        *,
        run_id: str,
        kind: str,
        payload: Mapping[str, Any],
        attempt_id: str | None = None,
        redactions: Iterable[str] = (),
    ) -> str:
        """Write one immutable, content-hashed, redacted manifest; return its content hash.

        The payload is redacted (Secret/sensitive-key masking + literal ``redactions`` scrub) at
        any depth BEFORE serialization, so no raw secret / raw hostile content lands on disk. A
        canonical content hash of the redacted payload is embedded. A rewrite of an existing
        manifest at the same path raises :class:`ManifestImmutableError` (append/replace-forbidden).
        """
        path = self._path(run_id, kind, attempt_id)
        if path.exists():
            raise ManifestImmutableError(
                f"manifest {kind!r} for run {run_id!r} already exists at {path} — a written "
                "manifest is immutable and may never be rewritten (append/replace-forbidden, D14)"
            )
        literals = tuple(r for r in redactions if isinstance(r, str) and r)
        redacted = _scrub_literals(redact_mapping(dict(payload)), literals)
        content_hash = _canonical_hash(redacted)
        document = {
            "kind": kind,
            "run_id": run_id,
            "attempt_id": attempt_id,
            "content_hash": content_hash,
            "payload": redacted,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(document, sort_keys=True, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return content_hash

    def kinds_written(self, run_id: str) -> list[str]:
        """Return the sorted, de-duplicated kinds of manifest written for ``run_id`` (recursive).

        Recurses into per-attempt subdirectories, so a per-attempt ``evidence``/``verdict``
        manifest still surfaces its kind at the run level (empty list if the run has none).
        """
        run_dir = self._run_dir(run_id)
        if not run_dir.is_dir():
            return []
        return sorted({path.stem for path in run_dir.rglob("*.json")})

    def read_all(self, run_id: str) -> list[str]:
        """Return the raw text of every manifest file written for ``run_id`` (recursive)."""
        run_dir = self._run_dir(run_id)
        if not run_dir.is_dir():
            return []
        return [path.read_text(encoding="utf-8") for path in sorted(run_dir.rglob("*.json"))]


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    """Canonical sha256 hex digest of a redacted manifest payload (order-independent)."""
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _scrub_literals(value: Any, literals: tuple[str, ...]) -> Any:
    """Recursively replace any occurrence of a sensitive ``literal`` in a string with the marker.

    Applied at any depth after :func:`redact_mapping`, this scrubs caller-supplied literals — the
    synthetic canary token, the credential reference, and hostile-instruction markers — so no raw
    secret and no raw adversarial content survives into a manifest string.
    """
    if not literals:
        return value
    if isinstance(value, str):
        scrubbed = value
        for literal in literals:
            if literal in scrubbed:
                scrubbed = scrubbed.replace(literal, _REDACTION_MARKER)
        return scrubbed
    if isinstance(value, Mapping):
        return {k: _scrub_literals(v, literals) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        scrubbed_items = [_scrub_literals(item, literals) for item in value]
        return tuple(scrubbed_items) if isinstance(value, tuple) else scrubbed_items
    return value
