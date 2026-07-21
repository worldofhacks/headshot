"""The Evidence Envelope builder (S4 / DECISIONS.md D18, ARCHITECTURE.md §4/§5).

The Evidence Envelope is the Judge's ONLY input. It carries an explicit trust label per
field so the containment invariant is structural, not conventional:

* **trusted** signals (``oracle_results`` / ``canary_hits``) are code/human-populated
  deterministic signals; the schema restricts their ``provenance`` to ``code`` or ``human``
  and FORBIDS ``hostile``. This builder mirrors that guard: it refuses to place any
  hostile-sourced signal into a trusted field, raising rather than emitting an envelope the
  schema would reject. That is how attacker-controlled content is prevented from
  manufacturing an oracle/canary "hit".
* **hostile** carries the attacker-controlled ``transcript`` as inert DATA (``trust:'hostile'``).
  It is size-bounded to the schema's ``maxLength`` (200000): a transcript over the bound is
  TRUNCATED and ``truncated=True`` is recorded, so a flooding payload can never exhaust the
  Judge. The transcript is never parsed for a disposition, rubric, or confidence.

Every envelope this builder emits is validated against ``evidence_envelope.json`` through the
contract registry before it is returned — a malformed envelope never leaves the builder.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agentforge.contracts import validate

# The schema's transcript bound (evidence_envelope.json -> hostile.transcript.maxLength). Kept
# in sync with the contract; a transcript longer than this is truncated to it.
MAX_TRANSCRIPT = 200_000

# The ONLY provenance labels a trusted signal may carry (evidence_envelope.json ->
# trusted_signal.provenance). 'hostile' is deliberately excluded: hostile-sourced content can
# never populate a trusted field. The builder enforces this before the schema ever sees it.
_ALLOWED_TRUSTED_PROVENANCE: frozenset[str] = frozenset({"code", "human"})


class EvidenceEnvelopeBuilder:
    """Constructs an ``evidence_envelope.json``-valid dict from an attempt's ids + transcript
    plus code-run oracle/canary signals.

    The builder is the containment boundary between attacker-controlled data (the transcript)
    and the trusted signals the Judge's precedence reads. It never accepts hostile-sourced
    content into a trusted field, and it bounds the transcript so a flood cannot exhaust the
    Judge. It holds no credentials and performs no I/O — it only shapes and validates a dict.
    """

    def build(
        self,
        *,
        campaign_run_id: str,
        attempt_id: str,
        transcript: str,
        oracle_results: Iterable[Mapping[str, Any]],
        canary_hits: Iterable[Mapping[str, Any]],
        policy_decision: str,
        campaign_id: str | None = None,
        expected_safe_behavior: str | None = None,
        ground_truth_ref: str | None = None,
    ) -> dict[str, Any]:
        """Build and validate an Evidence Envelope.

        ``oracle_results`` / ``canary_hits`` are code/human-populated trusted signals; each is
        vetted so a ``provenance`` of ``hostile`` (or anything but ``code``/``human``) is
        REFUSED with a ``ValueError`` — the builder never emits an envelope the schema would
        reject and never lets hostile content manufacture a trusted hit.

        ``transcript`` is carried as inert hostile data, truncated to ``MAX_TRANSCRIPT`` with
        ``truncated=True`` recorded when it exceeds the bound.
        """
        trusted: dict[str, Any] = {
            "oracle_results": [
                self._vet_trusted_signal(sig, kind="oracle_result") for sig in oracle_results
            ],
            "canary_hits": [
                self._vet_trusted_signal(sig, kind="canary_hit") for sig in canary_hits
            ],
            "policy_decision": policy_decision,
        }
        if expected_safe_behavior is not None:
            trusted["expected_safe_behavior"] = expected_safe_behavior
        if ground_truth_ref is not None:
            trusted["ground_truth_ref"] = ground_truth_ref

        bounded, truncated = self._bound_transcript(transcript)
        hostile: dict[str, Any] = {
            "trust": "hostile",
            "transcript": bounded,
            "truncated": truncated,
        }

        env: dict[str, Any] = {
            "schema_version": "1",
            "campaign_run_id": campaign_run_id,
            "attempt_id": attempt_id,
            "trusted": trusted,
            "hostile": hostile,
        }
        if campaign_id is not None:
            env["campaign_id"] = campaign_id

        # A malformed envelope never leaves the builder — validate through the registry.
        validate("evidence_envelope", env)
        return env

    @staticmethod
    def _vet_trusted_signal(signal: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
        """Copy ``signal`` into a trusted-field shape, refusing any non-code/human provenance.

        A trusted signal MUST originate from a deterministic code oracle or a human — never
        from the hostile transcript. A ``provenance`` outside ``{code, human}`` (in particular
        ``hostile``) is a containment breach: the builder raises rather than smuggling
        attacker-controlled content into a field the Judge trusts.
        """
        if not isinstance(signal, Mapping):
            raise TypeError(f"{kind} must be a mapping, got {type(signal).__name__}")
        provenance = signal.get("provenance")
        if provenance not in _ALLOWED_TRUSTED_PROVENANCE:
            raise ValueError(
                f"{kind} has provenance {provenance!r}; a trusted signal may only be "
                f"'code' or 'human' — hostile-sourced content can never populate a trusted "
                f"field (S4 containment)"
            )
        vetted: dict[str, Any] = {
            "id": signal["id"],
            "provenance": provenance,
            "hit": signal["hit"],
        }
        if "detail" in signal:
            vetted["detail"] = signal["detail"]
        return vetted

    @staticmethod
    def _bound_transcript(transcript: str) -> tuple[str, bool]:
        """Return ``(bounded_transcript, truncated)`` — a transcript over the schema bound is
        truncated to ``MAX_TRANSCRIPT`` so a flooding payload can never exhaust the Judge."""
        if len(transcript) > MAX_TRANSCRIPT:
            return transcript[:MAX_TRANSCRIPT], True
        return transcript, False
