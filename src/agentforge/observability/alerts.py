"""O3 alerting interfaces (ARCHITECTURE.md §9 alerting). STDLIB-ONLY, no network.

The six mandated O3 alert kinds fire on: a human-approval gate pending (with an SLA), a
regression detected / finding reopened, the budget circuit breaker tripping, a target
unreachable beyond backoff, queue depth over threshold, and an emission failure (Langfuse/DB
write failed). The defining property (O3): an alert is tied to the DURABLE source — the
exploit DB or the work queue — NOT to Langfuse alone. So an observability outage (Langfuse
down) can never SILENCE an alert: even the ``emission_failure`` alert about that very outage
routes through the durable source and is therefore never lost.

This module ships:
  * :class:`AlertKind` — the enumerated kinds (no free-form alert strings);
  * :class:`Alert` — an immutable (kind, source, payload) record;
  * :class:`AlertChannel` — the emit protocol M6b's real webhook/pager channel implements;
  * :class:`CapturingAlertChannel` — a deterministic in-memory channel (NO network) that
    records exactly what was emitted, in order, for tests and dry runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from agentforge.observability.tracing import backstop_provider_keys
from agentforge.secrets import redact_mapping


class AlertKind(Enum):
    """The six mandated O3 alert kinds (§9). Enumerated so no alert is a free-form string."""

    HUMAN_APPROVAL_PENDING = "human_approval_pending"
    REGRESSION_DETECTED = "regression_detected"
    BUDGET_CIRCUIT_BREAKER_TRIPPED = "budget_circuit_breaker_tripped"
    TARGET_UNREACHABLE = "target_unreachable"
    QUEUE_DEPTH_OVER_THRESHOLD = "queue_depth_over_threshold"
    EMISSION_FAILURE = "emission_failure"


@dataclass(frozen=True)
class Alert:
    """One O3 alert: its ``kind``, its DURABLE ``source``, and a synthetic ``payload``.

    ``source`` names the durable origin the alert is tied to (e.g. ``"exploit_db"`` or the work
    queue) — NEVER Langfuse alone, so an observability outage cannot silence it. ``payload`` is
    a free mapping for kind-specific detail (an SLA for a pending approval, a backoff reason for
    an unreachable target, the failing backend for an emission failure). Frozen: an alert record
    is immutable once created.
    """

    kind: AlertKind
    source: str
    payload: dict[str, Any] = field(default_factory=dict)


def redact_alert(alert: Alert) -> Alert:
    """Return a copy of ``alert`` whose payload is SAFE to surface to a human sink.

    §5: raw adversarial content / secrets are NEVER auto-rendered into an alert. The payload is
    passed through :func:`agentforge.secrets.redact_mapping` (masks a ``Secret`` value and any
    value under a sensitive-looking key) and then the provider-key backstop
    (:func:`~agentforge.observability.tracing.backstop_provider_keys`, which masks a bare,
    unwrapped ``sk-…``-style token under an innocuous key) — so no credential can leak even
    though an alert routes to a durable, human-facing destination. The ``kind`` and durable
    ``source`` are structural and pass through unchanged.
    """
    safe_payload = backstop_provider_keys(redact_mapping(alert.payload))
    return Alert(kind=alert.kind, source=alert.source, payload=safe_payload)


@runtime_checkable
class AlertChannel(Protocol):
    """The emit seam. M6b's real webhook/pager channel implements this; the core stays neutral."""

    def emit(self, alert: Alert) -> None: ...


class CapturingAlertChannel:
    """A deterministic, in-memory :class:`AlertChannel` — records emissions in order, no network.

    :meth:`emit` appends the alert to :attr:`captured` (insertion-ordered) and does nothing
    else — no webhook, no socket, no side effect. So a test (or a dry run) sees EXACTLY what was
    emitted, deterministically, without a real notification backend. This is the local stand-in
    for the durable-source-backed channel M6b wires to a real pager.
    """

    def __init__(self) -> None:
        self.captured: list[Alert] = []

    def emit(self, alert: Alert) -> None:
        """Record a REDACTED copy of ``alert`` in emission order (§5 — a raw secret or raw
        adversarial-content string never reaches the stored/human-facing alert). No network, no
        side effect beyond the append."""
        self.captured.append(redact_alert(alert))


__all__ = ["AlertKind", "Alert", "AlertChannel", "CapturingAlertChannel", "redact_alert"]
