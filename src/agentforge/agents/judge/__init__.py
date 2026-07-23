"""The independent Judge (ARCHITECTURE.md §3/§5, DECISIONS.md D13/D18, F1, S4).

The Judge is a **pure evaluator**: it consumes a typed
:class:`~agentforge.agents.judge.envelope.EvidenceEnvelopeBuilder` output (the
``evidence_envelope.json`` contract) and emits a ``verdict.json``-valid dict and NOTHING
else. It holds no credentials, no mutation tools, no publish authority, and executes no
actions — its only capability is :meth:`Judge.evaluate`. This is the D13 separation: an agent
that can *act* cannot be an independent judge.

Precedence is deterministic and applied in CODE, outside any model, reading ONLY the trusted
signals — never the hostile transcript. At MVP the LLM path is NOT wired, so the disposition
set is exactly ``{EXPLOIT_CONFIRMED, INDETERMINATE, ERROR}``; the LLM-only states
``EXPLOIT_LIKELY`` / ``NO_EXPLOIT_OBSERVED`` are never produced by the deterministic Judge.

OFFLINE: no hosted-model call, no network, no side effect — evaluating an envelope is pure.
"""

from __future__ import annotations

from agentforge.agents.judge.calibration import (
    CalibrationGate,
    CalibrationGateClosed,
    CalibrationInputError,
    CalibrationThresholds,
    JudgeIdentity,
)
from agentforge.agents.judge.judge import Judge, is_safe

__all__ = [
    "Judge",
    "is_safe",
    "CalibrationGate",
    "CalibrationGateClosed",
    "CalibrationInputError",
    "CalibrationThresholds",
    "JudgeIdentity",
]
