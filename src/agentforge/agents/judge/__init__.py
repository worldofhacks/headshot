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
    ACCEPTED_MODEL_JUDGE_THRESHOLDS,
    STRICT_THRESHOLDS,
    THRESHOLD_POLICIES,
    CalibrationGate,
    CalibrationGateClosed,
    CalibrationInputError,
    CalibrationThresholds,
    JudgeIdentity,
    resolve_threshold_policy,
)
from agentforge.agents.judge.calibration_runtime import (
    JudgeCalibrationStatus,
    load_judge_calibration_status,
)
from agentforge.agents.judge.enablement import require_model_judge_enablement
from agentforge.agents.judge.judge import Judge, is_safe

_HOSTED_EXPORTS = frozenset(
    {
        "HostedEvaluator",
        "HostedEvaluatorError",
        "HostedEvaluatorResult",
        "JudgeReconciliation",
        "reconcile_judge_assessment",
    }
)


def __getattr__(name: str):
    """Load hosted evaluator symbols lazily to avoid a hosted-runtime import cycle."""

    if name not in _HOSTED_EXPORTS:
        raise AttributeError(name)
    from agentforge.agents.judge import hosted

    return getattr(hosted, name)


__all__ = [
    "Judge",
    "is_safe",
    "CalibrationGate",
    "CalibrationGateClosed",
    "CalibrationInputError",
    "CalibrationThresholds",
    "ACCEPTED_MODEL_JUDGE_THRESHOLDS",
    "STRICT_THRESHOLDS",
    "THRESHOLD_POLICIES",
    "resolve_threshold_policy",
    "JudgeIdentity",
    "require_model_judge_enablement",
    "JudgeCalibrationStatus",
    "load_judge_calibration_status",
    "HostedEvaluator",
    "HostedEvaluatorError",
    "HostedEvaluatorResult",
    "JudgeReconciliation",
    "reconcile_judge_assessment",
]
