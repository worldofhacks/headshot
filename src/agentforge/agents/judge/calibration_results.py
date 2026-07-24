"""Validated adapter for previously captured hosted-evaluator calibration outcomes.

This module performs no provider call.  It accepts an operator-supplied result bundle only when
the bundle has complete OpenRouter lineage, exact identity/configuration bindings, and exactly
one assessment for every selected ground-truth label.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from agentforge.agents.judge.calibration import CalibrationInputError, JudgeIdentity
from agentforge.contracts import validate

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024
_IDENTITY_FIELDS = frozenset(
    {
        "judge_provider",
        "judge_model",
        "judge_model_version",
        "criteria_version",
        "implementation_version",
        "red_team_provider",
        "red_team_model",
    }
)
_BUNDLE_FIELDS = frozenset({"schema_version", "judge_identity", "provenance", "samples"})
_PROVENANCE_FIELDS = frozenset(
    {
        "capture_kind",
        "configuration_sha256",
        "role_configuration_sha256",
        "generation_policy_sha256",
        "requested_model",
        "returned_model",
        "captured_at",
    }
)
_SAMPLE_FIELDS = frozenset(
    {
        "label_id",
        "assessment",
        "provider_request_id",
        "trace_id",
        "returned_model",
        "input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "measured_cost_usd",
    }
)
_ASSESSMENT_FIELDS = frozenset({"state", "confidence", "rationale", "criteria_hits", "error_code"})
_ASSESSMENT_STATES = frozenset({"EXPLOIT_LIKELY", "NO_EXPLOIT_OBSERVED", "INDETERMINATE", "ERROR"})


class CapturedCalibrationEvaluator:
    """Expose traced, pre-captured model assessments through the calibration protocol."""

    def __init__(self, samples_by_label: Mapping[str, Mapping[str, Any]]) -> None:
        self._samples = copy.deepcopy(dict(samples_by_label))

    def evaluate(
        self,
        envelope: Mapping[str, Any],
        *,
        integrity_ok: bool = True,
    ) -> dict[str, Any]:
        if integrity_ok is not True:
            raise CalibrationInputError("captured calibration evidence integrity is not verified")
        try:
            label_id = envelope["trusted"]["ground_truth_ref"]
            sample = self._samples[label_id]
        except (KeyError, TypeError) as exc:
            raise CalibrationInputError(
                "captured calibration assessment has no matching ground-truth label"
            ) from exc
        assessment = sample["assessment"]
        state = assessment["state"]
        reason = {
            "EXPLOIT_LIKELY": "calibrated_positive",
            "NO_EXPLOIT_OBSERVED": "calibrated_negative",
            "INDETERMINATE": "uncertainty_band",
            "ERROR": "evidence_missing",
        }[state]
        verdict: dict[str, Any] = {
            "schema_version": "1",
            "campaign_run_id": envelope["campaign_run_id"],
            "attempt_id": envelope["attempt_id"],
            "state": state,
            "confidence": assessment["confidence"],
            "reason_codes": [reason],
        }
        if state in {"EXPLOIT_LIKELY", "NO_EXPLOIT_OBSERVED"}:
            verdict["confirmation_source"] = "calibrated_model"
        if assessment["criteria_hits"]:
            verdict["criteria_hits"] = list(assessment["criteria_hits"])
        if state == "ERROR":
            verdict["error_code"] = assessment["error_code"]
        try:
            validate("verdict", verdict)
        except Exception as exc:
            raise CalibrationInputError(
                "captured calibration assessment cannot produce a valid verdict"
            ) from exc
        return verdict


def load_judge_identity(path: str | Path) -> JudgeIdentity:
    """Load an explicit expected identity file; never infer identity from model results."""

    payload = _read_json(path, maximum_bytes=32 * 1024, label="Judge identity")
    if not isinstance(payload, Mapping) or set(payload) != _IDENTITY_FIELDS:
        raise CalibrationInputError("Judge identity file has an invalid shape")
    try:
        identity = JudgeIdentity(**dict(payload))
        identity.payload()
        return identity
    except (TypeError, CalibrationInputError) as exc:
        raise CalibrationInputError("Judge identity file has invalid fields") from exc


def load_captured_calibration_evaluator(
    path: str | Path,
    *,
    expected_identity: JudgeIdentity,
    expected_label_ids: Sequence[str],
) -> CapturedCalibrationEvaluator:
    """Validate one offline hosted result bundle and return its read-only evaluator."""

    raw = _read_json(path, maximum_bytes=_MAX_BUNDLE_BYTES, label="captured calibration")
    if not isinstance(raw, Mapping) or set(raw) != _BUNDLE_FIELDS:
        raise CalibrationInputError("captured calibration bundle has an invalid shape")
    if raw["schema_version"] != "1":
        raise CalibrationInputError("captured calibration schema version is unsupported")
    identity = expected_identity.payload()
    if raw["judge_identity"] != identity:
        raise CalibrationInputError("captured calibration Judge identity does not match expected")
    provenance = raw["provenance"]
    if not isinstance(provenance, Mapping) or set(provenance) != _PROVENANCE_FIELDS:
        raise CalibrationInputError("captured calibration provenance has an invalid shape")
    _validate_provenance(provenance, identity=identity)

    if isinstance(expected_label_ids, (str, bytes)):
        raise CalibrationInputError("expected calibration labels are invalid")
    labels = list(expected_label_ids)
    if not labels or any(not isinstance(label, str) or not label for label in labels):
        raise CalibrationInputError("expected calibration labels are invalid")
    if len(labels) != len(set(labels)):
        raise CalibrationInputError("expected calibration labels are duplicated")
    samples = raw["samples"]
    if not isinstance(samples, list):
        raise CalibrationInputError("captured calibration samples must be an array")
    indexed: dict[str, Mapping[str, Any]] = {}
    for sample in samples:
        validated = _validate_sample(
            sample,
            returned_model=provenance["returned_model"],
        )
        label_id = validated["label_id"]
        if label_id in indexed:
            raise CalibrationInputError("captured calibration label is duplicated")
        indexed[label_id] = validated
    if set(indexed) != set(labels):
        raise CalibrationInputError(
            "captured calibration labels do not exactly cover the selected ground truth"
        )
    return CapturedCalibrationEvaluator(indexed)


def _validate_provenance(
    provenance: Mapping[str, Any],
    *,
    identity: Mapping[str, str],
) -> None:
    if provenance["capture_kind"] != "openrouter_hosted_evaluator":
        raise CalibrationInputError("captured calibration source is not a hosted evaluator")
    if not identity["judge_provider"].startswith("openrouter:"):
        raise CalibrationInputError("expected Judge identity is not an OpenRouter provider")
    for field in (
        "configuration_sha256",
        "role_configuration_sha256",
        "generation_policy_sha256",
    ):
        value = provenance[field]
        if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
            raise CalibrationInputError("captured calibration configuration hash is invalid")
    if provenance["role_configuration_sha256"] != identity["judge_model_version"]:
        raise CalibrationInputError(
            "captured calibration role configuration does not match Judge identity"
        )
    if provenance["requested_model"] != identity["judge_model"]:
        raise CalibrationInputError(
            "captured calibration requested model does not match Judge identity"
        )
    _require_text(provenance["returned_model"], label="returned model", maximum=200)
    captured_at = _require_text(
        provenance["captured_at"],
        label="capture timestamp",
        maximum=64,
    )
    try:
        parsed = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CalibrationInputError("captured calibration timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise CalibrationInputError("captured calibration timestamp must include a timezone")


def _validate_sample(
    sample: object,
    *,
    returned_model: str,
) -> Mapping[str, Any]:
    if not isinstance(sample, Mapping) or set(sample) != _SAMPLE_FIELDS:
        raise CalibrationInputError("captured calibration sample has an invalid shape")
    candidate = copy.deepcopy(dict(sample))
    _require_text(candidate["label_id"], label="label identifier", maximum=160)
    if candidate["returned_model"] != returned_model:
        raise CalibrationInputError("captured calibration returned-model identity is inconsistent")
    _require_text(
        candidate["provider_request_id"],
        label="provider request identifier",
        maximum=256,
    )
    _require_text(candidate["trace_id"], label="trace identifier", maximum=256)
    for field in ("input_tokens", "output_tokens", "reasoning_tokens"):
        value = candidate[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CalibrationInputError("captured calibration token usage is invalid")
    cost = candidate["measured_cost_usd"]
    if isinstance(cost, bool) or not isinstance(cost, (int, float, str)):
        raise CalibrationInputError("captured calibration measured cost is invalid")
    try:
        measured_cost = Decimal(str(cost))
    except InvalidOperation as exc:
        raise CalibrationInputError("captured calibration measured cost is invalid") from exc
    if not measured_cost.is_finite() or measured_cost < 0:
        raise CalibrationInputError("captured calibration measured cost is invalid")
    candidate["assessment"] = _validate_assessment(candidate["assessment"])
    return candidate


def _validate_assessment(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _ASSESSMENT_FIELDS:
        raise CalibrationInputError("captured calibration assessment has an invalid shape")
    state = value["state"]
    if state not in _ASSESSMENT_STATES:
        raise CalibrationInputError("captured calibration assessment state is invalid")
    confidence = value["confidence"]
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= float(confidence) <= 1
    ):
        raise CalibrationInputError("captured calibration confidence is invalid")
    rationale = _require_text(value["rationale"], label="assessment rationale", maximum=4_000)
    criteria = value["criteria_hits"]
    if not isinstance(criteria, list) or len(criteria) > 32:
        raise CalibrationInputError("captured calibration criteria are invalid")
    validated_criteria = [
        _require_text(item, label="assessment criterion", maximum=120) for item in criteria
    ]
    if len(validated_criteria) != len(set(validated_criteria)):
        raise CalibrationInputError("captured calibration criteria are invalid")
    error_code = value["error_code"]
    if state == "ERROR":
        error_code = _require_text(error_code, label="assessment error code", maximum=120)
    elif error_code is not None:
        raise CalibrationInputError("captured non-error assessment cannot include an error code")
    return {
        "state": state,
        "confidence": float(confidence),
        "rationale": rationale,
        "criteria_hits": validated_criteria,
        "error_code": error_code,
    }


def _require_text(value: object, *, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(
            ord(character) < 32 and character not in "\n\t" or ord(character) == 127
            for character in value
        )
    ):
        raise CalibrationInputError(f"captured calibration {label} is invalid")
    return value


def _read_json(path: str | Path, *, maximum_bytes: int, label: str) -> object:
    try:
        configured = Path(path)
        with configured.open("rb") as handle:
            encoded = handle.read(maximum_bytes + 1)
    except (TypeError, OSError) as exc:
        raise CalibrationInputError(f"{label} file is unavailable") from exc
    if len(encoded) > maximum_bytes:
        raise CalibrationInputError(f"{label} file exceeds its size bound")
    try:
        return json.loads(
            encoded.decode("utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise CalibrationInputError(f"{label} file is not valid JSON") from exc


__all__ = [
    "CapturedCalibrationEvaluator",
    "load_captured_calibration_evaluator",
    "load_judge_identity",
]
