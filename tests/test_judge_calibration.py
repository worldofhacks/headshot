"""Versioned Judge calibration, hard false-negative gate, and identity drift invalidation."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agentforge.agents.judge import Judge
from agentforge.agents.judge.calibration import (
    CalibrationGate,
    CalibrationGateClosed,
    CalibrationThresholds,
    JudgeIdentity,
)
from agentforge.contracts import is_valid

GROUND_TRUTH = Path(__file__).resolve().parents[1] / "evals" / "ground-truth"


def _slices() -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8")) for path in sorted(GROUND_TRUTH.glob("*.json"))
    ]


def _identity(**updates: str) -> JudgeIdentity:
    values = {
        "judge_provider": "deterministic-code",
        "judge_model": "oracle-precedence",
        "judge_model_version": "1",
        "criteria_version": "verdict-v1",
        "implementation_version": "judge-v1",
        "red_team_provider": "offline-seed",
        "red_team_model": "seed-replay-v1",
    }
    values.update(updates)
    return JudgeIdentity(**values)


def test_current_deterministic_judge_is_measured_and_fails_non_oracle_gate() -> None:
    result = CalibrationGate(evaluator=Judge()).evaluate(
        slices=_slices(),
        identity=_identity(),
    )

    assert is_valid("judge_calibration", result)
    assert result["state"] == "failed"
    assert result["runtime_enabled"] is False
    assert result["metrics"]["sample_count"] == 15
    assert result["metrics"]["agreement_count"] == 9
    assert result["metrics"]["false_negative_count"] == 3
    assert result["metrics"]["false_positive_count"] == 0
    assert result["metrics"]["abstention_count"] == 9
    assert "false_negative_rate_exceeded" in result["reason_codes"]


class _ExpectedVerdictEvaluator:
    def __init__(self, slices: list[dict]) -> None:
        self.expected = {
            label["label_id"]: copy.deepcopy(label["expected_verdict"])
            for item in slices
            for label in item["labels"]
        }

    def evaluate(self, envelope: dict, *, integrity_ok: bool = True) -> dict:
        assert integrity_ok is True
        return copy.deepcopy(self.expected[envelope["trusted"]["ground_truth_ref"]])


def test_passing_calibration_still_requires_human_enable_and_exact_identity() -> None:
    slices = _slices()
    identity = _identity()
    gate = CalibrationGate(evaluator=_ExpectedVerdictEvaluator(slices))

    result = gate.evaluate(slices=slices, identity=identity)

    assert result["state"] == "passed"
    assert result["human_approved"] is False
    assert result["runtime_enabled"] is False
    enabled = gate.human_enable(
        result,
        current_identity=identity,
        approver_ref="user_security_reviewer",
    )
    assert enabled["human_approved"] is True
    assert enabled["runtime_enabled"] is True
    assert is_valid("judge_calibration", enabled)

    drifted = gate.invalidate_if_drift(
        enabled,
        current_identity=_identity(judge_model_version="2"),
    )
    assert drifted["state"] == "invalidated"
    assert drifted["runtime_enabled"] is False
    assert drifted["human_approved"] is False
    assert drifted["reason_codes"] == ["identity_drift"]


def test_failed_or_same_evaluator_identity_can_never_be_human_enabled() -> None:
    gate = CalibrationGate(evaluator=Judge())
    failed = gate.evaluate(slices=_slices(), identity=_identity())
    with pytest.raises(CalibrationGateClosed, match="passed calibration"):
        gate.human_enable(
            failed,
            current_identity=_identity(),
            approver_ref="user_security_reviewer",
        )

    not_independent = gate.evaluate(
        slices=_slices(),
        identity=_identity(
            red_team_provider="deterministic-code",
            red_team_model="oracle-precedence",
        ),
        thresholds=CalibrationThresholds(
            min_agreement_rate=0,
            max_false_positive_rate=1,
            max_false_negative_rate=1,
            max_expected_calibration_error=1,
            max_abstention_rate=1,
            min_samples_per_category=1,
        ),
    )
    assert not_independent["state"] == "failed"
    assert "evaluator_not_independent" in not_independent["reason_codes"]


class _UnsafeEvaluator:
    def evaluate(self, envelope: dict, *, integrity_ok: bool = True) -> dict:
        return {
            "schema_version": "1",
            "campaign_run_id": envelope["campaign_run_id"],
            "attempt_id": envelope["attempt_id"],
            "state": "NO_EXPLOIT_OBSERVED",
            "confidence": 1.0,
            "reason_codes": ["calibrated_negative"],
        }


def test_confirmed_ground_truth_miss_fails_even_with_permissive_thresholds() -> None:
    result = CalibrationGate(evaluator=_UnsafeEvaluator()).evaluate(
        slices=_slices(),
        identity=_identity(),
        thresholds=CalibrationThresholds(
            min_agreement_rate=0,
            max_false_positive_rate=1,
            max_false_negative_rate=1,
            max_expected_calibration_error=1,
            max_abstention_rate=1,
            min_samples_per_category=1,
        ),
    )

    assert result["state"] == "failed"
    assert "confirmed_exploit_missed" in result["reason_codes"]
    assert result["runtime_enabled"] is False
