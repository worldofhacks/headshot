"""Fail-closed Judge calibration loading and authority-state tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agentforge.agents.judge import Judge
from agentforge.agents.judge.calibration import (
    CalibrationGate,
    CalibrationGateClosed,
    JudgeIdentity,
)
from agentforge.agents.judge.calibration_runtime import load_judge_calibration_status
from agentforge.agents.judge.enablement import require_model_judge_enablement

GROUND_TRUTH = Path(__file__).resolve().parents[1] / "evals" / "ground-truth"


def _slices() -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8")) for path in sorted(GROUND_TRUTH.glob("*.json"))
    ]


def _identity(**updates: str) -> JudgeIdentity:
    values = {
        "judge_provider": "openrouter",
        "judge_model": "google/gemini-2.5-pro",
        "judge_model_version": "google/gemini-2.5-pro",
        "criteria_version": "verdict-v1",
        "implementation_version": "hosted-judge-v1",
        "red_team_provider": "openrouter",
        "red_team_model": "qwen/qwen3-235b-a22b",
    }
    values.update(updates)
    return JudgeIdentity(**values)


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


def _passed() -> dict:
    slices = _slices()
    return CalibrationGate(evaluator=_ExpectedVerdictEvaluator(slices)).evaluate(
        slices=slices,
        identity=_identity(),
    )


def _failed() -> dict:
    return CalibrationGate(evaluator=Judge()).evaluate(
        slices=_slices(),
        identity=_identity(),
    )


def test_unconfigured_or_unreadable_artifact_is_unavailable_not_authoritative(
    tmp_path: Path,
) -> None:
    unconfigured = load_judge_calibration_status(current_identity=_identity())
    missing = load_judge_calibration_status(
        current_identity=_identity(),
        configured_path=tmp_path / "missing.json",
    )

    assert unconfigured.public_payload() == {
        "state": "unavailable",
        "calibration_id": None,
        "metrics": None,
        "reason_codes": ["calibration_artifact_unavailable"],
        "model_authoritative": False,
        "source": "none",
    }
    assert missing.state == "unavailable"
    assert missing.model_authoritative is False


def test_failed_and_unapproved_pass_have_honest_non_authoritative_states() -> None:
    failed = load_judge_calibration_status(
        current_identity=_identity(),
        artifact=_failed(),
    )
    passed = load_judge_calibration_status(
        current_identity=_identity(),
        artifact=_passed(),
    )

    assert failed.state == "failed"
    assert failed.metrics is not None
    assert failed.metrics["agreement_rate"] == 0.6
    assert failed.metrics["false_negative_rate"] == pytest.approx(1 / 3)
    assert failed.model_authoritative is False
    assert passed.state == "passed"
    assert passed.model_authoritative is False
    assert passed.artifact()["human_approved"] is False
    assert passed.artifact()["runtime_enabled"] is False


def test_only_exact_human_enabled_pass_is_model_authoritative() -> None:
    gate = CalibrationGate(evaluator=_ExpectedVerdictEvaluator(_slices()))
    enabled_artifact = gate.human_enable(
        _passed(),
        current_identity=_identity(),
        approver_ref="user_security_reviewer",
    )

    status = load_judge_calibration_status(
        current_identity=_identity(),
        artifact=enabled_artifact,
    )

    assert status.state == "enabled"
    assert status.model_authoritative is True
    assert status.calibration_id == enabled_artifact["calibration_id"]
    assert status.artifact() == enabled_artifact


def test_identity_drift_or_tampered_content_address_is_invalidated() -> None:
    drifted = load_judge_calibration_status(
        current_identity=_identity(judge_model_version="different-returned-model"),
        artifact=_passed(),
    )
    tampered = _passed()
    tampered["thresholds"]["min_agreement_rate"] = 0.5
    integrity_failed = load_judge_calibration_status(
        current_identity=_identity(),
        artifact=tampered,
    )

    assert drifted.state == "invalidated"
    assert drifted.reason_codes == ("identity_drift",)
    assert drifted.model_authoritative is False
    assert integrity_failed.state == "invalidated"
    assert integrity_failed.reason_codes == ("calibration_artifact_integrity_failed",)
    assert integrity_failed.model_authoritative is False


def test_configured_file_is_bounded_absolute_and_contract_validated(tmp_path: Path) -> None:
    artifact_path = tmp_path / "judge-calibration.json"
    artifact_path.write_text(json.dumps(_passed()), encoding="utf-8")
    loaded = load_judge_calibration_status(
        current_identity=_identity(),
        configured_path=artifact_path,
    )
    relative = load_judge_calibration_status(
        current_identity=_identity(),
        configured_path=Path("judge-calibration.json"),
    )
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text("{not-json", encoding="utf-8")
    malformed = load_judge_calibration_status(
        current_identity=_identity(),
        configured_path=malformed_path,
    )

    assert loaded.state == "passed"
    assert loaded.source == "configured_file"
    assert relative.state == "invalidated"
    assert malformed.state == "invalidated"


def test_loader_rejects_ambiguous_sources_and_enablement_checks_embedded_identity() -> None:
    artifact = _passed()
    ambiguous = load_judge_calibration_status(
        current_identity=_identity(),
        artifact=artifact,
        configured_path=Path("/configured/calibration.json"),
    )
    enabled = CalibrationGate(evaluator=_ExpectedVerdictEvaluator(_slices())).human_enable(
        artifact,
        current_identity=_identity(),
        approver_ref="user_security_reviewer",
    )
    enabled["judge_identity"]["judge_model"] = "other/model"

    assert ambiguous.state == "invalidated"
    assert ambiguous.model_authoritative is False
    with pytest.raises(CalibrationGateClosed, match="identity is invalid"):
        require_model_judge_enablement(enabled, current_identity=_identity())
