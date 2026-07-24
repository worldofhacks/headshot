"""Offline, lineage-bound hosted Judge calibration result ingestion."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentforge.agents.judge.calibration import (
    CalibrationGate,
    CalibrationInputError,
    JudgeIdentity,
)
from agentforge.agents.judge.calibration_results import (
    load_captured_calibration_evaluator,
    load_judge_identity,
)

ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH = ROOT / "evals" / "ground-truth"
ROLE_CONFIGURATION_SHA256 = "b" * 64
RETURNED_MODEL = "google/gemini-2.5-pro"


def _slices() -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8")) for path in sorted(GROUND_TRUTH.glob("*.json"))
    ]


def _identity() -> JudgeIdentity:
    return JudgeIdentity(
        judge_provider="openrouter:google",
        judge_model="google/gemini-2.5-pro",
        judge_model_version=ROLE_CONFIGURATION_SHA256,
        criteria_version="verdict-v1",
        implementation_version="hosted-judge-v1",
        red_team_provider="openrouter:qwen",
        red_team_model="qwen/qwen3-235b-a22b",
    )


def _bundle() -> dict:
    samples = []
    for index, item in enumerate(_slices()):
        for label in item["labels"]:
            state = label["expected_verdict"]["state"]
            if state == "EXPLOIT_CONFIRMED":
                state = "EXPLOIT_LIKELY"
            samples.append(
                {
                    "label_id": label["label_id"],
                    "assessment": {
                        "state": state,
                        "confidence": 1.0,
                        "rationale": "Bounded synthetic calibration assessment.",
                        "criteria_hits": ["ground_truth_disposition"],
                        "error_code": "evaluation_error" if state == "ERROR" else None,
                    },
                    "provider_request_id": f"provider-request-{index}-{label['label_id']}",
                    "trace_id": f"langfuse-trace-{index}-{label['label_id']}",
                    "returned_model": RETURNED_MODEL,
                    "input_tokens": 100,
                    "output_tokens": 20,
                    "reasoning_tokens": 10,
                    "measured_cost_usd": "0.001",
                }
            )
    return {
        "schema_version": "1",
        "judge_identity": _identity().payload(),
        "provenance": {
            "capture_kind": "openrouter_hosted_evaluator",
            "configuration_sha256": "a" * 64,
            "role_configuration_sha256": ROLE_CONFIGURATION_SHA256,
            "generation_policy_sha256": "c" * 64,
            "requested_model": "google/gemini-2.5-pro",
            "returned_model": RETURNED_MODEL,
            "captured_at": "2026-07-24T15:30:00Z",
        },
        "samples": samples,
    }


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_traced_hosted_results_can_pass_without_model_confirmation_authority(
    tmp_path: Path,
) -> None:
    results_path = tmp_path / "captured-results.json"
    _write_json(results_path, _bundle())
    slices = _slices()
    evaluator = load_captured_calibration_evaluator(
        results_path,
        expected_identity=_identity(),
        expected_label_ids=[label["label_id"] for item in slices for label in item["labels"]],
    )

    result = CalibrationGate(evaluator=evaluator).evaluate(
        slices=slices,
        identity=_identity(),
    )

    assert result["state"] == "passed"
    assert result["metrics"]["agreement_rate"] == 1
    assert result["metrics"]["false_negative_rate"] == 0
    assert result["human_approved"] is False
    assert result["runtime_enabled"] is False
    assert all(sample["actual_state"] != "EXPLOIT_CONFIRMED" for sample in result["sample_results"])


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda payload: payload["judge_identity"].__setitem__(
                "judge_model",
                "unapproved/model",
            ),
            "identity does not match",
        ),
        (
            lambda payload: payload["samples"].pop(),
            "exactly cover",
        ),
        (
            lambda payload: payload["samples"][0].__setitem__(
                "returned_model",
                "other/model",
            ),
            "returned-model identity",
        ),
        (
            lambda payload: payload["samples"][0].__setitem__("trace_id", ""),
            "trace identifier",
        ),
    ],
)
def test_captured_results_fail_closed_on_identity_lineage_or_coverage_drift(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    payload = _bundle()
    mutation(payload)
    results_path = tmp_path / "captured-results.json"
    _write_json(results_path, payload)

    with pytest.raises(CalibrationInputError, match=message):
        load_captured_calibration_evaluator(
            results_path,
            expected_identity=_identity(),
            expected_label_ids=[
                label["label_id"] for item in _slices() for label in item["labels"]
            ],
        )


def test_expected_identity_is_loaded_separately_and_strictly(tmp_path: Path) -> None:
    identity_path = tmp_path / "identity.json"
    _write_json(identity_path, _identity().payload())

    assert load_judge_identity(identity_path) == _identity()

    invalid = copy.deepcopy(_identity().payload())
    invalid["unexpected"] = "field"
    _write_json(identity_path, invalid)
    with pytest.raises(CalibrationInputError, match="invalid shape"):
        load_judge_identity(identity_path)


def test_calibration_cli_keeps_default_identity_truthful_and_accepts_offline_results(
    tmp_path: Path,
) -> None:
    identity_path = tmp_path / "identity.json"
    results_path = tmp_path / "captured-results.json"
    _write_json(identity_path, _identity().payload())
    _write_json(results_path, _bundle())
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

    baseline = subprocess.run(
        [sys.executable, "scripts/run_judge_calibration.py"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    hosted = subprocess.run(
        [
            sys.executable,
            "scripts/run_judge_calibration.py",
            "--captured-results",
            str(results_path),
            "--expected-identity",
            str(identity_path),
            "--require-pass",
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    baseline_artifact = json.loads(baseline.stdout)
    hosted_artifact = json.loads(hosted.stdout)
    assert baseline_artifact["judge_identity"]["judge_provider"] == "deterministic-code"
    assert baseline_artifact["state"] == "failed"
    assert hosted.returncode == 0
    assert hosted_artifact["judge_identity"] == _identity().payload()
    assert hosted_artifact["state"] == "passed"
    assert hosted_artifact["human_approved"] is False
    assert hosted_artifact["runtime_enabled"] is False
