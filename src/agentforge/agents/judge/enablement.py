"""Fail-closed enablement check for any hosted or semantic Judge implementation."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from agentforge.agents.judge.calibration import CalibrationGateClosed, JudgeIdentity
from agentforge.contracts import validate


def require_model_judge_enablement(
    result: Mapping[str, Any],
    *,
    current_identity: JudgeIdentity,
) -> dict[str, Any]:
    """Return a validated calibration only when the exact model Judge may run.

    A passing measurement is insufficient on its own.  The artifact must also record evaluator
    independence, explicit human approval, runtime enablement, and an identity hash matching the
    exact provider/model/criteria/implementation tuple about to execute.
    """

    if not isinstance(result, Mapping):
        raise CalibrationGateClosed("model Judge calibration artifact is unavailable")
    candidate = copy.deepcopy(dict(result))
    try:
        validate("judge_calibration", candidate)
    except Exception as exc:
        raise CalibrationGateClosed("model Judge calibration artifact is invalid") from exc

    identity = current_identity.payload()
    encoded = json.dumps(
        identity,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    current_sha256 = hashlib.sha256(encoded).hexdigest()
    embedded_identity = candidate["judge_identity"]
    embedded_encoded = json.dumps(
        embedded_identity,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    embedded_sha256 = hashlib.sha256(embedded_encoded).hexdigest()
    if embedded_sha256 != candidate["identity_sha256"]:
        raise CalibrationGateClosed("model Judge calibration identity is invalid")
    if embedded_identity != identity:
        raise CalibrationGateClosed("Judge identity drift requires recalibration")
    if candidate["identity_sha256"] != current_sha256:
        raise CalibrationGateClosed("Judge identity drift requires recalibration")
    if not candidate["independent_from_red_team"]:
        raise CalibrationGateClosed("Judge must remain independent from Red Team")
    if candidate["state"] != "passed":
        raise CalibrationGateClosed("model Judge requires a passing calibration")
    if not candidate["human_approved"] or not candidate["runtime_enabled"]:
        raise CalibrationGateClosed("model Judge requires explicit human enablement")
    if not candidate.get("approver_ref"):
        raise CalibrationGateClosed("model Judge enablement lacks an approver reference")
    return candidate


__all__ = ["require_model_judge_enablement"]
