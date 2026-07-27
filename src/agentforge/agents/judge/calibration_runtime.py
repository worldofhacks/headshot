"""Fail-closed loading and runtime authority status for Judge calibration.

The hosted evaluator may still be called when calibration is absent or failing.  This module
only answers the narrower authority question: whether one exact, independently-produced Judge
identity has a contract-valid calibration artifact that both passed and was explicitly enabled
by a human.  It never creates or modifies approval fields.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from agentforge.agents.judge.calibration import JudgeIdentity
from agentforge.agents.judge.enablement import require_model_judge_enablement
from agentforge.agents.judge.provenance import ProvenanceError, decode_approver_ref
from agentforge.contracts import validate

CalibrationRuntimeState = Literal[
    "unavailable",
    "failed",
    "passed",
    "invalidated",
    "enabled",
]
CalibrationArtifactSource = Literal["none", "explicit_mapping", "configured_file"]

_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class JudgeCalibrationStatus:
    """Sanitized runtime status plus a defensive copy of a validated artifact."""

    state: CalibrationRuntimeState
    calibration_id: str | None
    metrics: Mapping[str, int | float] | None
    reason_codes: tuple[str, ...]
    model_authoritative: bool
    source: CalibrationArtifactSource
    _artifact: dict[str, Any] | None = field(default=None, repr=False, compare=False)

    def artifact(self) -> dict[str, Any] | None:
        """Return a defensive copy for lineage or a later enablement re-check."""

        return copy.deepcopy(self._artifact)

    @property
    def authority_mode(self) -> Literal["none", "full", "positive_only"]:
        """Return the model authority supported by the artifact's disclosed provenance."""

        if not self.model_authoritative or self._artifact is None:
            return "none"
        try:
            provenance = decode_approver_ref(str(self._artifact.get("approver_ref") or ""))
        except ProvenanceError:
            # Enabled artifacts from before graded provenance retain their historical meaning
            # after the existing identity, content-address, and enablement gates pass.
            return "full"
        if (
            provenance["ground_truth_tier"] == "human_two_person"
            and provenance["provider_tier"] == "usage_export_reconciled"
        ):
            return "full"
        return "positive_only"

    def public_payload(self) -> dict[str, Any]:
        """Return only status fields suitable for telemetry or a read model."""

        return {
            "state": self.state,
            "calibration_id": self.calibration_id,
            "metrics": None if self.metrics is None else dict(self.metrics),
            "reason_codes": list(self.reason_codes),
            "model_authoritative": self.model_authoritative,
            "authority_mode": self.authority_mode,
            "source": self.source,
        }


def load_judge_calibration_status(
    *,
    current_identity: JudgeIdentity,
    artifact: Mapping[str, Any] | None = None,
    configured_path: str | Path | None = None,
) -> JudgeCalibrationStatus:
    """Load one explicit artifact source and decide model authority without side effects.

    ``configured_path`` must be an absolute path supplied by trusted configuration (for example,
    a sealed file mount).  There is deliberately no default path and no environment-variable
    discovery here.  A caller may instead pass a mapping it already loaded through a trusted
    configuration boundary.  Missing data is ``unavailable``; malformed or identity-drifted data
    is ``invalidated``.  Neither state prevents the evaluator call itself, but both keep the
    deterministic oracle/canary ground truth decisive.
    """

    identity = current_identity.payload()
    if artifact is not None and configured_path is not None:
        return _status(
            state="invalidated",
            source="none",
            reason_codes=("multiple_artifact_sources_configured",),
        )
    if artifact is None and configured_path is None:
        return _status(
            state="unavailable",
            source="none",
            reason_codes=("calibration_artifact_unavailable",),
        )

    source: CalibrationArtifactSource
    candidate: object
    if configured_path is not None:
        source = "configured_file"
        candidate, load_state = _read_configured_artifact(configured_path)
        if load_state is not None:
            return _status(
                state=load_state,
                source=source,
                reason_codes=(_load_reason(load_state),),
            )
    else:
        source = "explicit_mapping"
        candidate = artifact

    if not isinstance(candidate, Mapping):
        return _status(
            state="invalidated",
            source=source,
            reason_codes=("calibration_artifact_invalid",),
        )
    try:
        validated = copy.deepcopy(dict(candidate))
        validate("judge_calibration", validated)
    except Exception:
        return _status(
            state="invalidated",
            source=source,
            reason_codes=("calibration_artifact_invalid",),
        )

    calibration_id = validated["calibration_id"]
    metrics = dict(validated["metrics"])
    if not _content_address_is_consistent(validated):
        return _status(
            state="invalidated",
            source=source,
            calibration_id=calibration_id,
            metrics=metrics,
            reason_codes=("calibration_artifact_integrity_failed",),
            artifact=validated,
        )
    if validated["judge_identity"] != identity:
        return _status(
            state="invalidated",
            source=source,
            calibration_id=calibration_id,
            metrics=metrics,
            reason_codes=("identity_drift",),
            artifact=validated,
        )
    if validated["state"] == "invalidated":
        return _status(
            state="invalidated",
            source=source,
            calibration_id=calibration_id,
            metrics=metrics,
            reason_codes=tuple(validated["reason_codes"]),
            artifact=validated,
        )
    if validated["state"] == "failed":
        return _status(
            state="failed",
            source=source,
            calibration_id=calibration_id,
            metrics=metrics,
            reason_codes=tuple(validated["reason_codes"]),
            artifact=validated,
        )

    # A passed measurement is intentionally distinct from human-enabled model authority.
    if not validated["human_approved"] or not validated["runtime_enabled"]:
        return _status(
            state="passed",
            source=source,
            calibration_id=calibration_id,
            metrics=metrics,
            reason_codes=tuple(validated["reason_codes"]),
            artifact=validated,
        )
    try:
        require_model_judge_enablement(validated, current_identity=current_identity)
    except Exception:
        return _status(
            state="invalidated",
            source=source,
            calibration_id=calibration_id,
            metrics=metrics,
            reason_codes=("calibration_enablement_invalid",),
            artifact=validated,
        )
    return _status(
        state="enabled",
        source=source,
        calibration_id=calibration_id,
        metrics=metrics,
        reason_codes=tuple(validated["reason_codes"]),
        model_authoritative=True,
        artifact=validated,
    )


def _read_configured_artifact(
    configured_path: str | Path,
) -> tuple[object | None, Literal["unavailable", "invalidated"] | None]:
    try:
        path = Path(configured_path)
    except TypeError:
        return None, "invalidated"
    if not path.is_absolute():
        return None, "invalidated"
    try:
        with path.open("rb") as handle:
            encoded = handle.read(_MAX_ARTIFACT_BYTES + 1)
    except (FileNotFoundError, PermissionError, OSError):
        return None, "unavailable"
    if len(encoded) > _MAX_ARTIFACT_BYTES:
        return None, "invalidated"
    try:
        return (
            json.loads(
                encoded.decode("utf-8"),
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            ),
            None,
        )
    except (UnicodeDecodeError, ValueError, TypeError):
        return None, "invalidated"


def _load_reason(state: Literal["unavailable", "invalidated"]) -> str:
    if state == "unavailable":
        return "calibration_artifact_unavailable"
    return "calibration_artifact_invalid"


def _content_address_is_consistent(artifact: Mapping[str, Any]) -> bool:
    embedded_identity_hash = _sha256(artifact["judge_identity"])
    if embedded_identity_hash != artifact["identity_sha256"]:
        return False
    expected_id = "JC-" + _sha256(
        {
            "slice_set_sha256": artifact["slice_set_sha256"],
            "identity_sha256": artifact["identity_sha256"],
            "thresholds": artifact["thresholds"],
        }
    )
    return expected_id == artifact["calibration_id"]


def _sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _status(
    *,
    state: CalibrationRuntimeState,
    source: CalibrationArtifactSource,
    reason_codes: tuple[str, ...],
    calibration_id: str | None = None,
    metrics: Mapping[str, int | float] | None = None,
    model_authoritative: bool = False,
    artifact: dict[str, Any] | None = None,
) -> JudgeCalibrationStatus:
    return JudgeCalibrationStatus(
        state=state,
        calibration_id=calibration_id,
        metrics=None if metrics is None else copy.deepcopy(dict(metrics)),
        reason_codes=reason_codes,
        model_authoritative=model_authoritative,
        source=source,
        _artifact=copy.deepcopy(artifact),
    )


__all__ = [
    "CalibrationArtifactSource",
    "CalibrationRuntimeState",
    "JudgeCalibrationStatus",
    "load_judge_calibration_status",
]
