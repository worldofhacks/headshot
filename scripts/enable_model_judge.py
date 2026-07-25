#!/usr/bin/env python3
"""Flip ``runtime_enabled`` for one exact, currently-deployed Judge identity — or refuse.

Measurement, approval, and enablement are three separate operations; this is only the third.  It
writes no metric and re-runs no evaluation.  Every check below is a refusal, never a repair:

1.  **Identity is re-derived, not trusted.**  The staged production configuration set is loaded
    and hash-pinned, and the Judge identity is computed from it.  A calibration measured against
    any other identity is rejected as drift — including a calibration whose identity was
    synthesized by an older capture.
2.  **The governing stratum must pass, not just the pooled headline.**  A trusted oracle/canary
    hit decides its case in code, so pooling those samples measures precedence, not the model.
    Enablement gates on the NON-ORACLE stratum — the only cases an enabled model Judge decides.
3.  **Ground truth must be human-attested by two distinct principals, blind to Judge output.**
    Rule-authored or agent-authored labels cannot license a model to act on them, and one person
    cannot both label and review.  The attestation is bound to the exact ``slice_set_sha256``.
4.  **A named human approves.**  ``--approver-ref`` is recorded in the artifact and re-verified
    by ``require_model_judge_enablement`` before the file is written.

Enabling the model Judge does NOT give it confirmation authority.  The hosted assessment schema
has no ``EXPLOIT_CONFIRMED`` member and ``reconcile_judge_assessment`` returns the deterministic
verdict whenever ground truth is ``EXPLOIT_CONFIRMED`` or ``ERROR``, so a confirmed exploit stays
oracle-, canary-, or human-sourced.  What enablement changes is narrower and stated plainly: cases
with no trusted hit stop being forced to ``INDETERMINATE`` and become ``EXPLOIT_LIKELY`` or
``NO_EXPLOIT_OBSERVED`` assessments.  Genuine uncertainty still reports ``INDETERMINATE``, and
``is_safe()`` remains true only for ``NO_EXPLOIT_OBSERVED``.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.agents.hosted_runtime import hosted_judge_identity
from agentforge.agents.judge import CalibrationGate, Judge
from agentforge.agents.judge.enablement import require_model_judge_enablement

_ROOT = Path(__file__).resolve().parents[1]
_GROUND_TRUTH = _ROOT / "evals" / "ground-truth"
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class EnablementRefused(RuntimeError):
    """The model Judge may not be enabled under the supplied evidence."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--calibration",
        type=Path,
        required=True,
        help="the passing judge_calibration.json artifact to enable",
    )
    parser.add_argument(
        "--hosted-configuration-set",
        type=Path,
        required=True,
        help="the staged production configuration set the deployment is running",
    )
    parser.add_argument(
        "--expected-configuration-sha256",
        required=True,
        help="the configuration_sha256 the deploying operator attested",
    )
    parser.add_argument(
        "--ground-truth-attestation",
        type=Path,
        required=True,
        help=(
            "two-person human attestation over the exact slice set (see "
            ".tdd-swarm/reports/RTG-ground-truth-label-spec.md)"
        ),
    )
    parser.add_argument(
        "--approver-ref",
        required=True,
        help="the authorized human principal approving runtime enablement",
    )
    parser.add_argument(
        "--slice-dir",
        type=Path,
        default=_GROUND_TRUTH,
        help="ground-truth slice directory used for the stratified re-check",
    )
    parser.add_argument("--output", type=Path, required=True, help="where to write the artifact")
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="required acknowledgement that this grants the model Judge runtime authority",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if not args.confirm:
        raise SystemExit("refusing to enable: --confirm is required")
    try:
        artifact = _enable(args)
    except EnablementRefused as exc:
        raise SystemExit(f"refusing to enable: {exc}") from exc

    args.output.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"model Judge ENABLED for identity {artifact['identity_sha256']}")
    print(f"  calibration  {artifact['calibration_id']}")
    print(f"  approver     {artifact['approver_ref']}")
    print("  confirmation authority is UNCHANGED: oracle / canary / human only.")
    return 0


def _enable(args: argparse.Namespace) -> dict[str, Any]:
    calibration = _read_json(args.calibration, "calibration artifact")
    configuration = _staged_configuration(
        args.hosted_configuration_set,
        expected_sha256=args.expected_configuration_sha256,
    )
    identity = hosted_judge_identity(configuration)

    if calibration.get("state") != "passed":
        raise EnablementRefused(f"calibration state is {calibration.get('state')!r}, not 'passed'")
    if calibration.get("judge_identity") != identity.payload():
        raise EnablementRefused(
            "the calibration measured a different Judge identity than the deployment is "
            "running — recalibrate against the staged configuration"
        )

    _require_two_person_ground_truth(
        _read_json(args.ground_truth_attestation, "ground-truth attestation"),
        slice_set_sha256=calibration["slice_set_sha256"],
    )
    _require_governing_stratum_passes(calibration, slice_dir=args.slice_dir)

    enabled = CalibrationGate(evaluator=Judge()).human_enable(
        calibration,
        current_identity=identity,
        approver_ref=args.approver_ref,
    )
    # Re-run the runtime gate over the artifact we are about to persist, so what is written is
    # exactly what the runtime will accept.
    require_model_judge_enablement(enabled, current_identity=identity)
    return enabled


def _require_two_person_ground_truth(
    attestation: Mapping[str, Any],
    *,
    slice_set_sha256: str,
) -> None:
    """A model may only act on labels two distinct humans attested, blind to its own output."""

    if attestation.get("slice_set_sha256") != slice_set_sha256:
        raise EnablementRefused(
            "the ground-truth attestation is bound to a different slice set than the "
            f"calibration ({attestation.get('slice_set_sha256')} != {slice_set_sha256})"
        )
    if attestation.get("blind_to_judge_output") is not True:
        raise EnablementRefused(
            "ground-truth labels must be attested blind to Judge output; labels adjusted after "
            "seeing model results cannot calibrate that model"
        )
    labeler = _principal(attestation.get("human_labeler"), "human_labeler")
    reviewer = _principal(attestation.get("distinct_reviewer"), "distinct_reviewer")
    if labeler == reviewer:
        raise EnablementRefused(
            f"ground-truth labeler and reviewer are the same principal ({labeler}); the "
            "two-person gate requires two distinct authorized humans"
        )


def _principal(value: Any, field: str) -> str:
    if not isinstance(value, Mapping):
        raise EnablementRefused(
            f"ground-truth attestation has no {field}; rule-authored or agent-authored labels "
            "cannot license runtime model authority"
        )
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise EnablementRefused(f"ground-truth {field} has no identified principal")
    attested_at = value.get("attested_at")
    if not isinstance(attested_at, str) or not attested_at.strip():
        raise EnablementRefused(f"ground-truth {field} carries no attestation timestamp")
    return identifier.strip()


def _require_governing_stratum_passes(calibration: Mapping[str, Any], *, slice_dir: Path) -> None:
    """Gate on the non-oracle stratum: the only cases an enabled model Judge decides."""

    analyzer = _load_analyzer()
    try:
        report = analyzer.build_report(calibration, analyzer._load_labels(slice_dir))
    except analyzer.AnalysisError as exc:
        raise EnablementRefused(f"the calibration could not be stratified: {exc}") from exc

    non_oracle = report["non_oracle"]
    if non_oracle["breaches"]:
        raise EnablementRefused(
            "the non-oracle stratum — the only cases the model actually decides — breaches "
            f"{', '.join(non_oracle['breaches'])} "
            f"(n={non_oracle['sample_count']}, agreement={non_oracle['agreement_rate']:.4f}, "
            f"false-negative={non_oracle['false_negative_rate']:.4f}). The pooled headline may "
            "still pass; it is not the number that governs enablement."
        )


def _load_analyzer() -> Any:
    path = _ROOT / "scripts" / "analyze_judge_calibration.py"
    spec = importlib.util.spec_from_file_location("analyze_judge_calibration", path)
    if spec is None or spec.loader is None:  # pragma: no cover - packaging accident
        raise EnablementRefused("the calibration analyzer is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _staged_configuration(path: Path, *, expected_sha256: str) -> HostedConfigurationSet:
    if _HEX64.fullmatch(expected_sha256 or "") is None:
        raise EnablementRefused("--expected-configuration-sha256 must be a sha256 hex digest")
    payload = _read_json(path, "staged hosted configuration set")
    try:
        configuration = HostedConfigurationSet.from_payload(payload)
    except (TypeError, ValueError) as exc:
        raise EnablementRefused(
            f"the staged hosted configuration set is invalid for this release ({exc})"
        ) from exc
    if configuration.configuration_sha256 != expected_sha256:
        raise EnablementRefused(
            "the staged configuration drifted from the attested identity — attested "
            f"{expected_sha256}, loaded {configuration.configuration_sha256}"
        )
    return configuration


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise EnablementRefused(f"the {label} is unreadable or not valid JSON") from exc


if __name__ == "__main__":
    raise SystemExit(main())
