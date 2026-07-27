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
3.  **Provenance is graded, and the grade is earned.**  Label and provider-call provenance are
    COMPUTED from the evidence supplied (``agents/judge/provenance.py``), never declared.  The
    approving human names the weakest tier they accept; enablement refuses if the real tier is
    weaker.  A deadline may legitimately force a weaker baseline than two-person human ground
    truth — what it may not do is let that baseline be read later as the stronger thing, so the
    accepted tiers are encoded into ``approver_ref`` and travel inside the artifact.
4.  **A named human approves.**  ``--approver-ref`` is recorded in the artifact and re-verified
    by ``require_model_judge_enablement`` before the file is written.  Relaxing the label
    provenance does NOT relax this: enablement is still a separate, attributable human act.

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
from typing import Any, Literal

from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.agents.hosted_runtime import hosted_judge_identity
from agentforge.agents.judge import CalibrationGate, Judge
from agentforge.agents.judge.enablement import require_model_judge_enablement
from agentforge.agents.judge.provenance import (
    GROUND_TRUTH_TIERS,
    PROVIDER_TIERS,
    ProvenanceError,
    classify_ground_truth,
    classify_provider_provenance,
    disclosure,
    encode_approver_ref,
    is_at_least,
)

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
        help=(
            "two-person human attestation over the exact slice set (see "
            ".tdd-swarm/reports/RTG-ground-truth-label-spec.md). Omit to enable against a weaker "
            "baseline, which then must be named in --accept-ground-truth-tier"
        ),
    )
    parser.add_argument(
        "--accept-ground-truth-tier",
        choices=GROUND_TRUTH_TIERS,
        required=True,
        help=(
            "the WEAKEST label provenance you are accepting. Enablement refuses if the real tier "
            "is weaker than this, and the accepted tier is written into the artifact"
        ),
    )
    parser.add_argument(
        "--accept-provider-tier",
        choices=PROVIDER_TIERS,
        required=True,
        help=(
            "the WEAKEST provider-call provenance you are accepting. 'lineage_consistent' accepts "
            "a bundle whose calls look real but were never reconciled against provider records"
        ),
    )
    parser.add_argument(
        "--provenance-attestation",
        type=Path,
        help=(
            "output of scripts/verify_calibration_provenance.py — the reconciliation of the "
            "capture bundle against the provider's own usage export. Omit to enable at "
            "'lineage_consistent' or weaker"
        ),
    )
    parser.add_argument(
        "--captured-results",
        type=Path,
        help="the capture bundle, required when no provenance attestation is supplied",
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

    ground_truth_tier, provider_tier = _classify(args, calibration=calibration)
    authority_mode: Literal["full", "positive_only"] = (
        "full"
        if (
            ground_truth_tier == "human_two_person"
            and provider_tier == "usage_export_reconciled"
        )
        else "positive_only"
    )
    _require_governing_stratum_passes(
        calibration,
        slice_dir=args.slice_dir,
        authority_mode=authority_mode,
    )

    try:
        approver_ref = encode_approver_ref(
            approver=args.approver_ref,
            ground_truth_tier=ground_truth_tier,
            provider_tier=provider_tier,
        )
    except ProvenanceError as exc:
        raise EnablementRefused(str(exc)) from exc

    enabled = CalibrationGate(evaluator=Judge()).human_enable(
        calibration,
        current_identity=identity,
        approver_ref=approver_ref,
    )
    # Re-run the runtime gate over the artifact we are about to persist, so what is written is
    # exactly what the runtime will accept.
    require_model_judge_enablement(enabled, current_identity=identity)
    return enabled


def _classify(
    args: argparse.Namespace,
    *,
    calibration: Mapping[str, Any],
) -> tuple[str, str]:
    """Derive the real provenance tiers and refuse anything weaker than what was accepted.

    The tiers are computed from the evidence actually supplied, so naming a strong tier does not
    grant it. What the operator's choice does is set a floor and put their name against it — the
    accepted tiers are then encoded into the artifact's own approver_ref, so a weaker baseline
    travels labelled rather than being read later as the stronger thing.
    """

    slices = _load_slices(args.slice_dir)
    attestation = (
        None
        if args.ground_truth_attestation is None
        else _read_json(args.ground_truth_attestation, "ground-truth attestation")
    )
    if attestation is not None:
        bound = attestation.get("slice_set_sha256")
        if bound != calibration["slice_set_sha256"]:
            raise EnablementRefused(
                "the ground-truth attestation is bound to a different slice set than the "
                f"calibration ({bound} != {calibration['slice_set_sha256']})"
            )
    try:
        ground_truth_tier, gt_evidence = classify_ground_truth(slices, attestation=attestation)
    except ProvenanceError as exc:
        raise EnablementRefused(str(exc)) from exc

    provenance = (
        None
        if args.provenance_attestation is None
        else _read_json(args.provenance_attestation, "provenance attestation")
    )
    if provenance is not None and provenance.get("judge_identity") != dict(
        calibration["judge_identity"]
    ):
        raise EnablementRefused(
            "the provenance attestation covers a different Judge identity than the calibration"
        )
    if provenance is None and args.captured_results is None:
        raise EnablementRefused(
            "supply --provenance-attestation or --captured-results; provider provenance cannot "
            "be graded from nothing"
        )
    bundle = (
        {"samples": []}
        if args.captured_results is None
        else _read_json(args.captured_results, "capture bundle")
    )
    if args.captured_results is None and provenance is not None:
        bundle = {"samples": [{}] * int(provenance.get("matched_generation_count") or 0)}
    try:
        provider_tier, prov_evidence = classify_provider_provenance(bundle, attestation=provenance)
    except ProvenanceError as exc:
        raise EnablementRefused(str(exc)) from exc

    _require_tier(
        actual=ground_truth_tier,
        accepted=args.accept_ground_truth_tier,
        tiers=GROUND_TRUTH_TIERS,
        label="ground-truth",
        evidence=gt_evidence,
    )
    _require_tier(
        actual=provider_tier,
        accepted=args.accept_provider_tier,
        tiers=PROVIDER_TIERS,
        label="provider-call",
        evidence=prov_evidence,
    )
    print(disclosure(ground_truth_tier=ground_truth_tier, provider_tier=provider_tier))
    return ground_truth_tier, provider_tier


def _require_tier(
    *,
    actual: str,
    accepted: str,
    tiers: tuple[str, ...],
    label: str,
    evidence: Mapping[str, Any],
) -> None:
    if not is_at_least(actual, accepted, tiers):
        raise EnablementRefused(
            f"{label} provenance is {actual!r}, weaker than the accepted floor {accepted!r}. "
            f"Evidence: {json.dumps(evidence, sort_keys=True)}"
        )


def _load_slices(slice_dir: Path) -> list[dict[str, Any]]:
    candidates = sorted(slice_dir.glob("*.json"))
    if not candidates:
        raise EnablementRefused(f"no ground-truth slices under {slice_dir}")
    return [_read_json(path, "ground-truth slice") for path in candidates]


def _require_governing_stratum_passes(
    calibration: Mapping[str, Any],
    *,
    slice_dir: Path,
    authority_mode: Literal["full", "positive_only"] = "full",
) -> None:
    """Gate the non-oracle stratum against the authority the artifact can actually grant.

    Full authority must pass every existing breach check. Provisional positive-only authority
    never persists ``NO_EXPLOIT_OBSERVED`` as safe: a model false negative remains the
    deterministic ``INDETERMINATE`` result. Consequently ``false_negative_rate_exceeded`` and
    ``positive_scored_safe`` are contained by construction in that mode; agreement, false
    positives, abstention, and all other breaches still fail closed.
    """

    analyzer = _load_analyzer()
    try:
        report = analyzer.build_report(calibration, analyzer._load_labels(slice_dir))
    except analyzer.AnalysisError as exc:
        raise EnablementRefused(f"the calibration could not be stratified: {exc}") from exc

    non_oracle = report["non_oracle"]
    breaches = list(non_oracle["breaches"])
    if authority_mode == "positive_only":
        breaches = [
            breach
            for breach in breaches
            if breach not in {"false_negative_rate_exceeded", "positive_scored_safe"}
        ]
    if breaches:
        raise EnablementRefused(
            "the non-oracle stratum — the only cases the model actually decides — breaches "
            f"{', '.join(breaches)} "
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
