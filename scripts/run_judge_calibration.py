#!/usr/bin/env python3
"""Measure a Judge identity against versioned ground truth without network access.

With no result bundle, the command truthfully measures the deterministic oracle-precedence
baseline under its deterministic identity.  It never labels that baseline as Gemini.  To measure
a real hosted evaluator, pass previously captured, lineage-complete outcomes plus a separate
expected-identity file.  The command never contacts a provider.

``--require-pass`` exits non-zero unless the measured identity passes the unchanged calibration
thresholds.  Human approval and runtime enablement are deliberately separate operations and are
never synthesized here.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentforge.agents.judge import (
    THRESHOLD_POLICIES,
    CalibrationGate,
    CalibrationInputError,
    Judge,
    JudgeIdentity,
    resolve_threshold_policy,
)
from agentforge.agents.judge.calibration_results import (
    load_captured_calibration_evaluator,
    load_judge_identity,
)

_ROOT = Path(__file__).resolve().parents[1]
_GROUND_TRUTH = _ROOT / "evals" / "ground-truth"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slice-dir",
        type=Path,
        default=_GROUND_TRUTH,
        help="versioned ground-truth slice directory (default: evals/ground-truth)",
    )
    parser.add_argument(
        "--captured-results",
        type=Path,
        help=(
            "offline hosted-evaluator result bundle with per-sample OpenRouter trace, "
            "returned-model, token, and measured-cost provenance"
        ),
    )
    parser.add_argument(
        "--expected-identity",
        type=Path,
        help=(
            "separate exact JudgeIdentity JSON; required with --captured-results so result "
            "content cannot self-select the identity being calibrated"
        ),
    )
    parser.add_argument(
        "--threshold-policy",
        choices=sorted(THRESHOLD_POLICIES),
        default="accepted",
        help=(
            "reviewed acceptance bar to measure against: 'accepted' is the owner-accepted model-"
            "Judge policy (agreement>=0.85, FN<=0.10, FP<=0.05, ECE<=0.10, abstention<=0.40, "
            ">=5 samples/category); 'strict' keeps the historical FN<=0.00 bar. The hard "
            "confirmed-exploit-missed invariant applies under BOTH policies. "
            "(default: accepted)"
        ),
    )
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="exit 2 unless calibration thresholds pass (runtime stays disabled regardless)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the calibration result JSON to this path instead of stdout",
    )
    return parser


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    if (args.captured_results is None) != (args.expected_identity is None):
        parser.error("--captured-results and --expected-identity must be provided together")
    try:
        slices = _load_slices(args.slice_dir)
        if args.captured_results is None:
            identity = _deterministic_identity()
            evaluator = Judge()
        else:
            identity = load_judge_identity(args.expected_identity)
            evaluator = load_captured_calibration_evaluator(
                args.captured_results,
                expected_identity=identity,
                expected_label_ids=[
                    label["label_id"] for item in slices for label in item["labels"]
                ],
            )
        result = CalibrationGate(evaluator=evaluator).evaluate(
            slices=slices,
            identity=identity,
            thresholds=resolve_threshold_policy(args.threshold_policy),
        )
    except CalibrationInputError as exc:
        parser.error(str(exc))
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 2 if args.require_pass and result["state"] != "passed" else 0


def _load_slices(path: Path) -> list[dict]:
    try:
        candidates = sorted(path.glob("*.json"))
    except OSError as exc:
        raise CalibrationInputError("ground-truth slice directory is unavailable") from exc
    if not candidates:
        raise CalibrationInputError("ground-truth slice directory has no JSON slices")
    slices: list[dict] = []
    for candidate in candidates:
        try:
            slices.append(json.loads(candidate.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CalibrationInputError("ground-truth slice file is invalid") from exc
    return slices


def _deterministic_identity() -> JudgeIdentity:
    return JudgeIdentity(
        judge_provider="deterministic-code",
        judge_model="oracle-precedence",
        judge_model_version="1",
        criteria_version="verdict-v1",
        implementation_version="judge-v1",
        red_team_provider="offline-seed",
        red_team_model="seed-replay-v1",
    )


if __name__ == "__main__":
    raise SystemExit(main())
