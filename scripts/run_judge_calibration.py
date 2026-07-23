#!/usr/bin/env python3
"""Reproduce the offline Judge calibration artifact without network access.

The default command reports the measured gate state.  ``--require-pass`` is the CI/runtime
activation check: it exits non-zero unless the exact evaluator identity passes calibration.
Human approval is deliberately a separate operation and is never synthesized here.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentforge.agents.judge import CalibrationGate, Judge, JudgeIdentity

_ROOT = Path(__file__).resolve().parents[1]
_GROUND_TRUTH = _ROOT / "evals" / "ground-truth"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-pass",
        action="store_true",
        help="exit 2 unless calibration thresholds pass (runtime stays disabled regardless)",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    slices = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(_GROUND_TRUTH.glob("*.json"))
    ]
    identity = JudgeIdentity(
        judge_provider="deterministic-code",
        judge_model="oracle-precedence",
        judge_model_version="1",
        criteria_version="verdict-v1",
        implementation_version="judge-v1",
        red_team_provider="offline-seed",
        red_team_model="seed-replay-v1",
    )
    result = CalibrationGate(evaluator=Judge()).evaluate(slices=slices, identity=identity)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if args.require_pass and result["state"] != "passed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
