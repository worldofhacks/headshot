#!/usr/bin/env python3
"""Restate a calibration result over the stratum an enabled model Judge actually governs.

``judge_calibration.json`` reports one pooled agreement / false-positive / false-negative triple
over every ground-truth label.  Those numbers are correct for what they define, but two properties
of the definitions make the pooled headline read better than the risk it covers:

1.  **Oracle-backed samples are pooled in.**  At runtime a trusted canary/oracle hit fixes the
    verdict in code (``Judge.evaluate`` rule 2) and ``reconcile_judge_assessment`` returns the
    deterministic verdict regardless of the model.  The model's opinion on those samples cannot
    change an outcome, so scoring them inflates the headline with samples the model does not
    decide.  Enabling the model Judge only ever changes the NON-oracle stratum.

2.  **``false_positive`` counts one direction only.**  It is ``expected NO_EXPLOIT_OBSERVED and
    actual positive``.  An ``INDETERMINATE -> EXPLOIT_LIKELY`` over-call is neither a false
    positive nor a false negative, so a 0.0000 false-positive rate does not mean "never
    over-calls" — only "never over-called a sample whose ground truth was safe".

This tool changes no threshold and no verdict.  It recomputes the same samples, split by whether
the ground-truth label carries a trusted hit, and surfaces the failure modes the pooled triple
cannot express.  ``--require-non-oracle-pass`` lets the enablement step gate on the stratum that
actually matters instead of the pooled one.

Stratum membership is derived exactly as the Judge derives precedence: a label is oracle-backed
iff its evidence envelope's trusted block carries any ``hit: true``.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_GROUND_TRUTH = _ROOT / "evals" / "ground-truth"

_POSITIVE_STATES = frozenset({"EXPLOIT_CONFIRMED", "EXPLOIT_LIKELY"})
_NEGATIVE_STATES = frozenset({"NO_EXPLOIT_OBSERVED"})
_ABSTENTION_STATES = frozenset({"INDETERMINATE", "ERROR"})


class AnalysisError(RuntimeError):
    """The calibration artifact and the ground-truth slices could not be reconciled."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--calibration",
        type=Path,
        required=True,
        help="a judge_calibration.json artifact produced by scripts/run_judge_calibration.py",
    )
    parser.add_argument(
        "--slice-dir",
        type=Path,
        default=_GROUND_TRUTH,
        help="the ground-truth slice directory the artifact was measured over",
    )
    parser.add_argument(
        "--batch-manifest",
        type=Path,
        help=(
            "batch-manifest.json from scripts/merge_calibration_batches.py. Adds per-sub-run "
            "metrics so one bad batch is visible instead of averaged into the aggregate"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the full report as JSON here (stdout stays human-readable)",
    )
    parser.add_argument(
        "--require-non-oracle-pass",
        action="store_true",
        help=(
            "exit 2 unless the NON-ORACLE stratum satisfies the artifact's own thresholds. The "
            "pooled headline can pass while this stratum fails; enablement should gate on this"
        ),
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    artifact = _read_json(args.calibration)
    labels = _load_labels(args.slice_dir)
    batch_manifest = None if args.batch_manifest is None else _read_json(args.batch_manifest)
    report = build_report(artifact, labels, batch_manifest=batch_manifest)

    if args.output is not None:
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    _render(report)

    if args.require_non_oracle_pass and report["non_oracle"]["breaches"]:
        return 2
    return 0


def build_report(
    artifact: Mapping[str, Any],
    labels: Mapping[str, Mapping[str, Any]],
    *,
    batch_manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Split the artifact's own samples by runtime authority and recompute honestly."""

    samples = artifact["sample_results"]
    thresholds = artifact["thresholds"]
    missing = sorted({sample["label_id"] for sample in samples} - set(labels))
    if missing:
        raise AnalysisError(
            f"{len(missing)} calibration samples have no matching ground-truth label "
            f"(first: {missing[0]}); the artifact and the slice directory disagree"
        )

    enriched = [
        {**sample, "oracle_backed": labels[sample["label_id"]]["oracle_backed"]}
        for sample in samples
    ]
    oracle = [item for item in enriched if item["oracle_backed"]]
    non_oracle = [item for item in enriched if not item["oracle_backed"]]

    return {
        "calibration_id": artifact["calibration_id"],
        "identity_sha256": artifact["identity_sha256"],
        "slice_set_sha256": artifact["slice_set_sha256"],
        "judge_identity": artifact["judge_identity"],
        "state": artifact["state"],
        "thresholds": thresholds,
        "pooled": {
            **_metrics(enriched),
            "reported_by_artifact": artifact["metrics"],
            "breaches": _breaches(_metrics(enriched), thresholds),
        },
        "oracle_backed": {
            **_metrics(oracle),
            "runtime_authority": (
                "deterministic — a trusted hit fixes the verdict in code; the model cannot "
                "change these outcomes, so their agreement is not evidence about the model"
            ),
        },
        "non_oracle": {
            **_metrics(non_oracle),
            "runtime_authority": (
                "the model — this is the ONLY stratum an enabled model Judge decides, and the "
                "only one where enabling it changes an outcome"
            ),
            "breaches": _breaches(_metrics(non_oracle), thresholds),
        },
        "non_oracle_by_category": [
            {"category": category, "metrics": _metrics(items)}
            for category, items in sorted(_by_category(non_oracle).items())
        ],
        "by_batch": _batch_metrics(enriched, batch_manifest),
    }


def _batch_metrics(
    samples: Sequence[Mapping[str, Any]],
    batch_manifest: Mapping[str, Any] | None,
) -> list[dict[str, Any]] | None:
    """Per-sub-run metrics, so a single bad batch is visible rather than averaged away.

    The aggregate over a batched campaign is the number that governs, but it can hide a sub-run
    that went wrong — a provider degradation partway through, a truncated batch. Reporting each
    batch alongside makes that legible without changing what the aggregate is.
    """

    if batch_manifest is None:
        return None
    assignment = batch_manifest.get("label_to_batch")
    if not isinstance(assignment, Mapping):
        raise AnalysisError("the batch manifest carries no label_to_batch mapping")

    unassigned = sorted({s["label_id"] for s in samples} - set(assignment))
    if unassigned:
        raise AnalysisError(
            f"{len(unassigned)} scored samples are in no batch (first: {unassigned[0]}); the "
            "manifest and the artifact describe different campaigns"
        )

    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for sample in samples:
        grouped[str(assignment[sample["label_id"]])].append(sample)
    return [
        {
            "batch": source,
            "metrics": _metrics(items),
            "non_oracle_metrics": _metrics([i for i in items if not i["oracle_backed"]]),
        }
        for source, items in sorted(grouped.items())
    ]


def _metrics(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = len(samples)
    expected_positive = [s for s in samples if s["expected_state"] in _POSITIVE_STATES]
    expected_negative = [s for s in samples if s["expected_state"] in _NEGATIVE_STATES]
    expected_abstain = [s for s in samples if s["expected_state"] in _ABSTENTION_STATES]

    agreements = sum(s["agreement"] is True for s in samples)
    false_negatives = sum(s["false_negative"] is True for s in samples)
    false_positives = sum(s["false_positive"] is True for s in samples)
    abstentions = sum(s["abstained"] is True for s in samples)

    # The two failure modes the contract's counters cannot express.
    safe_misses = sum(
        s["expected_state"] in _POSITIVE_STATES and s["actual_state"] in _NEGATIVE_STATES
        for s in samples
    )
    abstain_on_positive = sum(
        s["expected_state"] in _POSITIVE_STATES and s["actual_state"] in _ABSTENTION_STATES
        for s in samples
    )
    over_calls = sum(
        s["expected_state"] in _ABSTENTION_STATES and s["actual_state"] in _POSITIVE_STATES
        for s in samples
    )

    return {
        "sample_count": total,
        "expected_positive_count": len(expected_positive),
        "expected_negative_count": len(expected_negative),
        "expected_abstain_count": len(expected_abstain),
        "agreement_count": agreements,
        "agreement_rate": _ratio(agreements, total),
        "false_negative_count": false_negatives,
        "false_negative_rate": _ratio(false_negatives, len(expected_positive)),
        "false_positive_count": false_positives,
        "false_positive_rate": _ratio(false_positives, len(expected_negative)),
        "abstention_count": abstentions,
        "abstention_rate": _ratio(abstentions, total),
        # A positive scored "safe" is the only outcome that can silently clear a real exploit.
        # A positive that degrades to INDETERMINATE is contained: is_safe() is false for it.
        "safe_miss_count": safe_misses,
        "safe_miss_rate": _ratio(safe_misses, len(expected_positive)),
        "abstain_on_positive_count": abstain_on_positive,
        # Invisible to false_positive_rate, which only scores expected-SAFE samples.
        "over_call_on_ambiguous_count": over_calls,
        "over_call_on_ambiguous_rate": _ratio(over_calls, len(expected_abstain)),
    }


def _breaches(metrics: Mapping[str, Any], thresholds: Mapping[str, Any]) -> list[str]:
    if metrics["sample_count"] == 0:
        return ["stratum_empty"]
    checks = (
        (metrics["agreement_rate"] < thresholds["min_agreement_rate"], "agreement_below_threshold"),
        (
            metrics["false_positive_rate"] > thresholds["max_false_positive_rate"],
            "false_positive_rate_exceeded",
        ),
        (
            metrics["false_negative_rate"] > thresholds["max_false_negative_rate"],
            "false_negative_rate_exceeded",
        ),
        (
            metrics["abstention_rate"] > thresholds["max_abstention_rate"],
            "abstention_rate_exceeded",
        ),
        (metrics["safe_miss_count"] > 0, "positive_scored_safe"),
    )
    return [code for failed, code in checks if failed]


def _by_category(
    samples: Sequence[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for sample in samples:
        grouped[sample["category"]].append(sample)
    return grouped


def _ratio(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else numerator / denominator


def _load_labels(slice_dir: Path) -> dict[str, dict[str, Any]]:
    """Index every ground-truth label and mark whether the Judge would decide it in code."""

    candidates = sorted(slice_dir.glob("*.json"))
    if not candidates:
        raise AnalysisError(f"no ground-truth slices under {slice_dir}")
    labels: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        payload = _read_json(candidate)
        if not isinstance(payload, Mapping) or "labels" not in payload:
            continue
        for label in payload["labels"]:
            envelope = label.get("evidence_envelope") or {}
            trusted = envelope.get("trusted") or {}
            labels[label["label_id"]] = {
                "category": payload.get("category"),
                "sample_kind": label.get("sample_kind"),
                # Exactly the Judge's rule-2 test, over the same trusted block.
                "oracle_backed": _any_hit(trusted.get("canary_hits"))
                or _any_hit(trusted.get("oracle_results")),
            }
    if not labels:
        raise AnalysisError(f"ground-truth slices under {slice_dir} contain no labels")
    return labels


def _any_hit(signals: Any) -> bool:
    if not isinstance(signals, list):
        return False
    return any(isinstance(signal, Mapping) and signal.get("hit") is True for signal in signals)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise AnalysisError(f"{path} is unreadable or not valid JSON") from exc


def _render(report: Mapping[str, Any]) -> None:
    identity = report["judge_identity"]
    print(f"calibration {report['calibration_id']}  state={report['state']}")
    print(f"  evaluator  {identity['judge_model']} via {identity['judge_provider']}")
    print(f"  identity   {report['identity_sha256']}")
    print(f"  model ver  {identity['judge_model_version']}")
    print()
    header = (
        f"{'stratum':<14}{'n':>5}{'agree':>9}{'FN':>8}{'FP':>8}{'safe-miss':>11}{'over-call':>11}"
    )
    print(header)
    print("-" * len(header))
    for key, name in (
        ("pooled", "pooled"),
        ("oracle_backed", "oracle-backed"),
        ("non_oracle", "NON-ORACLE"),
    ):
        m = report[key]
        print(
            f"{name:<14}{m['sample_count']:>5}"
            f"{m['agreement_rate']:>9.4f}"
            f"{m['false_negative_rate']:>8.4f}"
            f"{m['false_positive_rate']:>8.4f}"
            f"{m['safe_miss_count']:>11}"
            f"{m['over_call_on_ambiguous_count']:>11}"
        )
    if report.get("by_batch"):
        print()
        print(f"{'per batch':<14}{'n':>5}{'agree':>9}{'non-oracle n':>14}{'non-oracle agree':>18}")
        print("-" * 60)
        for batch in report["by_batch"]:
            m, nm = batch["metrics"], batch["non_oracle_metrics"]
            name = batch["batch"].rsplit("/", 1)[-1][:13]
            print(
                f"{name:<14}{m['sample_count']:>5}{m['agreement_rate']:>9.4f}"
                f"{nm['sample_count']:>14}{nm['agreement_rate']:>18.4f}"
            )
        print("(the aggregate above governs; batches are shown so one bad sub-run is visible)")
    print()
    print("oracle-backed rows are decided in code; only the NON-ORACLE row moves when the")
    print("model Judge is enabled. Gate enablement on that row.")
    breaches = report["non_oracle"]["breaches"]
    print()
    if breaches:
        print(f"NON-ORACLE STRATUM BREACHES: {', '.join(breaches)}")
    else:
        print("non-oracle stratum satisfies the artifact's own thresholds")


if __name__ == "__main__":
    raise SystemExit(main())
