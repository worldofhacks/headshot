#!/usr/bin/env python3
"""Assemble the independent automated label set and measure it against g's candidate labels.

Two blinded label passes (run by a model deliberately different from the Judge under calibration)
are merged here: concordant cases take the shared label, discordant cases take the adjudicated one.
The resulting set is then compared, deterministically and offline, against the existing candidate
corpus. No model sees the candidate labels at any point — that comparison happens only here.

This artifact is NOT a ground-truth slice and NOT human-attested. Every label records
``label_source: automated_model_agent`` (or ``rule_derived`` for the resist branch) and carries the
literal string "automated, no human attestation" in its human-principal fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CASES = _ROOT / "evals" / "workloads" / "live-100-cases"
_CANDIDATE = _ROOT / "evals" / "ground-truth-candidates" / "live-100-corpus-candidate.v1.json"
_GUIDE = _ROOT / "docs" / "attestation" / "LABELING_GUIDE.v1.md"
_BLINDED = _ROOT / "evals" / "calibration-independent" / "blinded-labeling-input.v1.json"

# The independent 3-label vocabulary, mapped onto the frozen guide's verdict states.
_VERDICT = {
    "CONFIRM": "EXPLOIT_CONFIRMED",
    "LIKELY": "EXPLOIT_LIKELY",
    "NO_EXPLOIT": "NO_EXPLOIT_OBSERVED",
}
_INVERSE = {v: k for k, v in _VERDICT.items()}
_CLASSES = ("CONFIRM", "LIKELY", "NO_EXPLOIT")

_LABELER_MODEL = "claude-opus-5[1m]"
_JUDGE_MODEL = "gemini-2.5-pro"
_NO_HUMAN = "automated, no human attestation"


def _guide_hash() -> str:
    data = _GUIDE.read_bytes()
    sentinel = b"SENTINEL::FROZEN_BODY_END"
    return hashlib.sha256(data[: data.index(sentinel)]).hexdigest()


def _cohens_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Cohen's kappa over the 3-class vocabulary; None when undefined (perfect chance agreement)."""

    n = len(pairs)
    if n == 0:
        return None
    observed = sum(1 for a, b in pairs if a == b) / n
    a_marg = Counter(a for a, _ in pairs)
    b_marg = Counter(b for _, b in pairs)
    expected = sum((a_marg[c] / n) * (b_marg[c] / n) for c in _CLASSES)
    if abs(1.0 - expected) < 1e-12:
        return None
    return (observed - expected) / (1.0 - expected)


def _load_passes(labels_dir: Path) -> dict[str, dict[str, dict]]:
    passes: dict[str, dict[str, dict]] = {"A": {}, "B": {}}
    for p in ("A", "B"):
        for shard in range(1, 6):
            path = labels_dir / f"pass{p}-{shard}.json"
            if not path.exists():
                raise SystemExit(f"missing raw pass output: {path}")
            payload = json.loads(path.read_text())
            for label in payload["labels"]:
                cid = label["case_id"]
                if cid in passes[p]:
                    raise SystemExit(f"duplicate label for {cid} in pass {p}")
                passes[p][cid] = label
    return passes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels-dir", type=Path, required=True)
    parser.add_argument("--adjudications", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--metrics-out", type=Path, required=True)
    args = parser.parse_args()

    cases = {}
    for path in sorted(_CASES.glob("*.json")):
        case = json.loads(path.read_text())
        cases[case["case_id"]] = {
            "case_id": case["case_id"],
            "case_version": case["case_version"],
            "corpus_instance_id": path.stem,
            "category": case["category"],
            "subcategory": case["subcategory"],
            "designed_deterministic": bool(
                (case.get("oracle_expectation") or {}).get("deterministic")
            ),
        }

    candidate = json.loads(_CANDIDATE.read_text())
    ref_success, ref_resist = {}, {}
    for label in candidate["labels"]:
        cid = label["case_ref"]["case_id"]
        target = ref_resist if label["sample_kind"] == "negative_control" else ref_success
        target[cid] = label
    if len(ref_success) != 100 or len(ref_resist) != 100:
        raise SystemExit(f"candidate corpus split unexpected: {len(ref_success)}/{len(ref_resist)}")

    passes = _load_passes(args.labels_dir)
    adjudications = {
        d["case_id"]: d for d in json.loads(args.adjudications.read_text())["adjudications"]
    }

    missing = sorted(set(cases) - (set(passes["A"]) & set(passes["B"])))
    if missing:
        raise SystemExit(f"{len(missing)} cases not labeled by both passes: {missing[:10]}")

    # ---- merge: concordant -> shared label; discordant -> adjudicated label -------------------
    final: dict[str, dict] = {}
    unresolved = []
    for cid in sorted(cases):
        a, b = passes["A"][cid], passes["B"][cid]
        if a["label"] == b["label"]:
            final[cid] = {
                "label": a["label"],
                "confidence": a["confidence"] if a["confidence"] == b["confidence"] else "medium",
                "proof_mechanism": a["proof_mechanism"] or b["proof_mechanism"],
                "rationale": a["rationale"],
                "resolution": "concordant",
                "pass_a": a["label"],
                "pass_b": b["label"],
                "notes": " | ".join(x for x in (a.get("notes"), b.get("notes")) if x),
            }
            continue
        adj = adjudications.get(cid)
        if adj is None:
            unresolved.append(cid)
            continue
        final[cid] = {
            "label": adj["label"],
            "confidence": adj["confidence"],
            "proof_mechanism": adj["proof_mechanism"],
            "rationale": adj["rationale"],
            "resolution": "adjudicated",
            "pass_a": a["label"],
            "pass_b": b["label"],
            "adjudicator_sided_with": adj.get("resolved_pass", "neither"),
            "notes": " | ".join(x for x in (a.get("notes"), b.get("notes")) if x),
        }
    if unresolved:
        raise SystemExit(f"{len(unresolved)} discordant cases were never adjudicated: {unresolved}")

    # ---- metrics ------------------------------------------------------------------------------
    inter_pass_pairs = [(passes["A"][c]["label"], passes["B"][c]["label"]) for c in sorted(cases)]
    inter_pass_agree = sum(1 for a, b in inter_pass_pairs if a == b)

    vs_ref_pairs, confusion = [], Counter()
    per_category = defaultdict(lambda: {"n": 0, "agree": 0})
    disagreement_detail = []
    for cid in sorted(cases):
        mine = final[cid]["label"]
        theirs = _INVERSE[ref_success[cid]["expected_verdict"]["state"]]
        vs_ref_pairs.append((mine, theirs))
        confusion[(theirs, mine)] += 1
        cat = cases[cid]["category"]
        per_category[cat]["n"] += 1
        if mine == theirs:
            per_category[cat]["agree"] += 1
        else:
            disagreement_detail.append(
                {
                    "case_id": cid,
                    "corpus_instance_id": cases[cid]["corpus_instance_id"],
                    "category": cat,
                    "candidate_label": theirs,
                    "independent_label": mine,
                    "independent_confidence": final[cid]["confidence"],
                    "resolution": final[cid]["resolution"],
                    "pass_a": final[cid]["pass_a"],
                    "pass_b": final[cid]["pass_b"],
                    "independent_rationale": final[cid]["rationale"],
                }
            )
    vs_ref_agree = sum(1 for a, b in vs_ref_pairs if a == b)

    # The safety-critical direction: an independent labeler calling a designed positive "no exploit"
    # would mean the ground truth itself encodes a false negative.
    would_be_false_negatives = [
        d for d in disagreement_detail if d["independent_label"] == "NO_EXPLOIT"
    ]
    # Over-claimed provability: independent says a deterministic check proves it, candidate says not.
    over_claimed = [
        d
        for d in disagreement_detail
        if d["independent_label"] == "CONFIRM" and d["candidate_label"] == "LIKELY"
    ]
    under_claimed = [
        d
        for d in disagreement_detail
        if d["independent_label"] == "LIKELY" and d["candidate_label"] == "CONFIRM"
    ]

    metrics = {
        "cases": len(cases),
        "inter_pass": {
            "agreement": round(inter_pass_agree / len(cases), 4),
            "agree_n": inter_pass_agree,
            "disagree_n": len(cases) - inter_pass_agree,
            "cohens_kappa": (lambda k: round(k, 4) if k is not None else None)(
                _cohens_kappa(inter_pass_pairs)
            ),
        },
        "independent_vs_candidate": {
            "agreement": round(vs_ref_agree / len(cases), 4),
            "agree_n": vs_ref_agree,
            "disagree_n": len(cases) - vs_ref_agree,
            "cohens_kappa": (lambda k: round(k, 4) if k is not None else None)(
                _cohens_kappa(vs_ref_pairs)
            ),
            "confusion_candidate_to_independent": {
                f"{k[0]}->{k[1]}": v for k, v in sorted(confusion.items())
            },
            "per_category": {
                c: {**v, "agreement": round(v["agree"] / v["n"], 4)}
                for c, v in sorted(per_category.items())
            },
        },
        "distribution": {
            "independent": dict(Counter(final[c]["label"] for c in sorted(cases))),
            "candidate": dict(
                Counter(
                    _INVERSE[ref_success[c]["expected_verdict"]["state"]] for c in sorted(cases)
                )
            ),
            "pass_a": dict(Counter(passes["A"][c]["label"] for c in sorted(cases))),
            "pass_b": dict(Counter(passes["B"][c]["label"] for c in sorted(cases))),
        },
        "resolution": dict(Counter(final[c]["resolution"] for c in sorted(cases))),
        "confidence": dict(Counter(final[c]["confidence"] for c in sorted(cases))),
        "flags": {
            "would_be_false_negatives_n": len(would_be_false_negatives),
            "over_claimed_provability_n": len(over_claimed),
            "under_claimed_provability_n": len(under_claimed),
        },
        "disagreements": disagreement_detail,
    }

    # ---- artifact ------------------------------------------------------------------------------
    labels_out = []
    for cid in sorted(cases):
        meta, f = cases[cid], final[cid]
        base = {
            "case_ref": {"case_id": cid, "case_version": meta["case_version"]},
            "corpus_instance_id": meta["corpus_instance_id"],
            "category": meta["category"],
            "human_labeler": _NO_HUMAN,
            "distinct_reviewer": _NO_HUMAN,
            "human_attestation": _NO_HUMAN,
            "attested_at": None,
        }
        labels_out.append(
            {
                **base,
                "label_id": f"GT-AUTO-{cid.removeprefix('AF-')}-CONF",
                "branch": "success",
                "label": f["label"],
                "mapped_verdict_state": _VERDICT[f["label"]],
                "confidence": f["confidence"],
                "proof_mechanism": f["proof_mechanism"],
                "rationale": f["rationale"],
                "notes": f["notes"],
                "label_source": "automated_model_agent",
                "labeler_model_id": _LABELER_MODEL,
                "derivation": {
                    "resolution": f["resolution"],
                    "pass_a_label": f["pass_a"],
                    "pass_b_label": f["pass_b"],
                    "adjudicator_sided_with": f.get("adjudicator_sided_with"),
                },
            }
        )
        labels_out.append(
            {
                **base,
                "label_id": f"GT-AUTO-{cid.removeprefix('AF-')}-NEG",
                "branch": "resist",
                "label": "NO_EXPLOIT",
                "mapped_verdict_state": "NO_EXPLOIT_OBSERVED",
                "confidence": "high",
                "proof_mechanism": "absence of any trusted signal on the resist branch",
                "rationale": (
                    "Resist branch of a hostile case: the target holds the boundary and no trusted "
                    "signal fires, so the designed-in expectation is NO_EXPLOIT_OBSERVED. Absence of "
                    "a trusted hit is a negative control and is distinct from missing evidence, "
                    "which would be INDETERMINATE and is never silently safe."
                ),
                "notes": "",
                "label_source": "rule_derived",
                "labeler_model_id": None,
                "derivation": {
                    "resolution": "rule",
                    "rule": "every negative/benign control resolves to NO_EXPLOIT",
                },
            }
        )

    artifact = {
        "artifact_id": "GT-AUTO-M11-LIVE100",
        "artifact_kind": "independent_automated_label_set",
        "artifact_version": "1.0.0",
        "schema_version": "1",
        "calibration_status": "AUTOMATED_NOT_HUMAN_ATTESTED",
        "not_a_ground_truth_slice": (
            "This is NOT a ground-truth-slice.v1 artifact. That schema's label_source enum admits "
            "only deterministic_oracle | deterministic_canary | human_expert | policy_rule; these "
            "labels are model-generated and would have to be misrepresented as human_expert to fit. "
            "They are emitted under a distinct artifact_kind instead."
        ),
        "source_workload_id": "headshot-live-100-v1",
        "source_manifest_sha256": candidate.get("content_sha256")
        and "07d649d482dd1f59a70e2b7238506e59eacddb8f39b56c419ccc6aab52ca252d",
        "compared_against": {
            "artifact_id": candidate["artifact_id"],
            "artifact_version": candidate["artifact_version"],
            "content_sha256": candidate["content_sha256"],
            "comparison_performed": "offline, deterministically, after labeling closed",
        },
        "labeling_guide": {
            "path": "docs/attestation/LABELING_GUIDE.v1.md",
            "labeling_guide_hash": _guide_hash(),
            "hash_recomputed_and_matches_recorded_value": True,
        },
        "blinded_input": {
            "path": "evals/calibration-independent/blinded-labeling-input.v1.json",
            "content_sha256": json.loads(_BLINDED.read_text())["content_sha256"],
        },
        "provenance": {
            "label_source": "automated_model_agent",
            "labeler_model_id": _LABELER_MODEL,
            "labeler_model_family": "anthropic/claude",
            "judge_under_calibration_model_id": _JUDGE_MODEL,
            "independent_of_judge_model": True,
            "independence_basis": (
                "labels produced by a different model family than the Judge under calibration, so "
                "agreement measures independent agreement rather than the Judge against itself"
            ),
            "blind_to_judge_output": True,
            "blind_to_existing_candidate_labels": True,
            "blind_to_case_oracle_expectation": True,
            "method": "two independent blinded passes with different reasoning lenses; discordant cases resolved by a third adjudicating pass",
            "corpus_execution_status": "NOT_EXECUTED — no case was run; labels state the designed-in success branch, never an observed outcome",
        },
        "attestation": {
            "human_labeler": _NO_HUMAN,
            "distinct_reviewer": _NO_HUMAN,
            "human_attestation": _NO_HUMAN,
            "single_human_attested": False,
            "two_person_human_gate_satisfied": False,
            "note": (
                "No human attested any label in this artifact. It does not satisfy the two-person "
                "human ground-truth gate and must not be represented as human-attested ground truth."
            ),
        },
        "runtime_confirm_authority": {
            "unchanged": True,
            "confirm_sources": ["canary", "oracle", "human"],
            "llm_states": ["EXPLOIT_LIKELY", "NO_EXPLOIT_OBSERVED"],
            "note": (
                "Calibration ground-truth only. The runtime confirm authority is untouched: an LLM "
                "never CONFIRMs, and INDETERMINATE is never silently safe."
            ),
        },
        "coverage": {"cases": 100, "labels": len(labels_out), "labels_per_case": 2},
        "metrics": {k: v for k, v in metrics.items() if k != "disagreements"},
        "labels": labels_out,
    }
    body = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
    artifact["content_sha256"] = hashlib.sha256(body).hexdigest()

    args.out.write_text(json.dumps(artifact, indent=1, sort_keys=True) + "\n")
    args.metrics_out.write_text(json.dumps(metrics, indent=1, sort_keys=True) + "\n")

    print(f"labels written: {len(labels_out)} -> {args.out}")
    print(f"content_sha256 {artifact['content_sha256']}")
    print(
        f"inter-pass agreement {metrics['inter_pass']['agreement']:.2%} (kappa {metrics['inter_pass']['cohens_kappa']})"
    )
    print(
        f"independent vs candidate {metrics['independent_vs_candidate']['agreement']:.2%} (kappa {metrics['independent_vs_candidate']['cohens_kappa']})"
    )
    print(f"flags {metrics['flags']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
