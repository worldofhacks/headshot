#!/usr/bin/env python3
"""Build blinded labeling inputs for the independent (non-Judge-model) calibration pass.

The blinded view carries the attack's substance and the target surface, and strips every field
that states the designed-in answer: the oracle expectation block, the expected-evidence signal
lists, the ground-truth label refs, and any literal seeded-marker token or detector identifier
that leaks out of free text.

Redaction is verified, not assumed: ``--verify`` re-scans the emitted views and fails if any
tell survives.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CASES = _ROOT / "evals" / "workloads" / "live-100-cases"

# Fields removed wholesale: each states or directly implies the designed-in verdict.
_DROP_TOP_LEVEL = frozenset(
    {
        "oracle_expectation",
        "expected_evidence",
        "ground_truth_refs",
        "execution_status",
        "observed_behavior",
        "result_kind",
        "result_ref",
        "regression_promotion",
        "lifecycle_status",
        "artifact_kind",
        "schema_version",
        "case_version",
        "fixture_provenance",
        "authorization_posture",
        "expected_typed_failure",
    }
)

_CANARY_TOKEN = re.compile(r"SYNTH_CANARY_[A-Z0-9_]+")
_DETECTOR_ID = re.compile(r"\b(?:offline|recorder)-[a-z0-9-]+-v\d+\b")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
_TELL_WORD = re.compile(r"\b(?:oracle|detector)\b", re.IGNORECASE)


def _redact(text: str) -> str:
    """Strip literal detector identity from attack-substance prose, leaving the attack intact."""

    text = _CANARY_TOKEN.sub("[SEEDED_MARKER]", text)
    return _DETECTOR_ID.sub("[DETECTOR]", text)


# ``target_surface.attack_surface`` and ``test_design.adversarial_condition`` exist to state HOW a
# success would be proven ("...caught deterministically as SYNTH_CANARY_X by the <id> oracle"), i.e.
# the designed-in answer. They are dropped from EVERY case rather than sentence-scrubbed: scrubbing
# empties them only for the canary-backed cases, which would make emptiness itself the tell.
_DROP_ANSWER_ADJACENT = ("target_surface.attack_surface", "test_design.adversarial_condition")


def _blind(case: dict) -> dict:
    kept = {k: v for k, v in case.items() if k not in _DROP_TOP_LEVEL}
    surface = kept.get("target_surface", {})
    design = kept.get("test_design", {})
    view = {
        "case_id": kept["case_id"],
        "category": kept["category"],
        "subcategory": kept["subcategory"],
        "sequence_type": kept["sequence_type"],
        "adversarial_goal": _redact(kept["adversarial_goal"]),
        "input_sequence": [_redact(t) for t in kept["input_sequence"]],
        "input_sequence_trust": kept["input_sequence_trust"],
        "expected_safe_behavior": _redact(kept["expected_safe_behavior"]),
        "target_surface": {
            "capability": surface.get("capability"),
            "trust_boundary": surface.get("trust_boundary"),
        },
        "test_design": {
            "classification": design.get("classification"),
            "security_property": _redact(design.get("security_property", "")),
            "failure_condition": _redact(design.get("failure_condition", "")),
        },
        "exploitability": {
            "rating": kept.get("exploitability", {}).get("rating"),
            "preconditions": [
                _redact(p) for p in kept.get("exploitability", {}).get("preconditions", [])
            ],
        },
        "severity_rating": kept.get("severity", {}).get("rating"),
        "owasp": [f"{o['framework']} {o['id']} {o['name']}" for o in kept.get("owasp", [])],
    }
    return view


def _scan_tells(view: dict) -> list[str]:
    blob = json.dumps(view)
    tells = []
    if _CANARY_TOKEN.search(blob):
        tells.append("canary_token")
    if _DETECTOR_ID.search(blob):
        tells.append("detector_id")
    if "attack_surface" in view["target_surface"] or "adversarial_condition" in view["test_design"]:
        tells.append("answer_adjacent_field_survived")
    for banned in ("deterministic", "expected_verdict", "EXPLOIT_CONFIRMED", "ground_truth"):
        if banned in blob:
            tells.append(f"banned:{banned}")
    return tells


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="output JSON path")
    args = parser.parse_args()

    views = []
    for path in sorted(_CASES.glob("*.json")):
        case = json.loads(path.read_text())
        view = _blind(case)
        view["corpus_instance_id"] = path.stem
        tells = _scan_tells(view)
        if tells:
            raise SystemExit(
                f"blinding failed for {path.stem}: residual tells {sorted(set(tells))}"
            )
        for field in ("adversarial_goal", "expected_safe_behavior"):
            if not view[field]:
                raise SystemExit(f"blinding emptied {field} for {path.stem}")
        views.append(view)

    if len(views) != 100:
        raise SystemExit(f"expected 100 blinded views, got {len(views)}")

    payload = {
        "artifact_kind": "blinded_labeling_input",
        "schema_version": "1",
        "source_workload_id": "headshot-live-100-v1",
        "cases": views,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["content_sha256"] = hashlib.sha256(body).hexdigest()
    args.out.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n")
    print(f"wrote {len(views)} blinded views -> {args.out}")
    print(f"content_sha256 {payload['content_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
