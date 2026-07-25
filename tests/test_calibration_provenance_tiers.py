"""A weaker calibration baseline may be accepted, but never disguised as a stronger one.

A deadline can legitimately force enabling against rule-derived labels and an unreconciled bundle.
The failure to prevent is the one the superseded 8ce852b artifact made: correct arithmetic, read
later as stronger evidence than it was. So the tier is computed from the evidence, the accepting
human must name the floor, and the accepted tiers are written into the artifact itself.
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

import pytest

from agentforge.agents.judge.provenance import (
    GROUND_TRUTH_TIERS,
    PROVIDER_TIERS,
    ProvenanceError,
    classify_ground_truth,
    classify_provider_provenance,
    decode_approver_ref,
    disclosure,
    encode_approver_ref,
    is_at_least,
)

ROOT = Path(__file__).resolve().parents[1]


def _label(**overrides: object) -> dict[str, object]:
    label = {"label_id": "L-1", "label_source": "policy_rule"}
    label.update(overrides)
    return label


def _slices(labels: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{"category": "prompt_injection", "labels": labels}]


def _sample(index: int) -> dict[str, object]:
    return {
        "label_id": f"L-{index}",
        "provider_request_id": f"gen-178493430{index}-yDHN8gAVdjgNMKHf{index}",
        "returned_model": "google/gemini-2.5-pro",
        "input_tokens": 1000 + index,
        "output_tokens": 100 + index,
        "reasoning_tokens": 1400 + index,
        "measured_cost_usd": f"0.017{index}",
    }


# --- ordering ----------------------------------------------------------------------------


def test_tiers_are_ordered_strongest_first() -> None:
    assert GROUND_TRUTH_TIERS[0] == "human_two_person"
    assert GROUND_TRUTH_TIERS[-1] == "unattested"
    assert PROVIDER_TIERS[0] == "usage_export_reconciled"
    assert PROVIDER_TIERS[-1] == "unverified"
    assert is_at_least("human_two_person", "rule_derived", GROUND_TRUTH_TIERS)
    assert is_at_least("rule_derived", "rule_derived", GROUND_TRUTH_TIERS)
    assert not is_at_least("unattested", "rule_derived", GROUND_TRUTH_TIERS)


def test_an_unknown_tier_is_refused_rather_than_ranked() -> None:
    with pytest.raises(ProvenanceError, match="not a recognised provenance tier"):
        is_at_least("pretty_good", "rule_derived", GROUND_TRUTH_TIERS)


# --- ground truth ------------------------------------------------------------------------


def test_the_committed_corpus_classifies_as_rule_derived_not_ground_truth() -> None:
    """What is actually on disk, named accurately."""

    slices = [
        json.loads(Path(path).read_text(encoding="utf-8"))
        for path in sorted(glob.glob(str(ROOT / "evals" / "ground-truth" / "*.json")))
    ]

    tier, evidence = classify_ground_truth(slices)

    assert tier == "rule_derived"
    assert evidence["label_count"] == 54
    assert set(evidence["label_sources"]) == {
        "policy_rule",
        "deterministic_oracle",
        "deterministic_canary",
    }
    # No label names a labelling model, so "model_labeled" would be a false attribution.
    assert "labeling_models" not in evidence


def test_a_complete_two_person_attestation_earns_the_top_tier() -> None:
    tier, _ = classify_ground_truth(
        _slices([_label()]),
        attestation={
            "blind_to_judge_output": True,
            "human_labeler": {"id": "headshot:alex", "attested_at": "2026-07-25T12:00:00+00:00"},
            "distinct_reviewer": {"id": "headshot:jo", "attested_at": "2026-07-25T13:00:00+00:00"},
        },
    )
    assert tier == "human_two_person"


@pytest.mark.parametrize(
    "attestation",
    [
        pytest.param(
            {
                "blind_to_judge_output": True,
                "human_labeler": {"id": "headshot:alex", "attested_at": "t"},
                "distinct_reviewer": None,
            },
            id="reviewer-missing",
        ),
        pytest.param(
            {
                "blind_to_judge_output": True,
                "human_labeler": {"id": "headshot:alex", "attested_at": "t"},
                "distinct_reviewer": {"id": "headshot:alex", "attested_at": "t"},
            },
            id="same-principal-twice",
        ),
        pytest.param(
            {
                "blind_to_judge_output": False,
                "human_labeler": {"id": "headshot:alex", "attested_at": "t"},
                "distinct_reviewer": {"id": "headshot:jo", "attested_at": "t"},
            },
            id="not-blind",
        ),
        pytest.param(
            {
                "blind_to_judge_output": True,
                "human_labeler": {"id": "headshot:alex"},
                "distinct_reviewer": {"id": "headshot:jo", "attested_at": "t"},
            },
            id="no-timestamp",
        ),
    ],
)
def test_a_partial_attestation_cannot_buy_the_top_tier(attestation: dict[str, object]) -> None:
    """It falls through to what the labels support, rather than being honoured as human."""

    tier, _ = classify_ground_truth(_slices([_label()]), attestation=attestation)
    assert tier == "rule_derived"


def test_model_labeled_requires_every_label_to_name_its_model() -> None:
    all_named = _slices(
        [
            _label(label_id="L-1", labeling_model="anthropic/claude-opus-4.8"),
            _label(label_id="L-2", labeling_model="anthropic/claude-opus-4.8"),
        ]
    )
    assert classify_ground_truth(all_named)[0] == "model_labeled"

    partly_named = _slices(
        [_label(label_id="L-1", labeling_model="anthropic/claude-opus-4.8"), _label(label_id="L-2")]
    )
    assert classify_ground_truth(partly_named)[0] == "rule_derived"


def test_labels_with_no_source_at_all_are_unattested() -> None:
    tier, _ = classify_ground_truth(_slices([_label(label_source=None)]))
    assert tier == "unattested"


# --- provider calls ----------------------------------------------------------------------


def test_the_committed_bundle_earns_lineage_consistent_but_not_measured() -> None:
    """Exactly the claim I am entitled to make about the 54 calls without an export."""

    bundle = json.loads(
        (
            ROOT / "evals" / "results" / "judge-calibration-20260724" / "captured-results.json"
        ).read_text(encoding="utf-8")
    )

    tier, evidence = classify_provider_provenance(bundle)

    assert tier == "lineage_consistent"
    assert evidence["sample_count"] == 54
    assert all(evidence["checks"].values())


def test_a_reconciliation_earns_the_measured_tier() -> None:
    bundle = {"samples": [_sample(1), _sample(2)]}
    tier, _ = classify_provider_provenance(
        bundle,
        attestation={
            "attestation_kind": "openrouter_usage_export_reconciled",
            "matched_generation_count": 2,
        },
    )
    assert tier == "usage_export_reconciled"


def test_a_reconciliation_covering_fewer_samples_does_not_earn_it() -> None:
    bundle = {"samples": [_sample(1), _sample(2)]}
    tier, _ = classify_provider_provenance(
        bundle,
        attestation={
            "attestation_kind": "openrouter_usage_export_reconciled",
            "matched_generation_count": 1,
        },
    )
    assert tier == "lineage_consistent"


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        pytest.param(
            lambda s: [{**s[0], "provider_request_id": "FABRICATED"}, s[1]],
            "shape",
            id="bad-id-shape",
        ),
        pytest.param(
            lambda s: [s[0], {**s[1], "provider_request_id": s[0]["provider_request_id"]}],
            "unique",
            id="duplicate-ids",
        ),
        pytest.param(
            lambda s: [{**x, "measured_cost_usd": "0"} for x in s], "zero-cost", id="zero-cost"
        ),
        pytest.param(
            lambda s: [{**x, "measured_cost_usd": "0.01"} for x in s],
            "identical-cost",
            id="templated-costs",
        ),
    ],
)
def test_a_hand_written_bundle_does_not_reach_lineage_consistent(mutate, reason: str) -> None:
    """The checks a fabricated bundle would have to defeat, each one on its own."""

    samples = mutate([_sample(1), _sample(2)])
    tier, evidence = classify_provider_provenance({"samples": samples})

    assert tier == "unverified", f"{reason}: {evidence}"


# --- disclosure travels with the artifact ------------------------------------------------


def test_the_disclosure_names_the_weaker_baseline_plainly() -> None:
    text = disclosure(ground_truth_tier="rule_derived", provider_tier="lineage_consistent")

    assert "NOT human ground truth" in text
    assert "NOT model-labeled" in text
    assert "not proof" in text
    assert "automated-labeled baseline" in text


def test_accepted_tiers_are_encoded_into_the_artifacts_own_approver_ref() -> None:
    """A sidecar can be separated from the artifact; approver_ref cannot."""

    encoded = encode_approver_ref(
        approver="headshot:morgan",
        ground_truth_tier="rule_derived",
        provider_tier="lineage_consistent",
    )

    assert encoded == "gt=rule_derived;prov=lineage_consistent;by=headshot:morgan"
    assert len(encoded) <= 128
    assert decode_approver_ref(encoded) == {
        "ground_truth_tier": "rule_derived",
        "provider_tier": "lineage_consistent",
        "approver": "headshot:morgan",
    }


def test_an_approver_ref_without_provenance_is_not_silently_accepted() -> None:
    with pytest.raises(ProvenanceError, match="does not carry provenance tiers"):
        decode_approver_ref("headshot:morgan")


def test_encoding_refuses_separators_that_would_forge_a_tier() -> None:
    with pytest.raises(ProvenanceError, match="may not contain"):
        encode_approver_ref(
            approver="evil;prov=usage_export_reconciled;by=x",
            ground_truth_tier="rule_derived",
            provider_tier="unverified",
        )


def test_encoding_refuses_an_approver_too_long_for_the_contract_field() -> None:
    with pytest.raises(ProvenanceError, match="exceeds 128"):
        encode_approver_ref(
            approver="h" * 120,
            ground_truth_tier="human_two_person",
            provider_tier="usage_export_reconciled",
        )
