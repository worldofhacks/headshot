"""Graded provenance for a calibration: accept a weaker baseline, never disguise one.

Calibration evidence comes in strengths, and a deadline can legitimately force a weaker one.  What
must not happen is a weaker baseline being read later as the stronger thing — a rule-derived label
set reported as "ground truth", or a bundle whose provider calls were never reconciled reported as
"measured".  Both are the same failure the superseded 8ce852b artifact made: correct arithmetic,
misread provenance.

So provenance is a **graded, computed** property, not an assertion:

* the tier is derived from the evidence actually present (:func:`classify_ground_truth`,
  :func:`classify_provider_provenance`) — a caller cannot declare a tier it has not earned;
* the accepting human must name the tier they are accepting, and enablement refuses if the real
  tier is weaker than the named one; and
* the accepted tiers are encoded into ``approver_ref`` (:func:`encode_approver_ref`), which is
  inside the frozen ``judge_calibration`` contract.  A sidecar can be lost in a copy; a field the
  artifact carries cannot.  Anywhere the artifact travels, the downgrade travels with it.

Nothing here changes what the Judge may decide.  Confirmation remains oracle / canary / human
(``agents/judge/model_authority.py``) at every tier, and ``INDETERMINATE`` is never safe.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal

GroundTruthTier = Literal[
    "human_two_person",
    "model_labeled",
    "rule_derived",
    "unattested",
]
ProviderTier = Literal["usage_export_reconciled", "lineage_consistent", "unverified"]

#: Strongest first. Position is the comparison; the names are the vocabulary.
GROUND_TRUTH_TIERS: tuple[GroundTruthTier, ...] = (
    "human_two_person",
    "model_labeled",
    "rule_derived",
    "unattested",
)
PROVIDER_TIERS: tuple[ProviderTier, ...] = (
    "usage_export_reconciled",
    "lineage_consistent",
    "unverified",
)

#: What each tier means, in the words that belong in a report. These strings are the disclosure —
#: they are written to be quotable without further softening.
GROUND_TRUTH_DISCLOSURE: Mapping[GroundTruthTier, str] = {
    "human_two_person": (
        "human ground truth — every label attested by two distinct authorized principals, blind "
        "to Judge output"
    ),
    "model_labeled": (
        "automated-labeled baseline — labels proposed by a named model, NOT human ground truth. "
        "Where the labelling model is a different family from the Judge under calibration, "
        "agreement is independent rather than self-agreement; it is still one model's reading of "
        "designed-in intent, not an attested outcome"
    ),
    "rule_derived": (
        "automated-labeled baseline — labels derived in code from a static design table "
        "(scripts/build_calibration_corpus.py), NOT model-labeled and NOT human ground truth. The "
        "labels encode what the corpus author intended each sample to be, so the measurement "
        "shows agreement with that intent, not with an independent judgement of the evidence"
    ),
    "unattested": "no label provenance of any kind",
}
PROVIDER_DISCLOSURE: Mapping[ProviderTier, str] = {
    "usage_export_reconciled": (
        "measured — every sample reconciled against the provider's own usage export by request "
        "id, model and cost"
    ),
    "lineage_consistent": (
        "consistent with a real provider run, NOT reconciled against the provider's records — "
        "unique provider-shaped request ids, provider-reported per-sample costs and distinct "
        "token counts. Strong circumstantial evidence; it is not proof the calls occurred"
    ),
    "unverified": ("shape-valid only — nothing distinguishes this bundle from one written by hand"),
}

_PROVIDER_REQUEST_ID = re.compile(r"\Agen-\d{8,}-[A-Za-z0-9]{8,}\Z")
_MIN_LINEAGE_SAMPLES = 2


class ProvenanceError(ValueError):
    """The provenance of a calibration could not be established or was misdeclared."""


def _rank(tier: str, tiers: Sequence[str]) -> int:
    try:
        return tiers.index(tier)  # type: ignore[arg-type]
    except ValueError as exc:
        raise ProvenanceError(f"{tier!r} is not a recognised provenance tier") from exc


def is_at_least(actual: str, accepted: str, tiers: Sequence[str]) -> bool:
    """True when ``actual`` is the accepted tier or stronger (lower index is stronger)."""

    return _rank(actual, tiers) <= _rank(accepted, tiers)


def classify_ground_truth(
    slices: Sequence[Mapping[str, Any]],
    *,
    attestation: Mapping[str, Any] | None = None,
) -> tuple[GroundTruthTier, dict[str, Any]]:
    """Derive the ground-truth tier from the labels and any human attestation.

    A two-person attestation is only honoured when it is complete: two distinct identified
    principals, blind to Judge output. Anything less falls through to what the labels themselves
    can support, so a partly-filled attestation cannot buy the top tier.
    """

    labels = [label for item in slices for label in item.get("labels", [])]
    if not labels:
        raise ProvenanceError("no ground-truth labels to classify")

    evidence: dict[str, Any] = {"label_count": len(labels)}
    sources = sorted({str(label.get("label_source")) for label in labels})
    evidence["label_sources"] = sources

    if attestation is not None:
        labeler = _principal_id(attestation.get("human_labeler"))
        reviewer = _principal_id(attestation.get("distinct_reviewer"))
        blind = attestation.get("blind_to_judge_output") is True
        evidence["attestation"] = {
            "human_labeler": labeler,
            "distinct_reviewer": reviewer,
            "blind_to_judge_output": blind,
        }
        if labeler and reviewer and labeler != reviewer and blind:
            return "human_two_person", evidence

    # A model-labeled set names the model that produced its model-proposed labels. A set may mix
    # model-proposed labels with rule-derived ones (GT-AUTO-M11-LIVE100 pairs a model CONFIRM/LIKELY
    # label with a rule-derived resist label per case); it qualifies as long as every label that
    # claims automated_model_agent names its labeller. Partial attribution does NOT qualify — an
    # unnamed model label cannot be graded at all.
    model_labels = [
        label for label in labels if label.get("label_source") == "automated_model_agent"
    ]
    named = [
        str(label[field]).strip()
        for label in model_labels
        for field in ("labeler_model_id", "labeling_model")
        if isinstance(label.get(field), str) and label[field].strip()
    ]
    if model_labels and len(named) >= len(model_labels):
        evidence["labeling_models"] = sorted(set(named))
        evidence["model_label_count"] = len(model_labels)
        return "model_labeled", evidence

    if all(label.get("label_source") for label in labels):
        return "rule_derived", evidence
    return "unattested", evidence


def classify_provider_provenance(
    bundle: Mapping[str, Any],
    *,
    attestation: Mapping[str, Any] | None = None,
) -> tuple[ProviderTier, dict[str, Any]]:
    """Derive the provider tier from a reconciliation, else from the bundle's own lineage.

    ``lineage_consistent`` is EARNED, not assumed: the checks below are the ones that a bundle
    written by hand would have to have faked deliberately and consistently. They are still not
    proof — only the provider's records are — which is why the tier is named for consistency
    rather than verification.
    """

    samples = bundle.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ProvenanceError("the bundle carries no samples to classify")

    if attestation is not None:
        matched = attestation.get("matched_generation_count")
        if (
            attestation.get("attestation_kind") == "openrouter_usage_export_reconciled"
            and isinstance(matched, int)
            and matched >= len(samples)
        ):
            return "usage_export_reconciled", {
                "sample_count": len(samples),
                "matched_generation_count": matched,
            }

    request_ids = [str(sample.get("provider_request_id", "")) for sample in samples]
    costs = {str(sample.get("measured_cost_usd")) for sample in samples}
    token_triples = {
        (
            sample.get("input_tokens"),
            sample.get("output_tokens"),
            sample.get("reasoning_tokens"),
        )
        for sample in samples
    }
    checks = {
        "unique_request_ids": len(set(request_ids)) == len(request_ids),
        "provider_shaped_request_ids": all(
            _PROVIDER_REQUEST_ID.fullmatch(identifier) for identifier in request_ids
        ),
        "distinct_costs": len(costs) > 1,
        "distinct_token_counts": len(token_triples) > 1,
        "nonzero_costs": all(_positive(sample.get("measured_cost_usd")) for sample in samples),
    }
    evidence = {"sample_count": len(samples), "checks": checks}
    if len(samples) >= _MIN_LINEAGE_SAMPLES and all(checks.values()):
        return "lineage_consistent", evidence
    return "unverified", evidence


def disclosure(
    *,
    ground_truth_tier: GroundTruthTier,
    provider_tier: ProviderTier,
) -> str:
    """The sentence a report must carry. Written to be quoted verbatim, not paraphrased down."""

    return (
        f"Ground truth: {GROUND_TRUTH_DISCLOSURE[ground_truth_tier]}. "
        f"Provider calls: {PROVIDER_DISCLOSURE[provider_tier]}."
    )


#: ``approver_ref`` is capped at 128 characters by ``judge_calibration.json``.
_APPROVER_REF_MAX = 128
_ENCODED = re.compile(r"\Agt=(?P<gt>[a-z_]+);prov=(?P<prov>[a-z_]+);by=(?P<by>.+)\Z")


def encode_approver_ref(
    *,
    approver: str,
    ground_truth_tier: GroundTruthTier,
    provider_tier: ProviderTier,
) -> str:
    """Fold the accepted tiers into the artifact's own approver reference.

    ``judge_calibration.json`` is ``additionalProperties: false``, so a new top-level provenance
    field would be a contract change (``contract-steward``'s call, not this module's). Encoding the
    tiers into ``approver_ref`` puts the downgrade inside the artifact today, where a sidecar file
    could be separated from it. It also makes the acceptance attributable: the same field names the
    human who accepted it.
    """

    approver = (approver or "").strip()
    if not approver:
        raise ProvenanceError("an approver reference is required")
    if ";" in approver or "=" in approver:
        raise ProvenanceError("approver reference may not contain ';' or '='")
    _rank(ground_truth_tier, GROUND_TRUTH_TIERS)
    _rank(provider_tier, PROVIDER_TIERS)
    encoded = f"gt={ground_truth_tier};prov={provider_tier};by={approver}"
    if len(encoded) > _APPROVER_REF_MAX:
        raise ProvenanceError(
            f"approver reference with provenance exceeds {_APPROVER_REF_MAX} characters; "
            "shorten the approver id"
        )
    return encoded


def decode_approver_ref(value: str) -> dict[str, str]:
    """Read back the tiers an artifact was enabled under."""

    match = _ENCODED.fullmatch(str(value or ""))
    if match is None:
        raise ProvenanceError(
            "approver reference does not carry provenance tiers; it predates graded provenance "
            "or was written by hand"
        )
    return {
        "ground_truth_tier": match.group("gt"),
        "provider_tier": match.group("prov"),
        "approver": match.group("by"),
    }


def _principal_id(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    identifier = value.get("id")
    attested_at = value.get("attested_at")
    if not isinstance(identifier, str) or not identifier.strip():
        return None
    if not isinstance(attested_at, str) or not attested_at.strip():
        return None
    return identifier.strip()


def _positive(value: Any) -> bool:
    try:
        return float(str(value)) > 0
    except (TypeError, ValueError):
        return False


__all__ = [
    "GROUND_TRUTH_DISCLOSURE",
    "GROUND_TRUTH_TIERS",
    "PROVIDER_DISCLOSURE",
    "PROVIDER_TIERS",
    "GroundTruthTier",
    "ProvenanceError",
    "ProviderTier",
    "classify_ground_truth",
    "classify_provider_provenance",
    "decode_approver_ref",
    "disclosure",
    "encode_approver_ref",
    "is_at_least",
]
