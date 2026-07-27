"""Adopt an independent automated label set as the ``model_labeled`` calibration baseline.

``GT-AUTO-M11-LIVE100`` labels the 100-case corpus with a model from a **different family** than
the Judge under calibration (``claude-opus-5[1m]`` vs ``gemini-2.5-pro``), blind to the candidate
labels, to the cases' own ``oracle_expectation`` and to Judge output.  That independence is what
makes the agreement number mean something; it is still **not** human ground truth, and the artifact
says so in its own data (``two_person_human_gate_satisfied: false``).

WHY EIGHT CASES ARE EXCLUDED
----------------------------
The labeller flagged 8 cases as ``over_claimed_provability``: it labelled them ``CONFIRM`` where the
candidate said ``LIKELY``, asserting a deterministic artifact would fix the verdict when the case
binds no such oracle.  Calibrating against those would be incoherent in a specific, damaging way:

* the model Judge is **structurally incapable** of returning ``EXPLOIT_CONFIRMED``
  (``agents/judge/model_authority.py``), so a ``CONFIRM`` expectation it cannot satisfy is not a
  measurement of the Judge; and
* ``CalibrationGate`` scores ``expected EXPLOIT_CONFIRMED`` + a non-positive actual as a **false
  negative**, and ``_reasons`` raises the hard ``confirmed_exploit_missed`` invariant on it —
  which fails the whole calibration regardless of every rate threshold.

So the 8 would manufacture phantom false negatives, and could hard-fail a calibration, against a
Judge behaving exactly as designed.  They are excluded from scoring and **counted in the report**,
never dropped silently.

The exclusion is derived from the artifact's own flags rather than hard-coded, so it stays correct
if the label set is regenerated.  Independently, the same error cannot enter a ground-truth slice
at all: ``ground-truth-slice.v1.json`` admits ``automated_model_agent`` as a ``label_source`` but
does not grant it ``human_expert``'s privilege of licensing an ``EXPLOIT_CONFIRMED`` with no oracle
or canary hit, so validation rejects a model-labelled confirmation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

ARTIFACT_KIND = "independent_automated_label_set"
MODEL_LABEL_SOURCE = "automated_model_agent"
_OVER_CLAIMED = "over_claimed_provability"


class IndependentLabelError(ValueError):
    """The independent label set could not be adopted as a calibration baseline."""


def load_independent_labels(
    artifact: Mapping[str, Any],
    *,
    expected_content_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate the artifact's shape and honesty posture, and return an adoption summary.

    ``expected_content_sha256`` pins the exact label set being adopted, the same way the staged
    hosted configuration is pinned: a calibration that cannot name which labels it scored against
    is not reproducible.
    """

    if artifact.get("artifact_kind") != ARTIFACT_KIND:
        raise IndependentLabelError(
            f"expected artifact_kind {ARTIFACT_KIND!r}, got {artifact.get('artifact_kind')!r}"
        )
    content_sha256 = str(artifact.get("content_sha256") or "")
    if expected_content_sha256 is not None and content_sha256 != expected_content_sha256:
        raise IndependentLabelError(
            f"label set content hash {content_sha256} does not match the pinned "
            f"{expected_content_sha256}"
        )

    attestation = artifact.get("attestation")
    if not isinstance(attestation, Mapping):
        raise IndependentLabelError("the label set carries no attestation block")
    if attestation.get("two_person_human_gate_satisfied") is not False:
        # The artifact must not claim a gate it did not pass. If a future set genuinely passes it,
        # it belongs in the human tier and should not be adopted through this path.
        raise IndependentLabelError(
            "this path adopts automated labels only; an artifact claiming the two-person human "
            "gate must be adopted as human ground truth, not as a model-labelled baseline"
        )

    labels = artifact.get("labels")
    if not isinstance(labels, list) or not labels:
        raise IndependentLabelError("the label set carries no labels")

    model_labels = [item for item in labels if item.get("label_source") == MODEL_LABEL_SOURCE]
    if not model_labels:
        raise IndependentLabelError("the label set contains no model-proposed labels")
    models = sorted(
        {
            str(item["labeler_model_id"]).strip()
            for item in model_labels
            if str(item.get("labeler_model_id") or "").strip()
        }
    )
    if len(models) != 1:
        raise IndependentLabelError(
            f"model-proposed labels must name exactly one labeller model, found {models}"
        )

    return {
        "artifact_id": artifact.get("artifact_id"),
        "content_sha256": content_sha256,
        "source_workload_id": artifact.get("source_workload_id"),
        "labeler_model_id": models[0],
        "label_count": len(labels),
        "model_label_count": len(model_labels),
        "two_person_human_gate_satisfied": False,
        "corpus_execution_status": (artifact.get("provenance") or {}).get(
            "corpus_execution_status"
        ),
    }


def over_claimed_case_ids(metrics: Mapping[str, Any]) -> tuple[str, ...]:
    """The case ids whose CONFIRM label no bound oracle can produce.

    Read from the metrics artifact's own disagreement records rather than hard-coded, and
    cross-checked against its ``over_claimed_provability_n`` count so a silent drift between the
    two is an error rather than a quietly shorter exclusion list.
    """

    disagreements = metrics.get("disagreements")
    if not isinstance(disagreements, list):
        raise IndependentLabelError("the metrics artifact carries no disagreement records")
    flagged = tuple(
        sorted(
            str(item["case_id"])
            for item in disagreements
            if isinstance(item, Mapping)
            and item.get("candidate_label") == "LIKELY"
            and item.get("independent_label") == "CONFIRM"
        )
    )
    declared = ((metrics.get("flags") or {}).get(f"{_OVER_CLAIMED}_n"),)
    if declared[0] is not None and declared[0] != len(flagged):
        raise IndependentLabelError(
            f"metrics declare {declared[0]} over-claimed cases but {len(flagged)} are recorded; "
            "the exclusion list and the headline disagree"
        )
    return flagged


def partition_for_scoring(
    labels: Sequence[Mapping[str, Any]],
    *,
    excluded_case_ids: Sequence[str],
) -> dict[str, Any]:
    """Split labels into what is scored and what is excluded, keeping the excluded visible."""

    excluded_set = set(excluded_case_ids)
    scored: list[Mapping[str, Any]] = []
    excluded: list[Mapping[str, Any]] = []
    for label in labels:
        case_id = str((label.get("case_ref") or {}).get("case_id") or "")
        (excluded if case_id in excluded_set else scored).append(label)

    unmatched = excluded_set - {
        str((label.get("case_ref") or {}).get("case_id") or "") for label in labels
    }
    if unmatched:
        raise IndependentLabelError(
            f"excluded case ids not present in the label set: {sorted(unmatched)}"
        )
    return {
        "scored": scored,
        "excluded": excluded,
        "scored_count": len(scored),
        "excluded_count": len(excluded),
        "excluded_case_ids": sorted(excluded_set),
        "exclusion_reason": (
            "labelled CONFIRM with no bound deterministic oracle. The model Judge cannot return "
            "EXPLOIT_CONFIRMED at all, so scoring these would record false negatives the Judge "
            "cannot avoid and would trip the confirmed_exploit_missed invariant."
        ),
    }


__all__ = [
    "ARTIFACT_KIND",
    "MODEL_LABEL_SOURCE",
    "IndependentLabelError",
    "load_independent_labels",
    "over_claimed_case_ids",
    "partition_for_scoring",
]
