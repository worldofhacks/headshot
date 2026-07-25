"""Stage 2 of the governed generative loop — the HUMAN REVIEW GATE.

A curated bundle is a set of well-formed proposals. It is not yet something the platform may
attack a live target with, and no amount of validation in stage 1 makes it so: curation proves a
candidate is *well-formed and novel*, never that it is *appropriate to send*. Only a human deciding
so, on the exact bytes, makes it that.

This module is that decision, and it is deliberately hostile to the ways such a gate usually rots:

* **Bound to exact bytes.** A decision names the bundle's ``bundle_sha256`` AND each candidate's
  own ``case_sha256``. Review a bundle, mutate a turn, and every decision is refused — the whole
  point of content-addressing the bundle in stage 1.
* **No approval by omission.** Every candidate needs an explicit decision. A gate that treats
  "unmentioned" as "approved" approves whatever the reviewer did not notice, which is exactly the
  set of things a generator could hide something in.
* **No self-approval.** The principal that ran the generation cannot approve its output. This is
  the same two-person invariant the platform applies to findings, applied at the point where
  attack content is admitted.
* **Rejections are shown, not summarized away.** :func:`present` renders every curated candidate
  *and* every stage-1 rejection, because what curation threw out is evidence about whether the
  generator is behaving.

**What an approval is and is not.** An approval is the human authorization *decision* — the act
this platform requires before generated content may ever be dispatched. It is not by itself a
grant a campaign can run on: a grant is scoped to an exact target, host, caps and corpus hash, and
minting one is stage 3 (:mod:`agentforge.campaign.generated_profile`). Approval answers "may this
content be attacked with at all"; the fresh authorization answers "against exactly what, under
exactly which ceilings, for exactly one run". Both are required, and neither substitutes for the
other.

The emitted :class:`ReviewRecord` is intentionally shaped to the provenance contract
``agentforge.campaign.corpus.load_live_100_corpus`` already validates, with
``source_kind="hosted_red_team"`` — the reviewed-workload loader is the existing authority on what
an approved generated case looks like, and this gate feeds it rather than inventing a parallel
notion of "approved".
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agentforge.agents.red_team.curation import CuratedBundle, CuratedCandidate

# The identifier shape the reviewed-workload loader enforces on reviewer_id / instance_id.
_PRINCIPAL_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")

SOURCE_KIND = "hosted_red_team"

APPROVED = "approved"
REJECTED = "rejected"
_DECISIONS = frozenset({APPROVED, REJECTED})


class ReviewGateError(ValueError):
    """A review decision cannot be accepted against this bundle."""


@dataclass(frozen=True, slots=True)
class CaseDecision:
    """One human decision about one candidate, bound to that candidate's exact content hash.

    ``case_sha256`` is not redundant with ``instance_id``: it is what makes a decision
    non-transplantable. Without it, a decision recorded for one candidate could be replayed
    against different content that happened to reuse the identifier.
    """

    instance_id: str
    case_sha256: str
    decision: str
    rationale: str = ""

    def __post_init__(self) -> None:
        if (
            not isinstance(self.instance_id, str)
            or _PRINCIPAL_RE.fullmatch(self.instance_id) is None
        ):
            raise ReviewGateError("decision instance_id is not a valid identifier")
        if (
            not isinstance(self.case_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.case_sha256) is None
        ):
            raise ReviewGateError("decision case_sha256 is not a lowercase sha-256 digest")
        if self.decision not in _DECISIONS:
            raise ReviewGateError(f"decision must be one of {sorted(_DECISIONS)}")
        if not isinstance(self.rationale, str) or len(self.rationale) > 2000:
            raise ReviewGateError("decision rationale is not bounded text")


@dataclass(frozen=True, slots=True)
class ReviewRecord:
    """The persisted provenance of one approved candidate.

    Field-for-field the shape ``load_live_100_corpus`` validates, so an approved generated case can
    enter a reviewed workload without a second, weaker notion of approval existing anywhere.
    """

    instance_id: str
    case_sha256: str
    reviewer_id: str
    source_generation_sha256: str
    status: str = APPROVED
    source_kind: str = SOURCE_KIND

    def as_record(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "instance_id": self.instance_id,
            "case_sha256": self.case_sha256,
            "status": self.status,
            "reviewer_id": self.reviewer_id,
            "source_generation_sha256": self.source_generation_sha256,
            "source_kind": self.source_kind,
        }

    def source_generation_record(self) -> dict[str, Any]:
        """The companion generation-provenance artifact the workload loader also verifies."""

        return {
            "schema_version": "1",
            "instance_id": self.instance_id,
            "case_sha256": self.case_sha256,
            "source_kind": self.source_kind,
        }


@dataclass(frozen=True, slots=True)
class ReviewPresentation:
    """Exactly what a human is shown before deciding. Deterministic and complete."""

    bundle_sha256: str
    base_corpus_id: str
    base_corpus_hash: str
    generation: dict[str, Any]
    candidates: tuple[dict[str, Any], ...]
    rejections: tuple[dict[str, Any], ...]

    def as_record(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "bundle_sha256": self.bundle_sha256,
            "base_corpus_id": self.base_corpus_id,
            "base_corpus_hash": self.base_corpus_hash,
            "generation": self.generation,
            "candidates": [dict(row) for row in self.candidates],
            "rejections": [dict(row) for row in self.rejections],
        }


@dataclass(frozen=True, slots=True)
class ApprovedBundle:
    """The human-approved subset of a curated bundle, content-addressed in its own right.

    ``approved_bundle_sha256`` covers the approved cases, the reviewer identity and the bundle the
    decisions were made against, so the approval cannot be re-pointed at a different bundle or a
    different reviewer after the fact.
    """

    approved_bundle_sha256: str
    reviewed_bundle_sha256: str
    base_corpus_id: str
    base_corpus_hash: str
    reviewer_id: str
    generator_principal: str
    candidates: tuple[CuratedCandidate, ...]
    records: tuple[ReviewRecord, ...]
    rejected_instance_ids: tuple[str, ...]
    generation_sha256: str

    def __post_init__(self) -> None:
        if not self.candidates:
            raise ReviewGateError("an approved bundle must contain at least one approved case")
        if len(self.candidates) != len(self.records):
            raise ReviewGateError("every approved case must carry exactly one review record")

    def case_hashes(self) -> tuple[str, ...]:
        return tuple(candidate.case_sha256 for candidate in self.candidates)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def present(bundle: CuratedBundle) -> ReviewPresentation:
    """Render the complete, deterministic reviewer view of a curated bundle.

    Includes the stage-1 rejections. A reviewer who only sees what survived curation cannot tell a
    well-behaved generator from one whose output was mostly refused, and that difference is the
    main signal available at this gate.
    """

    if not isinstance(bundle, CuratedBundle):
        raise ReviewGateError("only a CuratedBundle may be presented for review")
    return ReviewPresentation(
        bundle_sha256=bundle.bundle_sha256,
        base_corpus_id=bundle.base_corpus_id,
        base_corpus_hash=bundle.base_corpus_hash,
        generation=bundle.generation.as_record(),
        candidates=tuple(candidate.review_row() for candidate in bundle.candidates),
        rejections=tuple(rejection.as_record() for rejection in bundle.rejections),
    )


def approve(
    bundle: CuratedBundle,
    *,
    reviewed_bundle_sha256: str,
    decisions: Sequence[CaseDecision] | Sequence[Mapping[str, Any]],
    reviewer_id: str,
    generator_principal: str,
) -> ApprovedBundle:
    """Record a human review of ``bundle`` and return the approved subset.

    ``reviewed_bundle_sha256`` is the digest the reviewer actually saw. It must equal the bundle's
    own digest: that equality is what makes "the human approved this" a statement about bytes
    rather than about a label.

    Fail-closed, in order: bundle identity, reviewer identity, self-approval, decision coverage,
    per-case content binding, then non-empty approval. Any failure raises
    :class:`ReviewGateError` and NOTHING is approved — a partially-valid decision set never yields
    a partially-approved bundle.
    """

    if not isinstance(bundle, CuratedBundle):
        raise ReviewGateError("only a CuratedBundle may be reviewed")

    # (1) Identity of the reviewed artifact. A mutated bundle is a different bundle.
    if (
        not isinstance(reviewed_bundle_sha256, str)
        or reviewed_bundle_sha256 != bundle.bundle_sha256
    ):
        raise ReviewGateError(
            "the reviewed bundle digest does not match this bundle — the content changed after "
            "it was presented for review (fail closed)"
        )

    # (2) Both principals must be well-formed identities, not free text.
    for label, principal in (
        ("reviewer_id", reviewer_id),
        ("generator_principal", generator_principal),
    ):
        if not isinstance(principal, str) or _PRINCIPAL_RE.fullmatch(principal) is None:
            raise ReviewGateError(f"{label} is not a valid principal identifier")

    # (3) Two-person invariant. The principal that generated the content cannot approve it.
    if reviewer_id == generator_principal:
        raise ReviewGateError(
            "the generating principal cannot approve its own generated attacks — review requires "
            "a distinct human principal (fail closed)"
        )

    if not bundle.candidates:
        raise ReviewGateError("an empty curated bundle has nothing to approve")

    normalized = tuple(
        item if isinstance(item, CaseDecision) else CaseDecision(**dict(item)) for item in decisions
    )

    # (4) Coverage: exactly one decision per candidate, no extras, no omissions.
    by_instance: dict[str, CaseDecision] = {}
    for decision in normalized:
        if decision.instance_id in by_instance:
            raise ReviewGateError(
                f"candidate {decision.instance_id} carries more than one decision"
            )
        by_instance[decision.instance_id] = decision
    candidate_ids = {candidate.instance_id for candidate in bundle.candidates}
    missing = sorted(candidate_ids - by_instance.keys())
    if missing:
        raise ReviewGateError(
            f"{len(missing)} curated candidate(s) carry no explicit decision — approval by "
            f"omission is refused (first: {missing[0]})"
        )
    unknown = sorted(by_instance.keys() - candidate_ids)
    if unknown:
        raise ReviewGateError(
            f"decision names a candidate absent from this bundle (first: {unknown[0]})"
        )

    # (5) Content binding: a decision must have been made about this candidate's exact bytes.
    approved: list[CuratedCandidate] = []
    records: list[ReviewRecord] = []
    rejected: list[str] = []
    for candidate in bundle.candidates:
        decision = by_instance[candidate.instance_id]
        if decision.case_sha256 != candidate.case_sha256:
            raise ReviewGateError(
                f"the decision for {candidate.instance_id} names a different case digest — a "
                "decision cannot be transplanted onto other content (fail closed)"
            )
        if decision.decision == REJECTED:
            rejected.append(candidate.instance_id)
            continue
        approved.append(candidate)
        records.append(
            ReviewRecord(
                instance_id=candidate.instance_id,
                case_sha256=candidate.case_sha256,
                reviewer_id=reviewer_id,
                source_generation_sha256=candidate.source_generation_sha256,
            )
        )

    # (6) An all-rejected review is a legitimate outcome, but it authorizes nothing.
    if not approved:
        raise ReviewGateError(
            "the reviewer approved no candidate — there is nothing to authorize (this is a valid "
            "review outcome, not an error in the bundle)"
        )

    approved_bundle_sha256 = _canonical_sha256(
        {
            "schema_version": "1",
            "reviewed_bundle_sha256": bundle.bundle_sha256,
            "base_corpus_id": bundle.base_corpus_id,
            "base_corpus_hash": bundle.base_corpus_hash,
            "generation_sha256": bundle.generation_sha256,
            "reviewer_id": reviewer_id,
            "approved_case_sha256": [item.case_sha256 for item in approved],
        }
    )
    return ApprovedBundle(
        approved_bundle_sha256=approved_bundle_sha256,
        reviewed_bundle_sha256=bundle.bundle_sha256,
        base_corpus_id=bundle.base_corpus_id,
        base_corpus_hash=bundle.base_corpus_hash,
        reviewer_id=reviewer_id,
        generator_principal=generator_principal,
        candidates=tuple(approved),
        records=tuple(records),
        rejected_instance_ids=tuple(rejected),
        generation_sha256=bundle.generation_sha256,
    )


__all__ = [
    "APPROVED",
    "REJECTED",
    "SOURCE_KIND",
    "ApprovedBundle",
    "CaseDecision",
    "ReviewGateError",
    "ReviewPresentation",
    "ReviewRecord",
    "approve",
    "present",
]
