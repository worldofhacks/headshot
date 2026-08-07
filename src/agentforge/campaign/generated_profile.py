"""Stage 3 of the governed generative loop — a NEW corpus identity and a FRESH authorization.

This module exists because of one rule: **a campaign never mutates its corpus inside a run it has
already been authorized for.** An authorization is content-addressed over the exact corpus hash
(:func:`agentforge.campaign.authorization.operation_hash`), so an approved generated case is, by
construction, outside every grant that existed before it. The coordinator's insistence that each
proposal equal the reviewed corpus byte-for-byte is therefore *correct*, and the missing piece was
never a loosening of that check — it was this: a governed way to mint a new corpus identity and
take a new grant for it.

So the generated corpus is a genuinely separate identity. :func:`build_generated_corpus` refuses to
return a profile whose ``content_hash`` collides with the base corpus, and
:func:`require_fresh_authorization` refuses a scope still carrying the base corpus hash. Between
them, "reuse the grant we already had" has no expressible form.

What this module will NOT do:

* it cannot approve anything — it consumes an :class:`~agentforge.agents.red_team.review_gate.
  ApprovedBundle` and re-verifies it, and a bundle that was mutated after approval fails that
  re-verification;
* it cannot dispatch — see :func:`prepare_generated_dispatch`, which performs every governed
  precondition and then stops, because physical dispatch stacks on the 0022 governed four-role
  execution path; and
* it cannot widen caps — the caps in the scope are the caps, and this module only checks that the
  scope it was handed is the one built for this profile.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agentforge.agents.red_team.curation import CuratedCandidate
from agentforge.agents.red_team.review_gate import SOURCE_KIND, ApprovedBundle, ReviewRecord
from agentforge.agents.red_team.seed_replay import corpus_sha256, seed_to_attempt
from agentforge.campaign.corpus import AuthoredCorpus
from agentforge.contracts import validate
from agentforge.target.spec import AuthorizationScope


class GeneratedCorpusError(ValueError):
    """An approved bundle cannot become an independently authorizable corpus."""


class GeneratedDispatchUnavailable(RuntimeError):
    """Every governed precondition passed, but physical dispatch is not wired in this tree.

    Stage 4 reuses the 0022 governed four-role execution path. Until that path is present this is
    raised AFTER all checks, so the gate is exercised and the missing piece is unambiguous — a
    silent no-op here would look exactly like a successful dispatch.
    """

    code = "generated-dispatch-unavailable"


@dataclass(frozen=True, slots=True)
class GeneratedCorpusProfile:
    """An immutable, separately-hashed corpus built from human-approved generated cases.

    Deliberately parallel to
    :class:`~agentforge.campaign.tool_profile.ReviewedToolCorpusProfile`: both are "a reviewed
    addition to the authored base, with an identity of its own that forces a new grant". The
    difference is only the provenance of the addition.
    """

    corpus_id: str
    content_hash: str
    base_corpus_hash: str
    base_corpus_id: str
    approved_bundle_sha256: str
    reviewer_id: str
    generator_principal: str
    generation_sha256: str
    attempts: tuple[dict[str, Any], ...]
    generated_case_sha256: tuple[str, ...]
    review_records: tuple[ReviewRecord, ...]
    fresh_authorization_required: bool = True

    def __post_init__(self) -> None:
        if self.fresh_authorization_required is not True:
            raise GeneratedCorpusError("a generated corpus always requires a fresh authorization")
        if self.content_hash == self.base_corpus_hash:
            raise GeneratedCorpusError("a generated corpus must not share the base corpus identity")

    def provenance_records(self) -> tuple[dict[str, Any], ...]:
        """The review artifacts, in the shape the reviewed-workload loader verifies."""

        return tuple(record.as_record() for record in self.review_records)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _verify_unchanged(candidate: CuratedCandidate) -> dict[str, Any]:
    """Re-derive a candidate's content hash and refuse it if the payload drifted since approval.

    The approval was made about specific bytes. Re-hashing here is what makes that binding hold
    across the boundary between the review gate and the campaign, rather than trusting a field.
    """

    actual = _canonical_sha256(candidate.payload)
    if actual != candidate.case_sha256:
        raise GeneratedCorpusError(
            f"approved case {candidate.instance_id} changed after review "
            "(content hash does not re-derive)"
        )
    return candidate.payload


def build_generated_corpus(
    base: AuthoredCorpus,
    approved: ApprovedBundle,
) -> GeneratedCorpusProfile:
    """Turn a human-approved bundle into a separately-identified, authorizable corpus profile.

    The profile is the authored base PLUS the approved generated cases, hashed as a whole with the
    same :func:`~agentforge.agents.red_team.seed_replay.corpus_sha256` the platform uses
    everywhere else — so the resulting digest is directly comparable to, and provably distinct
    from, the base corpus digest a prior grant was bound to.
    """

    if not isinstance(base, AuthoredCorpus):
        raise GeneratedCorpusError("a generated corpus must extend a validated authored corpus")
    if not isinstance(approved, ApprovedBundle):
        raise GeneratedCorpusError("only a human-approved bundle may become a corpus")

    # The approval was made against a specific base. Re-pointing it at a different base would let
    # a review performed against one corpus authorize content alongside another.
    if approved.base_corpus_hash != base.content_hash or approved.base_corpus_id != base.corpus_id:
        raise GeneratedCorpusError(
            "the approved bundle was reviewed against a different base corpus (fail closed)"
        )

    records_by_instance = {record.instance_id: record for record in approved.records}
    if len(records_by_instance) != len(approved.records):
        raise GeneratedCorpusError("approved bundle contains duplicate review records")

    base_attempts = tuple(seed_to_attempt(case.payload) for case in base.cases)
    generated_attempts: list[dict[str, Any]] = []
    generated_hashes: list[str] = []
    ordered_records: list[ReviewRecord] = []

    for candidate in approved.candidates:
        record = records_by_instance.get(candidate.instance_id)
        if record is None:
            raise GeneratedCorpusError(
                f"approved case {candidate.instance_id} carries no review record"
            )
        if record.case_sha256 != candidate.case_sha256:
            raise GeneratedCorpusError(
                f"review record for {candidate.instance_id} names different content"
            )
        if record.status != "approved" or record.source_kind != SOURCE_KIND:
            raise GeneratedCorpusError(
                f"review record for {candidate.instance_id} is not an approved generated case"
            )
        payload = _verify_unchanged(candidate)
        attempt = seed_to_attempt(payload)
        attempt["mutation_lineage"] = [
            f"generated:{candidate.instance_id}:{candidate.source_generation_sha256}"
        ]
        validate("attack_attempt", attempt)
        generated_attempts.append(attempt)
        generated_hashes.append(candidate.case_sha256)
        ordered_records.append(record)

    if not generated_attempts:
        raise GeneratedCorpusError("a generated corpus must add at least one approved case")

    attempts = (*base_attempts, *generated_attempts)
    content_hash = corpus_sha256(list(attempts))
    if content_hash == base.content_hash:
        raise GeneratedCorpusError(
            "generated corpus hash collides with the base corpus — it would silently ride the "
            "existing grant (fail closed)"
        )
    return GeneratedCorpusProfile(
        corpus_id=f"generated-corpus-{content_hash[:16]}",
        content_hash=content_hash,
        base_corpus_hash=base.content_hash,
        base_corpus_id=base.corpus_id,
        approved_bundle_sha256=approved.approved_bundle_sha256,
        reviewer_id=approved.reviewer_id,
        generator_principal=approved.generator_principal,
        generation_sha256=approved.generation_sha256,
        attempts=attempts,
        generated_case_sha256=tuple(generated_hashes),
        review_records=tuple(ordered_records),
    )


def require_fresh_authorization(
    profile: GeneratedCorpusProfile,
    *,
    scope: AuthorizationScope,
    spent_run_nonces: Sequence[str] = (),
) -> AuthorizationScope:
    """Refuse any scope that is not a fresh grant minted for exactly this generated corpus.

    Fail-closed, in order:

    1. the scope must carry THIS profile's corpus hash — a grant for other content cannot cover
       these cases;
    2. the scope must not carry the BASE corpus hash — the specific reuse this whole stage exists
       to prevent, checked explicitly so it can never be reached by a hash coincidence;
    3. the scope's corpus id must be this profile's; and
    4. the run nonce must not be one already spent — a grant rides exactly one run instance, so a
       replayed nonce is a replayed grant.

    Returns the scope unchanged on success. It is deliberately not modified here: a function that
    could edit the scope it validates would be a place to widen one.
    """

    if not isinstance(profile, GeneratedCorpusProfile):
        raise GeneratedCorpusError("authorization may only be checked for a generated profile")
    if not isinstance(scope, AuthorizationScope):
        raise GeneratedCorpusError("a validated AuthorizationScope is required")

    if scope.corpus_hash != profile.content_hash:
        raise GeneratedCorpusError(
            "authorization scope is not bound to this generated corpus hash — a grant minted for "
            "other content can never authorize these generated cases (fail closed)"
        )
    if scope.corpus_hash == profile.base_corpus_hash:
        raise GeneratedCorpusError(
            "authorization scope still carries the BASE corpus hash — generated cases may not "
            "ride the grant that authorized the reviewed corpus (fail closed)"
        )
    if scope.corpus_id != profile.corpus_id:
        raise GeneratedCorpusError(
            "authorization scope corpus id does not name this generated corpus (fail closed)"
        )
    if scope.run_nonce in set(spent_run_nonces):
        raise GeneratedCorpusError(
            "authorization scope reuses a spent run nonce — a grant rides exactly one run "
            "instance (fail closed)"
        )
    return scope


@dataclass(frozen=True, slots=True)
class GeneratedDispatchPlan:
    """Everything a governed dispatch needs, assembled only after every gate has passed."""

    profile: GeneratedCorpusProfile
    scope: AuthorizationScope
    attempts: tuple[dict[str, Any], ...]

    def plan_sha256(self) -> str:
        return _canonical_sha256(
            {
                "corpus_id": self.profile.corpus_id,
                "corpus_hash": self.profile.content_hash,
                "approved_bundle_sha256": self.profile.approved_bundle_sha256,
                "scope_hash": self.scope.scope_hash(),
                "attempt_count": len(self.attempts),
            }
        )


def prepare_generated_dispatch(
    profile: GeneratedCorpusProfile,
    *,
    scope: AuthorizationScope,
    spent_run_nonces: Sequence[str] = (),
) -> GeneratedDispatchPlan:
    """Run every governed precondition for dispatching a generated corpus, and stop there.

    This is the complete stage-3 exit: curation, human approval, a distinct corpus identity, and a
    fresh in-scope grant have all been established by the time this returns. Handing the plan to
    the :class:`~agentforge.policy.gateway.PolicyGateway` is stage 4, which stacks on the 0022
    governed four-role execution path — see :class:`GeneratedDispatchUnavailable`.
    """

    require_fresh_authorization(profile, scope=scope, spent_run_nonces=spent_run_nonces)
    return GeneratedDispatchPlan(profile=profile, scope=scope, attempts=profile.attempts)


__all__ = [
    "GeneratedCorpusError",
    "GeneratedCorpusProfile",
    "GeneratedDispatchPlan",
    "GeneratedDispatchUnavailable",
    "build_generated_corpus",
    "prepare_generated_dispatch",
    "require_fresh_authorization",
]
