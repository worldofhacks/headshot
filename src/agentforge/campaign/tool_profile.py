"""Governed, separately hashed campaign profiles for reviewed tool candidates.

This module cannot activate or dispatch a campaign. It only builds proposed attempts whose
identity is intentionally distinct from the fixed nine-case MVP corpus.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agentforge.agents.red_team.seed_replay import corpus_sha256, seed_to_attempt
from agentforge.campaign.corpus import MVP_CASE_COUNT, AuthoredCorpus
from agentforge.contracts import validate
from agentforge.security_tools.candidates import ToolAttackCandidate


@dataclass(frozen=True, slots=True)
class ReviewedToolCorpusProfile:
    corpus_id: str
    content_hash: str
    base_corpus_hash: str
    reviewed_candidate_ids: tuple[str, ...]
    attempts: tuple[dict[str, Any], ...]
    fresh_authorization_required: bool = True


def build_reviewed_tool_corpus(
    base: AuthoredCorpus,
    candidates: Iterable[ToolAttackCandidate],
    *,
    reviewed_candidate_ids: Iterable[str],
) -> ReviewedToolCorpusProfile:
    """Build an immutable proposed profile after an explicit candidate review selection."""

    base_attempts = tuple(seed_to_attempt(case.payload) for case in base.cases)
    if len(base_attempts) != MVP_CASE_COUNT:
        raise ValueError("the approved base corpus no longer contains exactly nine attempts")
    reviewed = tuple(sorted(set(reviewed_candidate_ids)))
    if not reviewed:
        raise ValueError("at least one explicitly reviewed tool candidate is required")
    by_id: dict[str, ToolAttackCandidate] = {}
    for candidate in candidates:
        if candidate.candidate_id in by_id:
            raise ValueError("duplicate tool candidate id")
        by_id[candidate.candidate_id] = candidate
    missing = set(reviewed) - by_id.keys()
    if missing:
        raise ValueError("review selection contains an unknown tool candidate")

    tool_attempts: list[dict[str, Any]] = []
    for candidate_id in reviewed:
        candidate = by_id[candidate_id]
        attempt = {
            "schema_version": "1",
            "case_ref": f"tool-candidate:{candidate.candidate_id}",
            "input_sequence": list(candidate.input_sequence),
            "category": candidate.category,
            "mutation_lineage": [f"tool:{candidate.candidate_id}:{candidate.provenance_sha256}"],
        }
        validate("attack_attempt", attempt)
        tool_attempts.append(attempt)

    attempts = (*base_attempts, *tool_attempts)
    content_hash = corpus_sha256(list(attempts))
    if content_hash == base.content_hash:
        raise ValueError("tool corpus must have an identity distinct from the approved MVP corpus")
    return ReviewedToolCorpusProfile(
        corpus_id=f"reviewed-tool-corpus-{content_hash[:16]}",
        content_hash=content_hash,
        base_corpus_hash=base.content_hash,
        reviewed_candidate_ids=reviewed,
        attempts=attempts,
    )


__all__ = ["ReviewedToolCorpusProfile", "build_reviewed_tool_corpus"]
