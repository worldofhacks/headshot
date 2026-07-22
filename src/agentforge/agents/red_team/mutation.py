"""Mutation interface — a partial success -> N lineage-tagged variant attempts (M8).

ARCHITECTURE.md §8/§16 (mutate toward the coverage gap), PRD-14/17.

Given a partial-success attempt and the M6a coverage snapshot, :func:`mutate` asks a
:class:`RedTeamProvider` for ``count`` variant continuations aimed at the LEAST-covered category,
then wraps each into a schema-valid ``attack_attempt`` (P10) that PRESERVES LINEAGE — every
variant records the chain of ancestors it descends from, so a confirmed exploit stays traceable
to its original seed. The DETERMINISTIC fake/cassette provider generates the variants offline (no
model, no network); the hosted provider is the boundary for real generation (behind
authorization, never called in a test).

A variant is PROPOSED input only. It carries no ``credential``, no ``content_hash``, and no
``verdict`` — the untrusted generator never mints evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agentforge.agents.red_team.providers import RedTeamProvider
from agentforge.agents.red_team.selection import least_covered_category

_SCHEMA_VERSION = "1"


def _lineage_of(attempt: Mapping[str, Any]) -> list[str]:
    """Return the ancestor chain a mutation of ``attempt`` should carry forward.

    The child's lineage is the parent's own lineage EXTENDED by the parent's ``case_ref`` — so a
    grandchild records both its parent and its grandparent, and the lineage only ever grows.
    """
    parent_lineage = list(attempt.get("mutation_lineage", []))
    parent_ref = attempt.get("case_ref")
    if parent_ref is not None and parent_ref not in parent_lineage:
        parent_lineage.append(parent_ref)
    return parent_lineage


def mutate(
    attempt: dict[str, Any],
    *,
    coverage: Mapping[str, int],
    count: int,
    provider: RedTeamProvider,
) -> list[dict[str, Any]]:
    """Mutate a partial-success ``attempt`` into ``count`` variant AttackAttempts.

    The variants are aimed at the least-covered category (so a partial success steers toward the
    coverage gap), generated offline by ``provider``. Each returned variant is a schema-valid
    ``attack_attempt`` carrying:

    * a fresh, deterministic ``case_ref`` derived from the parent (so a later generation can name
      it in its own lineage);
    * the parent's ``input_sequence`` extended by the provider's generated continuation;
    * the target ``category``; and
    * ``mutation_lineage`` — the parent's ancestry plus the parent itself, so the whole descent is
      recorded and a confirmed exploit remains traceable to the original seed.

    No trusted field (credential / content_hash / verdict) is ever attached — mutation produces
    proposed input only.
    """
    target_category = least_covered_category(coverage)
    lineage = _lineage_of(attempt)
    parent_ref = attempt.get("case_ref", "seed")

    generated = provider.generate(attempt, count=count, category=target_category)

    variants: list[dict[str, Any]] = []
    for index, gen in enumerate(generated):
        child_lineage = list(lineage)
        provenance_ref = gen.get("mutation_lineage_ref")
        if isinstance(provenance_ref, str) and provenance_ref not in child_lineage:
            child_lineage.append(provenance_ref)
        variant: dict[str, Any] = {
            "schema_version": _SCHEMA_VERSION,
            # A deterministic child ref, distinct from the parent so lineage chains are legible.
            "case_ref": f"{parent_ref}~m{index}",
            "input_sequence": list(gen["input_sequence"]),
            "category": target_category,
            "mutation_lineage": child_lineage,
        }
        variants.append(variant)
    return variants
