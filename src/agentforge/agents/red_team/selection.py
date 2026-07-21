"""Coverage-aware case selection (M8).

ARCHITECTURE.md §8/§16 (coverage-driven prioritization), PRD-14/17; M6a coverage signal.

The Red Team steers the campaign toward the coverage GAP: given the M6a coverage snapshot
(category -> covered-attempt count), it orders the LEAST-covered category's cases first, so a
partial success mutates toward where the platform is blind. Selection is DETERMINISTIC given a
fixed snapshot (no order-breaking randomness) and TOTAL — it reorders, it never silently drops
or duplicates a case. Ties break on category name / stable input order so the result is
reproducible for a regression/replay run.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

# A category absent from the snapshot is treated as maximally UNCOVERED (0 attempts seen), so a
# brand-new category is prioritized rather than silently sorted last.
_UNSEEN_COVERAGE = 0


def least_covered_category(coverage: Mapping[str, int]) -> str:
    """Return the least-covered category from a coverage snapshot.

    Ranks by covered-attempt count ascending; ties break on the category name so the choice is
    deterministic (never dependent on dict insertion order). Raises ``ValueError`` on an empty
    snapshot rather than guessing a category.
    """
    if not coverage:
        raise ValueError("coverage snapshot is empty; no least-covered category to select")
    return min(coverage, key=lambda category: (coverage[category], category))


def select_cases(
    cases: Sequence[dict[str, Any]], coverage: Mapping[str, int]
) -> list[dict[str, Any]]:
    """Order ``cases`` so the least-covered category's cases come FIRST.

    Cases are grouped by ``category`` and the groups are ordered by (covered count ascending,
    category name), so the whole least-covered group leads the campaign toward the coverage gap.
    Within a group the input order is preserved (a stable reorder). The result is deterministic
    for a fixed snapshot and total — every input case appears exactly once, none is dropped and
    none is invented.
    """

    def rank(case: dict[str, Any]) -> tuple[int, str]:
        category = case.get("category", "")
        return (coverage.get(category, _UNSEEN_COVERAGE), category)

    # ``sorted`` is stable, so cases sharing a category keep their original relative order.
    return sorted(cases, key=rank)
