"""Shared case taxonomy: supported execution categories and reviewed-workload source kinds.

Two distinct concepts were previously expressed by three independent copies of the same
three-element frozenset (``control_plane.store._CASE_CATEGORIES``,
``api.postgres._REQUIRED_CATEGORIES`` and ``campaign.corpus.MVP_CATEGORIES``). Because they were
textually identical they were easy to read as one rule, and the reviewed ``headshot-live-100-v1``
workload — authored across six categories — could never produce an attempt for the three
categories that were missing from the accept-lists.

They are NOT one rule:

* :data:`SUPPORTED_CASE_CATEGORIES` is an ACCEPT-LIST. It answers "may a case in this category
  execute at all?" and must cover every category the reviewed workload actually contains.
* :data:`MVP_REQUIRED_CATEGORIES` is a COVERAGE FLOOR. It answers "which categories must a run
  have observed before coverage is satisfied?" It is deliberately the original three and is
  applied with ``issubset`` so a richer six-category run still satisfies it, while a legacy
  three-category run remains valid.

Keeping both here makes the distinction explicit and prevents the two from drifting apart again.
``campaign.corpus.MVP_CATEGORIES`` is intentionally left in place as the immutable nine-case MVP
corpus identity check and is not re-exported from here.

This module imports only the standard library. Every layer (corpus loaders, the control-plane
store, and the read/coverage API) can therefore depend on it without creating an import cycle —
``agentforge.campaign`` eagerly constructs the campaign coordinator on import, so the control
plane cannot safely import the taxonomy from that package.
"""

from __future__ import annotations

from typing import Final

#: Every category the platform will admit for execution and evidence aggregation.
#:
#: This is the reviewed content of ``headshot-live-100-v1``. Widening the accept-list to match
#: the corpus does not lower any requirement: the graded floor is
#: :data:`MVP_REQUIRED_CATEGORIES`, which is unchanged.
SUPPORTED_CASE_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "prompt_injection",
        "data_exfiltration",
        "tool_misuse",
        "state_corruption",
        "denial_of_service",
        "identity_role_exploitation",
    }
)

#: The MVP coverage floor. Apply with ``MVP_REQUIRED_CATEGORIES.issubset(observed)`` — never with
#: equality, which would reject a superset run that legitimately covers more ground.
MVP_REQUIRED_CATEGORIES: Final[frozenset[str]] = frozenset(
    {
        "prompt_injection",
        "data_exfiltration",
        "tool_misuse",
    }
)

#: How a reviewed workload case came to exist. This is PRODUCER lineage and is deliberately
#: separate from security-tool lineage (``source_tool`` / ``source_technique``).
#:
#: ``hosted_red_team`` is a producer kind, not a security tool. It must never populate
#: ``source_tool`` and must never contribute to Garak/PyRIT/Promptfoo/Giskard tool metrics. Only
#: identifiers from ``agentforge.security_tools.catalog`` may populate ``source_tool``.
REVIEWED_WORKLOAD_SOURCE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "m11_seed",
        "reviewed_full_scan",
        "hosted_red_team",
    }
)

#: Closed syntax for the immutable instance identifiers carried by reviewed workload manifests.
WORKLOAD_INSTANCE_ID_PATTERN: Final[str] = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"

__all__ = [
    "MVP_REQUIRED_CATEGORIES",
    "REVIEWED_WORKLOAD_SOURCE_KINDS",
    "SUPPORTED_CASE_CATEGORIES",
    "WORKLOAD_INSTANCE_ID_PATTERN",
]
