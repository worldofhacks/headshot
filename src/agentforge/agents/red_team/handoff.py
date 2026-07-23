"""Typed, network-free Red Team proposal boundary for the durable Runner.

The campaign authorization is bound to the exact reviewed corpus hash, so this boundary may
select and replay those authored seeds but may not silently mutate their content.  A future
mutation campaign must bind the generated corpus into a new authorization before dispatch.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agentforge.agents.red_team.seed_replay import seed_to_attempt
from agentforge.contracts import validate


class RedTeamProposalError(ValueError):
    """A directive or authored seed cannot produce an authorized AttackAttempt."""


class SeedReplayRedTeam:
    """Consume a CampaignDirective and emit only exact-corpus AttackAttempt proposals."""

    def propose(
        self,
        *,
        cases: Sequence[Mapping[str, Any]],
        directive: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        candidate_directive = dict(directive)
        try:
            validate("campaign_directive", candidate_directive)
        except Exception as exc:
            raise RedTeamProposalError(
                f"campaign directive fails the Red Team handoff contract: {exc}"
            ) from exc

        selected_category = candidate_directive["category"]
        authored = [dict(case) for case in cases]
        if not any(case.get("category") == selected_category for case in authored):
            raise RedTeamProposalError(
                "CampaignDirective selected category is absent from the authorized corpus"
            )

        refs = [case.get("case_id") for case in authored]
        if len(refs) != len(set(refs)):
            raise RedTeamProposalError("authorized corpus contains duplicate case identifiers")

        # Python's sort is stable: prioritize the directed category while preserving the
        # reviewed corpus order inside both partitions.
        ordered = sorted(
            authored,
            key=lambda case: case.get("category") != selected_category,
        )
        proposals: list[dict[str, Any]] = []
        for case in ordered:
            try:
                proposal = seed_to_attempt(case)
                validate("attack_attempt", proposal)
            except Exception as exc:
                raise RedTeamProposalError(
                    "authored seed cannot produce a valid AttackAttempt"
                ) from exc
            proposals.append(proposal)
        return proposals
