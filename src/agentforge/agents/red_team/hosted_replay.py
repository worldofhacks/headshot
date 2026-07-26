"""Hosted Red Team selection over an exact, previously reviewed corpus."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from agentforge.agents.hosted_runtime import (
    HostedCompositionError,
    HostedExecutionLineage,
    HostedRoleRuntime,
)
from agentforge.agents.red_team.seed_replay import seed_to_attempt
from agentforge.contracts import validate

_MAX_SELECTION_CANDIDATES = 64


class HostedReplaySelectorError(HostedCompositionError):
    """The hosted Red Team did not select an exact authorized case."""

    code = "hosted-red-team-selection-failed"


@dataclass(frozen=True, slots=True)
class HostedReplaySelectionResult:
    """One model-selected exact-corpus attempt and its provider lineage."""

    proposal: Mapping[str, Any]
    execution_id: str
    provider_request_id: str
    lineage: HostedExecutionLineage


class HostedReplaySelector:
    """Let the hosted Red Team choose only among immutable authorized cases.

    The model cannot author or mutate target-bound bytes in this replay mode. It returns one
    ``case_ref`` from the closed enum supplied by the Runner; trusted code then projects that exact
    reviewed case into the attack-attempt contract.
    """

    def __init__(self, *, runtime: HostedRoleRuntime) -> None:
        if not isinstance(runtime, HostedRoleRuntime):
            raise HostedReplaySelectorError("hosted role runtime is unavailable")
        self._runtime = runtime

    def select(
        self,
        *,
        cases: Sequence[Mapping[str, Any]],
        directive: Mapping[str, Any],
        parent_execution_id: str,
        parent_request_id: str | None = None,
    ) -> HostedReplaySelectionResult:
        candidate_directive = dict(directive)
        try:
            validate("campaign_directive", candidate_directive)
        except Exception as exc:
            raise HostedReplaySelectorError("campaign directive is invalid") from exc
        category = candidate_directive["category"]
        eligible = [dict(case) for case in cases if case.get("category") == category]
        if not eligible or len(eligible) > _MAX_SELECTION_CANDIDATES:
            raise HostedReplaySelectorError("authorized selection candidates are out of bounds")
        refs = [case.get("case_id") for case in eligible]
        if any(not isinstance(ref, str) or not ref for ref in refs) or len(refs) != len(set(refs)):
            raise HostedReplaySelectorError("authorized case identities are invalid")
        by_ref = dict(zip(refs, eligible, strict=True))
        holder: dict[str, Mapping[str, Any]] = {}

        def validate_selection(raw: Mapping[str, Any]) -> Mapping[str, Any]:
            if set(raw) != {"case_ref"} or raw.get("case_ref") not in by_ref:
                raise HostedReplaySelectorError(
                    "Red Team selected a case outside the authorized corpus"
                )
            proposal = seed_to_attempt(by_ref[str(raw["case_ref"])])
            try:
                validate("attack_attempt", proposal)
            except Exception as exc:
                raise HostedReplaySelectorError(
                    "selected case cannot produce an authorized attack attempt"
                ) from exc
            holder["proposal"] = proposal
            return proposal

        invocation = self._runtime.invoke(
            "red_team",
            input_payload={
                "schema_version": "1",
                "campaign_id": candidate_directive["campaign_id"],
                "category": category,
                "coverage_goal": candidate_directive["coverage_goal"],
                "selection_policy": "select_exact_reviewed_case_only",
                "candidates": [
                    {
                        "case_ref": ref,
                        "turn_count": len(case.get("input_sequence", [])),
                        "test_classification": (
                            case.get("test_design", {}).get("classification")
                            if isinstance(case.get("test_design"), dict)
                            else None
                        ),
                    }
                    for ref, case in zip(refs, eligible, strict=True)
                ],
            },
            output_schema={
                "type": "object",
                "properties": {"case_ref": {"enum": refs}},
                "required": ["case_ref"],
                "additionalProperties": False,
            },
            schema_name="red_team_reviewed_case_selection",
            parent_execution_id=parent_execution_id,
            parent_request_id=parent_request_id,
            validate_output=validate_selection,
        )
        proposal = holder.get("proposal")
        if proposal is None:
            raise HostedReplaySelectorError("Red Team selection was not validated")
        return HostedReplaySelectionResult(
            proposal=proposal,
            execution_id=invocation.execution_id,
            provider_request_id=invocation.provider_request_id,
            lineage=invocation.lineage,
        )


__all__ = [
    "HostedReplaySelectionResult",
    "HostedReplaySelector",
    "HostedReplaySelectorError",
]
