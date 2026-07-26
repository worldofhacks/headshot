"""Hosted Red Team exact-corpus selection."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agentforge.agents.hosted_runtime import HostedRoleRuntime
from agentforge.agents.red_team import HostedReplaySelector, HostedReplaySelectorError


class _Runtime(HostedRoleRuntime):
    def __init__(self, selected: str) -> None:
        self.selected = selected
        self.calls: list[dict[str, Any]] = []

    def invoke(self, role: str, **kwargs: Any) -> Any:
        self.calls.append({"role": role, **kwargs})
        validated = kwargs["validate_output"]({"case_ref": self.selected})
        return SimpleNamespace(
            execution_id="execution-red-team-hosted",
            provider_request_id="provider-request-red-team",
            lineage=SimpleNamespace(role="red_team"),
            output=validated,
        )


def _directive() -> dict[str, object]:
    return {
        "schema_version": "1",
        "campaign_id": "run-hosted-replay-1",
        "target_ref": "openemr",
        "category": "prompt_injection",
        "coverage_goal": "execute the exact reviewed manifest",
        "mutation_policy": "preserve_authorized_manifest_order",
        "caps": {"budget_usd": 10.0, "rate_per_min": 30, "timeout_s": 300},
    }


def _case(case_ref: str) -> dict[str, object]:
    return {
        "case_id": case_ref,
        "category": "prompt_injection",
        "input_sequence": [f"synthetic reviewed input {case_ref}"],
        "test_design": {"classification": "boundary"},
    }


def test_hosted_selector_emits_only_the_model_selected_reviewed_case() -> None:
    runtime = _Runtime("CASE-002")
    result = HostedReplaySelector(runtime=runtime).select(
        cases=[_case("CASE-001"), _case("CASE-002")],
        directive=_directive(),
        parent_execution_id="execution-orchestrator-hosted",
    )

    assert result.proposal["case_ref"] == "CASE-002"
    assert result.proposal["input_sequence"] == ["synthetic reviewed input CASE-002"]
    assert runtime.calls[0]["role"] == "red_team"
    assert runtime.calls[0]["parent_execution_id"] == "execution-orchestrator-hosted"
    assert runtime.calls[0]["output_schema"]["properties"]["case_ref"]["enum"] == [
        "CASE-001",
        "CASE-002",
    ]
    assert runtime.calls[0]["output_schema"]["properties"]["case_ref"]["type"] == "string"


def test_hosted_selector_fails_closed_on_out_of_corpus_model_choice() -> None:
    runtime = _Runtime("CASE-OUTSIDE")

    with pytest.raises(HostedReplaySelectorError, match="outside"):
        HostedReplaySelector(runtime=runtime).select(
            cases=[_case("CASE-001")],
            directive=_directive(),
            parent_execution_id="execution-orchestrator-hosted",
        )
