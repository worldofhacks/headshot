"""The authoritative Runner handoff: CampaignDirective -> Red Team -> AttackAttempt."""

from __future__ import annotations

import socket

import pytest

from agentforge.agents.red_team import RedTeamProposalError, SeedReplayRedTeam
from agentforge.contracts import is_valid


def _directive(category: str = "data_exfiltration") -> dict[str, object]:
    return {
        "schema_version": "1",
        "campaign_id": "run-red-team-handoff-1",
        "target_ref": "synthetic-copilot",
        "category": category,
        "coverage_goal": "close the highest-priority verified gap",
        "mutation_policy": "reviewed_seed_replay_only",
        "caps": {"budget_usd": 5.0, "rate_per_min": 30, "timeout_s": 120},
    }


def _case(case_id: str, category: str) -> dict[str, object]:
    return {
        "case_id": case_id,
        "category": category,
        "input_sequence": [f"synthetic request for {case_id}"],
    }


def test_directive_selects_priority_and_red_team_emits_typed_attempts() -> None:
    cases = [
        _case("AF-TM-1", "tool_misuse"),
        _case("AF-PI-1", "prompt_injection"),
        _case("AF-DX-1", "data_exfiltration"),
    ]

    proposals = SeedReplayRedTeam().propose(cases=cases, directive=_directive())

    assert [item["case_ref"] for item in proposals] == ["AF-DX-1", "AF-TM-1", "AF-PI-1"]
    assert all(is_valid("attack_attempt", item) for item in proposals)
    assert all(
        forbidden not in item
        for item in proposals
        for forbidden in ("credential", "content_hash", "verdict", "evidence")
    )


def test_red_team_rejects_invalid_directive_duplicates_and_unknown_priority() -> None:
    red_team = SeedReplayRedTeam()
    cases = [_case("AF-PI-1", "prompt_injection")]

    invalid = _directive()
    invalid["caps"] = {"budget_usd": -1, "rate_per_min": 30}
    with pytest.raises(RedTeamProposalError, match="directive"):
        red_team.propose(cases=cases, directive=invalid)

    with pytest.raises(RedTeamProposalError, match="duplicate"):
        red_team.propose(cases=[cases[0], cases[0]], directive=_directive("prompt_injection"))

    with pytest.raises(RedTeamProposalError, match="selected category"):
        red_team.propose(cases=cases, directive=_directive("tool_misuse"))


def test_red_team_handoff_is_deterministic_and_network_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Red Team seed proposal attempted network access")

    monkeypatch.setattr(socket, "socket", deny_socket)
    cases = [_case("AF-PI-1", "prompt_injection"), _case("AF-DX-1", "data_exfiltration")]

    first = SeedReplayRedTeam().propose(cases=cases, directive=_directive())
    second = SeedReplayRedTeam().propose(cases=cases, directive=_directive())

    assert first == second
