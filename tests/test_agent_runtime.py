"""Agent engine policy and configured-surface security-tool planning."""

from __future__ import annotations

import pytest

from agentforge.agents.runtime import default_assignment, validate_agent_configuration
from agentforge.security_tools.catalog import security_tool
from agentforge.security_tools.scope import plan_tool_for_surface


def test_runtime_defaults_are_four_separated_deterministic_roles() -> None:
    assignments = {
        role: default_assignment(role)
        for role in ("orchestrator", "red_team", "judge", "documentation")
    }

    assert {assignment.execution_mode for assignment in assignments.values()} == {"deterministic"}
    assert assignments["judge"].model == "oracle-precedence-v1"
    assert assignments["red_team"].model == "full-scan-corpus-v1"
    assert len({assignment.configuration_sha256 for assignment in assignments.values()}) == 4


def test_hosted_models_are_staged_and_cannot_replace_governor_or_judge() -> None:
    configured = validate_agent_configuration(
        role="red_team",
        provider="openrouter",
        model="provider/model-v1",
        execution_mode="hosted_advisory",
    )

    assert configured[4] == "staged_pending_authorization"
    with pytest.raises(ValueError, match="not permitted"):
        validate_agent_configuration(
            role="judge",
            provider="anthropic",
            model="provider-model-v1",
            execution_mode="hosted_advisory",
        )


def test_tool_planner_distinguishes_campaign_scan_and_source_assurance() -> None:
    surface = {
        "surface_kind": "chat",
        "protocol": "https",
        "method": "POST",
        "relative_path": "chat",
    }

    garak = plan_tool_for_surface(security_tool("garak"), **surface)
    zap = plan_tool_for_surface(security_tool("zap"), **surface)
    semgrep = plan_tool_for_surface(security_tool("semgrep"), **surface)
    giskard = plan_tool_for_surface(security_tool("giskard"), **surface)

    assert garak.applicability == "in_campaign"
    assert garak.requires_separate_authorization is False
    assert zap.applicability == "companion_scan"
    assert zap.requires_separate_authorization is True
    assert semgrep.applicability == "platform_assurance"
    assert giskard.applicability == "adapter_available"
