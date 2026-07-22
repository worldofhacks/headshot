from __future__ import annotations

from agentforge.security_tools.catalog import security_tool
from agentforge.security_tools.workbench import (
    MAX_TRAFFIC_PREVIEW_CHARS,
    inspect_sanitized_exchange,
    security_workbench_records,
)


def test_llm_workbench_is_operational_without_claiming_burp_is_installed() -> None:
    tool = security_tool("headshot-llm-workbench")
    records = security_workbench_records()

    assert tool.availability == "operational and evidenced"
    assert tool.target_access == "policy_gateway_only"
    assert "PortSwigger Burp Suite itself is not installed" in tool.detail
    assert {record["workflow"] for record in records} >= {
        "Proxy + Logger + Inspector",
        "Repeater",
        "Intruder",
        "Scanner",
        "Comparer",
    }
    assert any(record["state"] == "not applicable" for record in records)


def test_passive_inspector_hashes_and_bounds_the_sanitized_exchange() -> None:
    response = "system prompt: ***REDACTED***" + "x" * MAX_TRAFFIC_PREVIEW_CHARS
    inspection = inspect_sanitized_exchange(
        request_payload={"turns": ["synthetic"]},
        response_payload=response,
        status_code=200,
        error_code=None,
        duration_ms=30_000,
    )

    assert len(inspection["request_sha256"]) == 64
    assert len(inspection["response_sha256"]) == 64
    assert inspection["response_preview"].endswith("...[truncated by Headshot]")
    assert inspection["inspection_flags"] == [
        "secret_redaction_applied",
        "possible_instruction_disclosure",
        "slow_model_response",
    ]
    assert inspection["inspection_owasp_mappings"] == [
        "A02:2021",
        "LLM02:2025",
        "LLM10:2025",
    ]


def test_passive_inspector_reports_transport_and_tool_use_as_advisory_signals() -> None:
    inspection = inspect_sanitized_exchange(
        request_payload={"turns": ["synthetic"]},
        response_payload='{"tool_calls": [{"name": "lookup"}]}',
        status_code=503,
        error_code="upstream_unavailable",
        duration_ms=10,
    )

    assert inspection["inspection_flags"] == [
        "transport_or_server_error",
        "tool_invocation_observed",
    ]
    assert inspection["inspection_owasp_mappings"] == ["A09:2021", "LLM06:2025"]
