"""Target-surface compatibility planning for the trusted security-tool catalog.

This planner never launches a scanner.  It makes the current execution boundary explicit:
which tools contribute exact-corpus cases, which can inspect the configured live origin under a
separate authorization, and which apply only to Headshot's own source.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from agentforge.security_tools.catalog import SecurityToolDefinition

Applicability = Literal[
    "in_campaign",
    "companion_scan",
    "platform_assurance",
    "adapter_available",
    "not_applicable",
]

_FULL_SCAN_TOOL_IDS = frozenset({"garak", "pyrit", "promptfoo"})


@dataclass(frozen=True, slots=True)
class ToolScopePlan:
    applicability: Applicability
    execution_mode: str
    reason: str
    requires_separate_authorization: bool

    def public_record(self) -> dict[str, Any]:
        return {
            "applicability": self.applicability,
            "execution_mode": self.execution_mode,
            "scope_reason": self.reason,
            "requires_separate_authorization": self.requires_separate_authorization,
        }


def plan_tool_for_surface(
    tool: SecurityToolDefinition,
    *,
    surface_kind: str,
    protocol: str,
    method: str,
    relative_path: str,
) -> ToolScopePlan:
    """Return the truthful operational posture for one configured target surface."""

    normalized_kind = surface_kind.strip().lower()
    normalized_protocol = protocol.strip().lower()
    normalized_method = method.strip().upper()
    normalized_path = relative_path.strip().lstrip("/")
    conversational = normalized_kind in {
        "chat",
        "completion",
        "responses",
        "messages",
        "tool",
        "rag",
        "memory",
        "action",
    }

    if tool.tool_id in _FULL_SCAN_TOOL_IDS and conversational:
        return ToolScopePlan(
            applicability="in_campaign",
            execution_mode="reviewed candidates dispatched through the policy gateway",
            reason=(
                f"Pinned {tool.name} candidates are part of the exact authorized full-scan "
                f"corpus for {normalized_method} /{normalized_path}."
            ),
            requires_separate_authorization=False,
        )
    if tool.tool_id == "giskard" and conversational:
        return ToolScopePlan(
            applicability="adapter_available",
            execution_mode="native artifact import and governed candidate review",
            reason=(
                "The Giskard adapter can normalize agent/RAG scenarios, but no Giskard case is "
                "inside the currently pinned authorization corpus."
            ),
            requires_separate_authorization=True,
        )
    if tool.tool_id == "zap":
        if normalized_protocol == "https":
            return ToolScopePlan(
                applicability="companion_scan",
                execution_mode="exact-origin passive baseline",
                reason=(
                    "The HTTPS origin is compatible with bounded passive DAST. ZAP remains a "
                    "separate, explicit scan authorization and never inherits target credentials."
                ),
                requires_separate_authorization=True,
            )
        return ToolScopePlan(
            applicability="not_applicable",
            execution_mode="disabled",
            reason="Live ZAP scope requires an approved HTTPS origin.",
            requires_separate_authorization=True,
        )
    if tool.tool_id == "semgrep":
        return ToolScopePlan(
            applicability="platform_assurance",
            execution_mode="Headshot repository SAST",
            reason=(
                "Semgrep scans Headshot source and policy boundaries; a black-box target URL "
                "does not expose target source code."
            ),
            requires_separate_authorization=False,
        )
    if tool.tool_id == "headshot-llm-workbench" and conversational:
        return ToolScopePlan(
            applicability="in_campaign",
            execution_mode="sanitized intercept, replay, evidence and independent adjudication",
            reason=(
                "Every physical request to this conversational surface crosses the Headshot "
                "policy gateway and authoritative request/evidence ledgers."
            ),
            requires_separate_authorization=False,
        )
    return ToolScopePlan(
        applicability="not_applicable",
        execution_mode="disabled",
        reason=f"{tool.name} has no approved execution path for this configured surface.",
        requires_separate_authorization=True,
    )


__all__ = ["Applicability", "ToolScopePlan", "plan_tool_for_surface"]
