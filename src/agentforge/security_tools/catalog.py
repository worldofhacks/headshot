"""Trusted, immutable catalog for configured security-tool integrations.

The catalog is intentionally code-owned.  A browser payload cannot register a scanner, select a
binary, or relax a scanner's target-access posture.  LLM attack frameworks contribute candidate
inputs or scan-only observations; they never receive target credentials and never bypass the
PolicyGateway.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

ToolAvailability = Literal[
    "operational and evidenced",
    "adapter integrated, execution deferred",
    "evaluated and rejected",
    "blocked pending authorization",
]


@dataclass(frozen=True, slots=True)
class SecurityToolDefinition:
    tool_id: str
    name: str
    version: str
    kind: Literal["llm-attack", "llm-eval", "llm-proxy", "dast", "sast", "dependency", "commercial"]
    availability: ToolAvailability
    integration_mode: str
    target_access: Literal["none", "policy_gateway_only", "exact_origin_passive", "repository_only"]
    capabilities: tuple[str, ...]
    owasp_llm: tuple[str, ...] = ()
    owasp_web: tuple[str, ...] = ()
    operational_scope: tuple[str, ...] = ()
    adapter_only_scope: tuple[str, ...] = ()
    execution_evidence: tuple[str, ...] = ()
    last_verified_at: str = "2026-07-22T16:11:19Z"
    detail: str = ""

    def public_record(self) -> dict[str, object]:
        """Return the safe UI/read-model projection; never include command or credential data."""

        return asdict(self)


SECURITY_TOOL_CATALOG: tuple[SecurityToolDefinition, ...] = (
    SecurityToolDefinition(
        tool_id="garak",
        name="NVIDIA Garak",
        version="0.15.1",
        kind="llm-attack",
        availability="operational and evidenced",
        integration_mode="native JSONL probes and results -> governed candidates + scan findings",
        target_access="none",
        capabilities=(
            "broad probe corpus",
            "prompt injection",
            "encoding bypass",
            "system prompt leakage",
            "data exfiltration",
            "multi-turn GOAT/FITD seeds",
        ),
        owasp_llm=("LLM01:2025", "LLM02:2025", "LLM06:2025", "LLM07:2025", "LLM10:2025"),
        operational_scope=("native JSONL attempt/eval import", "offline Dan_11_0 probe generation"),
        adapter_only_scope=("other installed Garak probe families",),
        execution_evidence=("ci://security-tools/garak.report.jsonl",),
        detail=(
            "Garak generates candidates only; AgentForge owns dispatch, evidence, and verdict "
            "authority."
        ),
    ),
    SecurityToolDefinition(
        tool_id="pyrit",
        name="Microsoft PyRIT",
        version="0.14.0",
        kind="llm-attack",
        availability="operational and evidenced",
        integration_mode="bounded converters and AttackResult export -> governed mutations",
        target_access="none",
        capabilities=(
            "Crescendo",
            "TAP",
            "Skeleton Key",
            "encoding converters",
            "ASCII smuggling",
            "multi-turn attack lineage",
        ),
        owasp_llm=("LLM01:2025", "LLM02:2025", "LLM06:2025", "LLM10:2025"),
        operational_scope=(
            "Base64 converter",
            "ROT13 converter",
            "ASCII smuggling converter",
            "AttackResult import",
        ),
        adapter_only_scope=("Crescendo orchestration", "TAP", "Skeleton Key"),
        execution_evidence=("ci://security-tools/pyrit.json",),
        detail=(
            "PyRIT creates transformations and multi-turn candidates; its scorer is advisory only."
        ),
    ),
    SecurityToolDefinition(
        tool_id="giskard",
        name="Giskard Scan",
        version="1.0.0b3",
        kind="llm-attack",
        availability="operational and evidenced",
        integration_mode="scenario suite export -> governed RAG/agent candidates + scan findings",
        target_access="none",
        capabilities=(
            "agent vulnerability scan",
            "prompt injection dataset",
            "GOAT",
            "Crescendo",
            "GCG",
            "knowledge-base and RAG scenarios",
        ),
        owasp_llm=("LLM01:2025", "LLM02:2025", "LLM04:2025", "LLM08:2025", "LLM09:2025"),
        operational_scope=(
            "packaged prompt-injection scenario load",
            "native scenario/result import",
        ),
        adapter_only_scope=(
            "LLM-generated interactions",
            "GOAT",
            "Crescendo",
            "GCG",
            "target scan",
        ),
        execution_evidence=("ci://security-tools/giskard.json",),
        detail=(
            "Packaged scenarios load offline; generated attacks and target scans remain unexecuted."
        ),
    ),
    SecurityToolDefinition(
        tool_id="promptfoo",
        name="Promptfoo",
        version="0.121.19",
        kind="llm-eval",
        availability="operational and evidenced",
        integration_mode="red-team presets and JSON eval output -> governed candidates + findings",
        target_access="none",
        capabilities=(
            "OWASP LLM Top 10",
            "OWASP API Top 10",
            "MITRE ATLAS",
            "NIST AI RMF",
            "jailbreak strategies",
            "RAG and agent plugins",
        ),
        owasp_llm=tuple(f"LLM{index:02d}:2025" for index in range(1, 11)),
        operational_scope=("pre-authored offline eval", "native results JSON import"),
        adapter_only_scope=("remote red-team generation", "remote-only plugins"),
        execution_evidence=("ci://security-tools/promptfoo.json",),
        detail=(
            "Remote generation and cloud sharing are disabled; results stay local and normalized."
        ),
    ),
    SecurityToolDefinition(
        tool_id="zap",
        name="OWASP ZAP",
        version="2.17.0",
        kind="dast",
        availability="operational and evidenced",
        integration_mode="pinned passive baseline -> exact-origin normalized findings",
        target_access="exact_origin_passive",
        capabilities=("passive DAST", "HTTP hardening", "web misconfiguration", "bounded spider"),
        owasp_web=("A03:2021", "A04:2021", "A05:2021", "A10:2021"),
        operational_scope=(
            "isolated passive fake-target baseline",
            "separately authorized exact-origin HTTPS passive baseline",
        ),
        execution_evidence=(
            "ci://security-tools/zap.json",
            "postgres://tool_findings?tool=zap",
        ),
        detail=(
            "Passive-only and exact-origin checked before and after execution. Live target scans "
            "require their own authorization and never inherit campaign credentials."
        ),
    ),
    SecurityToolDefinition(
        tool_id="semgrep",
        name="Semgrep",
        version="1.170.0",
        kind="sast",
        availability="operational and evidenced",
        integration_mode="repository SAST -> normalized findings",
        target_access="repository_only",
        capabilities=("SAST", "prompt-construction checks", "policy-boundary checks"),
        owasp_web=("A01:2021", "A03:2021", "A04:2021", "A05:2021"),
        operational_scope=("repository SAST",),
        execution_evidence=(
            "ci://security-tools/semgrep.json",
            "ci://security-tools/semgrep.sarif",
        ),
        detail="Scans Headshot source only; it is not presented as live-target evidence.",
    ),
    SecurityToolDefinition(
        tool_id="headshot-llm-workbench",
        name="Headshot LLM Security Workbench",
        version="1.0.0",
        kind="llm-proxy",
        availability="operational and evidenced",
        integration_mode=(
            "sanitized intercept ledger + governed replay/fuzzing + ZAP + independent Judge"
        ),
        target_access="policy_gateway_only",
        capabilities=(
            "request and response inspector",
            "traffic logger and search",
            "governed replay",
            "bounded LLM fuzzing",
            "passive DAST",
            "message comparison",
            "multi-turn sequence analysis",
            "encoding transforms",
        ),
        owasp_llm=tuple(f"LLM{index:02d}:2025" for index in range(1, 11)),
        owasp_web=(
            "A01:2021",
            "A02:2021",
            "A03:2021",
            "A04:2021",
            "A05:2021",
            "A07:2021",
            "A09:2021",
            "A10:2021",
        ),
        operational_scope=(
            "Postgres + Langfuse traffic ledger",
            "sanitized request/response inspector",
            "reviewed-corpus regression replay",
            "Garak/PyRIT/Giskard/Promptfoo mutation",
            "exact-origin passive ZAP",
            "independent Judge comparison",
        ),
        adapter_only_scope=(
            "active web DAST",
            "public out-of-band callback listener",
            "DOM and instrumented-runtime testing",
        ),
        execution_evidence=(
            "postgres://outbound_http_requests",
            "langfuse://target-http-request",
            "ci://tests/test_outbound_telemetry.py",
        ),
        detail=(
            "Burp-style LLM workflow built from governed Headshot capabilities; PortSwigger "
            "Burp Suite itself is not installed or claimed."
        ),
    ),
)

_BY_ID = {tool.tool_id: tool for tool in SECURITY_TOOL_CATALOG}


def security_tool(tool_id: str) -> SecurityToolDefinition:
    try:
        return _BY_ID[tool_id]
    except KeyError as exc:
        raise ValueError("security tool is not in the trusted catalog") from exc


def security_tool_records() -> list[dict[str, object]]:
    return [tool.public_record() for tool in SECURITY_TOOL_CATALOG]


__all__ = [
    "SECURITY_TOOL_CATALOG",
    "SecurityToolDefinition",
    "ToolAvailability",
    "security_tool",
    "security_tool_records",
]
