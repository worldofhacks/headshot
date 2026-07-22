"""Burp-style, LLM-focused security-workbench projections.

Headshot does not pretend that the commercial Burp Suite product is installed.  Instead, this
module makes the equivalent workflow explicit over capabilities the platform actually owns:
captured target traffic, governed replay and mutation, deterministic DAST, and independent
adjudication.  The traffic inspector consumes only the already-sanitized request ledger and emits
advisory signals; it cannot dispatch traffic or create a Judge verdict.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Literal

MAX_TRAFFIC_PREVIEW_CHARS = 4_096


@dataclass(frozen=True, slots=True)
class WorkbenchCapability:
    workflow: str
    headshot_control: str
    state: Literal["operational", "governed", "not applicable"]
    llm_focus: str
    safeguard: str
    evidence: str

    def public_record(self) -> dict[str, str]:
        return asdict(self)


WORKBENCH_CAPABILITIES: tuple[WorkbenchCapability, ...] = (
    WorkbenchCapability(
        workflow="Dashboard + Target",
        headshot_control="Targets, Campaigns, Coverage",
        state="operational",
        llm_focus="Versioned model/API surfaces and OWASP Web + LLM coverage",
        safeguard="Only persisted ready targets and enabled surfaces are dispatchable",
        evidence="target registry + campaign ledger",
    ),
    WorkbenchCapability(
        workflow="Proxy + Logger + Inspector",
        headshot_control="Traces",
        state="operational",
        llm_focus="Sanitized prompt/response exchange inspection with correlation and cost",
        safeguard="Secrets are redacted before Postgres and Langfuse persistence",
        evidence="outbound_http_requests + Langfuse trace ID",
    ),
    WorkbenchCapability(
        workflow="Repeater",
        headshot_control="Regression replay",
        state="governed",
        llm_focus="Replay a confirmed synthetic case against a versioned target",
        safeguard="New corpus hash and fresh exact-scope authorization; no raw resend button",
        evidence="regression attempt + immutable evidence hash",
    ),
    WorkbenchCapability(
        workflow="Intruder",
        headshot_control="Garak + PyRIT + Giskard + Promptfoo",
        state="governed",
        llm_focus="Prompt injection, exfiltration, tool misuse, encodings and multi-turn mutation",
        safeguard="Candidate-only tools; PolicyGateway owns rate, attempt, timeout and cost caps",
        evidence="content-addressed ToolAttackBundle + mutation lineage",
    ),
    WorkbenchCapability(
        workflow="Scanner",
        headshot_control="OWASP ZAP + independent Judge",
        state="operational",
        llm_focus="Passive web DAST plus behavioral evaluation of agent responses and tool use",
        safeguard="Exact-origin passive ZAP; critical publication remains human-gated",
        evidence="normalized ToolFinding + Judge verdict",
    ),
    WorkbenchCapability(
        workflow="Decoder",
        headshot_control="PyRIT converters",
        state="operational",
        llm_focus="Base64, ROT13 and ASCII-smuggling transformations",
        safeguard="Offline transformation only; converted output is still an untrusted candidate",
        evidence="native converter artifact + provenance digest",
    ),
    WorkbenchCapability(
        workflow="Comparer",
        headshot_control="Judge + evidence + resilience",
        state="operational",
        llm_focus=(
            "Compare expected invariants, target output, prior fixes and independent verdicts"
        ),
        safeguard="The attack generator cannot approve its own result",
        evidence="AttemptResult, Verdict and regression history",
    ),
    WorkbenchCapability(
        workflow="Sequencer",
        headshot_control="Multi-turn lineage + replay protection",
        state="operational",
        llm_focus="Conversation ordering, state-boundary tests and deterministic sequence identity",
        safeguard="Run nonces, attempt nonces and content hashes reject replay or reordering",
        evidence="campaign scope hash + mutation lineage",
    ),
    WorkbenchCapability(
        workflow="Collaborator / out-of-band",
        headshot_control="Exfiltration canaries",
        state="governed",
        llm_focus="Detect attempted data exfiltration in bounded synthetic scenarios",
        safeguard="No public callback listener or uncontrolled off-origin traffic in the MVP",
        evidence="Judge evidence only; OOB network testing is not claimed",
    ),
    WorkbenchCapability(
        workflow="DOM Invader + Clickbandit + Infiltrator",
        headshot_control="ZAP + Semgrep",
        state="not applicable",
        llm_focus="Specialized browser/IAST techniques are outside the black-box LLM chat surface",
        safeguard="No false claim of equivalent DOM or instrumented-runtime coverage",
        evidence="Use separately authorized tooling if those surfaces enter scope",
    ),
)


def security_workbench_records() -> list[dict[str, str]]:
    return [capability.public_record() for capability in WORKBENCH_CAPABILITIES]


def _canonical_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _preview(value: str) -> str:
    if len(value) <= MAX_TRAFFIC_PREVIEW_CHARS:
        return value
    return f"{value[:MAX_TRAFFIC_PREVIEW_CHARS]}\n...[truncated by Headshot]"


def inspect_sanitized_exchange(
    *,
    request_payload: Any,
    response_payload: str | None,
    status_code: int | None,
    error_code: str | None,
    duration_ms: float,
) -> dict[str, Any]:
    """Return bounded previews, hashes, and passive signals for one ledger exchange.

    Inputs must already have passed the outbound-telemetry sanitizer.  Findings are deliberately
    described as signals because only the independent Judge may turn target behavior into a
    trusted verdict.
    """

    request_text = _canonical_text(request_payload)
    response_text = response_payload or ""
    request_lower = request_text.lower()
    response_lower = response_text.lower()
    flags: list[str] = []
    mappings: set[str] = set()

    if error_code or (status_code is not None and status_code >= 500):
        flags.append("transport_or_server_error")
        mappings.add("A09:2021")
    if status_code in {401, 403}:
        flags.append("authentication_boundary_response")
        mappings.add("A07:2021")
    if status_code == 429:
        flags.append("rate_limit_response")
        mappings.add("A04:2021")
    if "***redacted" in request_lower or "***redacted" in response_lower:
        flags.append("secret_redaction_applied")
        mappings.update(("A02:2021", "LLM02:2025"))
    if any(
        marker in response_lower
        for marker in ("system prompt", "hidden instruction", "developer message")
    ):
        flags.append("possible_instruction_disclosure")
        mappings.add("LLM02:2025")
    if any(
        marker in response_lower
        for marker in ('"tool_call"', '"tool_calls"', '"function_call"', "tool invocation")
    ):
        flags.append("tool_invocation_observed")
        mappings.add("LLM06:2025")
    if len(response_text.encode("utf-8")) > 1_048_576:
        flags.append("large_model_response")
        mappings.add("LLM10:2025")
    if duration_ms >= 30_000:
        flags.append("slow_model_response")
        mappings.add("LLM10:2025")

    return {
        "request_preview": _preview(request_text),
        "response_preview": None if response_payload is None else _preview(response_text),
        "request_sha256": hashlib.sha256(request_text.encode("utf-8")).hexdigest(),
        "response_sha256": (
            None
            if response_payload is None
            else hashlib.sha256(response_text.encode("utf-8")).hexdigest()
        ),
        "inspection_flags": flags,
        "inspection_owasp_mappings": sorted(mappings),
    }


__all__ = [
    "MAX_TRAFFIC_PREVIEW_CHARS",
    "WORKBENCH_CAPABILITIES",
    "WorkbenchCapability",
    "inspect_sanitized_exchange",
    "security_workbench_records",
]
