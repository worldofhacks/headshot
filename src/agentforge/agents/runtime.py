"""Trusted runtime identities and model-policy validation for the four agent roles.

The word ``model`` in this module means the engine that actually performs a role.  The
production defaults are deterministic policy engines, not hidden hosted-LLM calls.  Hosted
models may be staged for candidate generation or report drafting, but they cannot become active
until a separately authorized corpus/calibration workflow exists.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal

AgentRole = Literal["orchestrator", "red_team", "judge", "documentation"]
ExecutionMode = Literal["deterministic", "hosted_advisory"]
ActivationState = Literal["active", "staged_pending_authorization"]

AGENT_ROLES: tuple[AgentRole, ...] = (
    "orchestrator",
    "red_team",
    "judge",
    "documentation",
)

_MODEL_ID = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}\Z")
_HOSTED_PROVIDERS = frozenset({"openrouter", "together", "anthropic"})
_DETERMINISTIC_MODELS: dict[AgentRole, frozenset[str]] = {
    "orchestrator": frozenset({"coverage-governor-v1"}),
    "red_team": frozenset({"full-scan-corpus-v1", "corpus-replay-v1"}),
    "judge": frozenset({"oracle-precedence-v1"}),
    "documentation": frozenset({"evidence-report-v1", "concise-evidence-report-v1"}),
}
_HOSTED_ELIGIBLE = frozenset({"red_team", "documentation"})


@dataclass(frozen=True, slots=True)
class AgentDefinition:
    role: AgentRole
    display_name: str
    responsibility: str
    trust_level: str
    target_access: str
    input_contract: str
    output_contract: str
    default_provider: str
    default_model: str
    default_execution_mode: ExecutionMode = "deterministic"

    def public_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AgentAssignment:
    role: AgentRole
    provider: str
    model: str
    execution_mode: ExecutionMode
    activation_state: ActivationState
    version: int
    configuration_sha256: str
    configured_at: str | None = None
    configured_by: str | None = None

    def public_record(self) -> dict[str, Any]:
        return asdict(self)


AGENT_DEFINITIONS: tuple[AgentDefinition, ...] = (
    AgentDefinition(
        role="orchestrator",
        display_name="Orchestrator",
        responsibility=(
            "Reads verified coverage, findings, regression, queue and budget signals; "
            "prioritizes, redirects or halts work."
        ),
        trust_level="trusted governor",
        target_access="none",
        input_contract="OrchestrationSnapshot v1",
        output_contract="CampaignDirective v1",
        default_provider="headshot",
        default_model="coverage-governor-v1",
    ),
    AgentDefinition(
        role="red_team",
        display_name="Red Team",
        responsibility=(
            "Selects the exact authorized authored and security-tool candidate corpus; "
            "never mints evidence or target authority."
        ),
        trust_level="untrusted generator",
        target_access="policy gateway only",
        input_contract="CampaignDirective v1 + authorized AttackCase corpus",
        output_contract="AttackAttempt v1",
        default_provider="headshot",
        default_model="full-scan-corpus-v1",
    ),
    AgentDefinition(
        role="judge",
        display_name="Independent Judge",
        responsibility=(
            "Evaluates hash-verified evidence with deterministic oracle/canary precedence; "
            "never generates attacks or publishes findings."
        ),
        trust_level="independent evaluator",
        target_access="none",
        input_contract="EvidenceEnvelope v1",
        output_contract="Verdict v1",
        default_provider="headshot",
        default_model="oracle-precedence-v1",
    ),
    AgentDefinition(
        role="documentation",
        display_name="Documentation",
        responsibility=(
            "Converts only confirmed, sanitized evidence into a draft report and a blocked "
            "regression disposition."
        ),
        trust_level="trusted draft writer",
        target_access="none",
        input_contract="Verdict v1 + sanitized DocumentationInput",
        output_contract="VulnReport v1 + RegressionDisposition v1",
        default_provider="headshot",
        default_model="evidence-report-v1",
    ),
)

_DEFINITION_BY_ROLE = {definition.role: definition for definition in AGENT_DEFINITIONS}


def agent_definition(role: str) -> AgentDefinition:
    try:
        return _DEFINITION_BY_ROLE[role]  # type: ignore[index]
    except KeyError as exc:
        raise ValueError("agent role is not in the trusted runtime catalog") from exc


def configuration_sha256(configuration: dict[str, Any]) -> str:
    canonical = json.dumps(
        configuration,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def validate_agent_configuration(
    *,
    role: str,
    provider: str,
    model: str,
    execution_mode: str,
) -> tuple[AgentRole, str, str, ExecutionMode, ActivationState, str]:
    """Validate one assignment and return its normalized, activation-safe representation."""

    definition = agent_definition(role)
    normalized_provider = provider.strip().lower()
    normalized_model = model.strip()
    if _MODEL_ID.fullmatch(normalized_model) is None:
        raise ValueError("agent model identifier is invalid")
    if execution_mode not in {"deterministic", "hosted_advisory"}:
        raise ValueError("agent execution mode is invalid")

    if execution_mode == "deterministic":
        if normalized_provider != "headshot":
            raise ValueError("deterministic agent engines use the headshot provider")
        if normalized_model not in _DETERMINISTIC_MODELS[definition.role]:
            raise ValueError("deterministic model is not approved for this agent role")
        activation_state: ActivationState = "active"
    else:
        if definition.role not in _HOSTED_ELIGIBLE:
            raise ValueError("hosted advisory models are not permitted for this agent role")
        if normalized_provider not in _HOSTED_PROVIDERS:
            raise ValueError("hosted advisory provider is not approved")
        # Hosted generation cannot alter a corpus after its hash was human-authorized, and a
        # model cannot replace the independent Judge. Persist the choice, but keep it staged.
        activation_state = "staged_pending_authorization"

    payload = {
        "role": definition.role,
        "provider": normalized_provider,
        "model": normalized_model,
        "execution_mode": execution_mode,
        "activation_state": activation_state,
    }
    return (
        definition.role,
        normalized_provider,
        normalized_model,
        execution_mode,  # type: ignore[return-value]
        activation_state,
        configuration_sha256(payload),
    )


def default_assignment(role: str) -> AgentAssignment:
    definition = agent_definition(role)
    payload = {
        "role": definition.role,
        "provider": definition.default_provider,
        "model": definition.default_model,
        "execution_mode": definition.default_execution_mode,
        "activation_state": "active",
    }
    return AgentAssignment(
        role=definition.role,
        provider=definition.default_provider,
        model=definition.default_model,
        execution_mode=definition.default_execution_mode,
        activation_state="active",
        version=1,
        configuration_sha256=configuration_sha256(payload),
    )


__all__ = [
    "AGENT_DEFINITIONS",
    "AGENT_ROLES",
    "AgentAssignment",
    "AgentDefinition",
    "AgentRole",
    "agent_definition",
    "configuration_sha256",
    "default_assignment",
    "validate_agent_configuration",
]
