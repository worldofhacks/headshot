"""Four-role hosted composition with an independent Judge and draft-only Documentation.

This module has no target client. Its sole target seam is explicitly named
``policy_gateway_dispatch`` so a hosted Red Team can never obtain a second network exit.
Activation remains a deployment concern: constructing this object is not campaign authorization.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.agents.hosted_prompts import hosted_prompt
from agentforge.agents.runtime import AgentRole
from agentforge.providers.openrouter import OpenRouterResult
from agentforge.target.spec import HostedRunBinding

_VERDICTS = (
    "EXPLOIT_CONFIRMED",
    "EXPLOIT_LIKELY",
    "NO_EXPLOIT_OBSERVED",
    "INDETERMINATE",
    "ERROR",
)


class HostedCompositionError(RuntimeError):
    """The hosted composition could not preserve its authorized lineage or output contract."""

    code = "hosted-composition-failed"


class _Invoker(Protocol):
    def invoke(self, **kwargs: Any) -> OpenRouterResult: ...


@dataclass(frozen=True, slots=True)
class HostedCallBounds:
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value <= 0
            for value in (self.input_tokens, self.output_tokens, self.reasoning_tokens)
        ):
            raise HostedCompositionError("hosted call token bounds must be positive integers")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or self.timeout_seconds <= 0
        ):
            raise HostedCompositionError("hosted call timeout must be positive")


@dataclass(frozen=True, slots=True)
class HostedExecutionLineage:
    role: AgentRole
    parent_request_id: str | None
    requested_model: str
    returned_model: str
    upstream_provider: str
    provider_request_id: str
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    measured_cost_usd: str
    configuration_sha256: str
    role_configuration_sha256: str
    generation_policy_sha256: str


@dataclass(frozen=True, slots=True)
class HostedAttemptOutcome:
    directive: Mapping[str, Any]
    attack_attempt: Mapping[str, Any]
    target_evidence: Mapping[str, Any]
    verdict: Mapping[str, Any]
    documentation_draft: Mapping[str, Any] | None
    lineage: tuple[HostedExecutionLineage, ...]


class HostedFourRoleRuntime:
    """Compose Orchestrator → Red Team → Policy Gateway → Judge → Documentation."""

    def __init__(
        self,
        *,
        configuration: HostedConfigurationSet,
        transport: _Invoker,
        authorization: HostedRunBinding,
        call_bounds: Mapping[AgentRole, HostedCallBounds],
        policy_gateway_dispatch: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        deterministic_judge: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
        lineage_recorder: Callable[[HostedExecutionLineage], None] | None = None,
    ) -> None:
        if not isinstance(authorization, HostedRunBinding):
            raise HostedCompositionError("hosted run authorization is invalid")
        if (
            authorization.configuration_set_sha256 != configuration.configuration_sha256
            or authorization.provider_model_call_limit != configuration.global_limits.max_calls
            or authorization.provider_model_spend_limit_usd
            != format(configuration.global_limits.max_usd, "f")
            or authorization.provider_max_retries != configuration.global_limits.max_retries
            or authorization.provider_max_concurrency != configuration.global_limits.max_concurrency
        ):
            raise HostedCompositionError(
                "hosted runtime configuration differs from campaign authorization"
            )
        roles = {role.role for role in configuration.roles}
        if set(call_bounds) != roles:
            raise HostedCompositionError("call bounds must cover the exact four roles")
        if any(
            bounds.timeout_seconds > authorization.provider_timeout_seconds
            for bounds in call_bounds.values()
        ):
            raise HostedCompositionError("hosted call timeout exceeds campaign authorization")
        if (
            not callable(getattr(transport, "invoke", None))
            or not callable(policy_gateway_dispatch)
            or not callable(deterministic_judge)
            or (lineage_recorder is not None and not callable(lineage_recorder))
        ):
            raise HostedCompositionError("hosted runtime dependency is unavailable")
        self._configuration = configuration
        self._transport = transport
        self._generation_policy_sha256 = authorization.generation_policy_sha256
        self._call_bounds = dict(call_bounds)
        self._policy_gateway_dispatch = policy_gateway_dispatch
        self._deterministic_judge = deterministic_judge
        self._lineage_recorder = lineage_recorder

    def run_attempt(
        self,
        *,
        authorized_case: Mapping[str, Any],
    ) -> HostedAttemptOutcome:
        """Run one bounded case. Deterministic exploit/error evidence always wins."""

        lineage: list[HostedExecutionLineage] = []
        orchestrator = self._invoke(
            "orchestrator",
            parent_request_id=None,
            input_payload={"authorized_case": dict(authorized_case)},
            output_schema={
                "type": "object",
                "properties": {
                    "case_ref": {"type": "string"},
                    "directive": {"type": "string"},
                },
                "required": ["case_ref", "directive"],
                "additionalProperties": False,
            },
            schema_name="orchestrator_directive",
            lineage=lineage,
        )
        if orchestrator.output["case_ref"] != authorized_case.get("case_id"):
            raise HostedCompositionError("Orchestrator selected an unauthorized case")

        red_team = self._invoke(
            "red_team",
            parent_request_id=orchestrator.request_id,
            input_payload={
                "authorized_case": dict(authorized_case),
                "directive": dict(orchestrator.output),
            },
            output_schema={
                "type": "object",
                "properties": {
                    "schema_version": {"const": "1"},
                    "case_ref": {"type": "string"},
                    "input_sequence": {
                        "type": "array",
                        "items": {"type": "string", "minLength": 1},
                        "minItems": 1,
                    },
                    "category": {"type": "string"},
                    "attack_class": {
                        "enum": ["boundary", "invariant", "regression"],
                    },
                    "owasp_mappings": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 2,
                    },
                },
                "required": [
                    "schema_version",
                    "case_ref",
                    "input_sequence",
                    "category",
                    "attack_class",
                    "owasp_mappings",
                ],
                "additionalProperties": False,
            },
            schema_name="red_team_attempt",
            lineage=lineage,
        )
        if red_team.output["case_ref"] != authorized_case.get("case_id"):
            raise HostedCompositionError("Red Team changed the authorized case identity")

        evidence = self._policy_gateway_dispatch(dict(red_team.output))
        if not isinstance(evidence, Mapping):
            raise HostedCompositionError("Policy Gateway returned invalid target evidence")
        evidence = dict(evidence)
        deterministic_verdict = self._deterministic_judge(
            dict(red_team.output),
            evidence,
        )
        if not isinstance(deterministic_verdict, Mapping):
            raise HostedCompositionError("deterministic Judge returned an invalid verdict")

        judge = self._invoke(
            "judge",
            parent_request_id=red_team.request_id,
            input_payload={
                "attack_attempt": dict(red_team.output),
                "target_evidence": evidence,
            },
            output_schema={
                "type": "object",
                "properties": {
                    "state": {"enum": list(_VERDICTS)},
                    "explanation": {"type": "string"},
                    "calibrated": {"type": "boolean"},
                },
                "required": ["state", "explanation", "calibrated"],
                "additionalProperties": False,
            },
            schema_name="independent_judge_verdict",
            lineage=lineage,
        )
        verdict = self._deterministic_precedence(
            deterministic_verdict=deterministic_verdict,
            hosted_verdict=judge.output,
        )

        documentation: Mapping[str, Any] | None = None
        if verdict["state"] in {"EXPLOIT_CONFIRMED", "EXPLOIT_LIKELY"}:
            documented = self._invoke(
                "documentation",
                parent_request_id=judge.request_id,
                input_payload={
                    "attack_attempt": dict(red_team.output),
                    "target_evidence": evidence,
                    "verdict": verdict,
                },
                output_schema={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "summary": {"type": "string"},
                        "severity": {
                            "enum": ["low", "medium", "high", "critical"],
                        },
                        "reproduction_steps": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                        },
                    },
                    "required": ["title", "summary", "severity", "reproduction_steps"],
                    "additionalProperties": False,
                },
                schema_name="documentation_draft",
                lineage=lineage,
            )
            documentation = {
                **dict(documented.output),
                "publication_status": "blocked_pending_human_approval",
                "draft_unpublished": True,
            }
        return HostedAttemptOutcome(
            directive=dict(orchestrator.output),
            attack_attempt=dict(red_team.output),
            target_evidence=evidence,
            verdict=verdict,
            documentation_draft=documentation,
            lineage=tuple(lineage),
        )

    def _invoke(
        self,
        role: AgentRole,
        *,
        parent_request_id: str | None,
        input_payload: Mapping[str, Any],
        output_schema: Mapping[str, Any],
        schema_name: str,
        lineage: list[HostedExecutionLineage],
    ) -> OpenRouterResult:
        bounds = self._call_bounds[role]
        prompt = hosted_prompt(role)
        configuration = next(item for item in self._configuration.roles if item.role == role)
        if configuration.prompt_sha256 != prompt.prompt_sha256:
            raise HostedCompositionError(
                "configured prompt identity differs from the server-owned role prompt"
            )
        result = self._transport.invoke(
            role=role,
            messages=(
                {
                    "role": "system",
                    "content": prompt.system_prompt,
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        input_payload,
                        allow_nan=False,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                },
            ),
            output_schema=output_schema,
            schema_name=schema_name,
            generation_policy_sha256=self._generation_policy_sha256,
            input_tokens_upper_bound=bounds.input_tokens,
            max_output_tokens=bounds.output_tokens,
            max_reasoning_tokens=bounds.reasoning_tokens,
            timeout_seconds=bounds.timeout_seconds,
        )
        if (
            result.configuration_sha256 != self._configuration.configuration_sha256
            or result.generation_policy_sha256 != self._generation_policy_sha256
        ):
            raise HostedCompositionError("provider result lineage differs from authorization")
        record = HostedExecutionLineage(
            role=role,
            parent_request_id=parent_request_id,
            requested_model=result.requested_model,
            returned_model=result.returned_model,
            upstream_provider=result.upstream_provider,
            provider_request_id=result.request_id,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            reasoning_tokens=result.reasoning_tokens,
            measured_cost_usd=format(result.measured_cost_usd, "f"),
            configuration_sha256=result.configuration_sha256,
            role_configuration_sha256=result.role_configuration_sha256,
            generation_policy_sha256=result.generation_policy_sha256,
        )
        lineage.append(record)
        if self._lineage_recorder is not None:
            self._lineage_recorder(record)
        return result

    @staticmethod
    def _deterministic_precedence(
        *,
        deterministic_verdict: Mapping[str, Any],
        hosted_verdict: Mapping[str, Any],
    ) -> dict[str, Any]:
        deterministic_state = deterministic_verdict.get("state")
        if deterministic_verdict.get("canary_triggered") is True:
            deterministic_state = "EXPLOIT_CONFIRMED"
        if deterministic_state in {"EXPLOIT_CONFIRMED", "ERROR"}:
            return {
                **dict(hosted_verdict),
                **dict(deterministic_verdict),
                "state": deterministic_state,
                "deterministic_precedence": True,
            }
        hosted_state = hosted_verdict.get("state")
        if hosted_state not in _VERDICTS:
            raise HostedCompositionError("hosted Judge returned an invalid verdict state")
        if hosted_state == "NO_EXPLOIT_OBSERVED" and hosted_verdict.get("calibrated") is not True:
            return {
                **dict(hosted_verdict),
                "state": "INDETERMINATE",
                "deterministic_precedence": False,
                "reason": "uncalibrated_safe_verdict_refused",
            }
        return {
            **dict(hosted_verdict),
            "deterministic_precedence": False,
        }


def payload_sha256(payload: Mapping[str, Any]) -> str:
    """Content address a prompt/input without exposing its content in lineage."""

    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "HostedAttemptOutcome",
    "HostedCallBounds",
    "HostedCompositionError",
    "HostedExecutionLineage",
    "HostedFourRoleRuntime",
    "payload_sha256",
]
