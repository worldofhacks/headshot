"""Four-role hosted composition with an independent Judge and draft-only Documentation.

This module has no target client. Its sole target seam is explicitly named
``policy_gateway_dispatch`` so a hosted Red Team can never obtain a second network exit.
Activation remains a deployment concern: constructing this object is not campaign authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from typing import Any, Literal, Protocol

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    resolve_hosted_prompt,
    validate_hosted_configuration_set,
)
from agentforge.agents.judge import CalibrationGateClosed, JudgeIdentity
from agentforge.agents.judge.enablement import require_model_judge_enablement
from agentforge.agents.runtime import AgentRole
from agentforge.providers.lineage import ProviderLogicalContextV1
from agentforge.providers.openrouter import OpenRouterResult
from agentforge.secrets import looks_like_provider_key
from agentforge.target.spec import HostedRunBinding

_VERDICTS = (
    "EXPLOIT_CONFIRMED",
    "EXPLOIT_LIKELY",
    "NO_EXPLOIT_OBSERVED",
    "INDETERMINATE",
    "ERROR",
)

#: The states a MODEL Judge may return.  ``EXPLOIT_CONFIRMED`` is deliberately absent: only an
#: oracle, a canary, or a human confirms an exploit (D13), so the model is not given the vocabulary
#: to claim one.  This mirrors ``agents/judge/hosted.py::_assessment_schema`` — the two model-Judge
#: surfaces must not disagree about what the model is allowed to say.
_MODEL_ASSESSMENT_VERDICTS = (
    "EXPLOIT_LIKELY",
    "NO_EXPLOIT_OBSERVED",
    "INDETERMINATE",
    "ERROR",
)
_JUDGE_CRITERIA_VERSION = "independent-judge-assessment-v2"
_JUDGE_IMPLEMENTATION_VERSION = "hosted-role-runtime-v2"
_SCHEMA_NAME = re.compile(r"\A[a-z][a-z0-9_]{0,63}\Z")
_TYPED_REASON = re.compile(r"\A[a-z][a-z0-9_-]{0,63}\Z")
_RAW_AUTH_MATERIAL = re.compile(
    r"(?i)(?:"
    r"\bsk-(?:or-|ant-|proj-)?[A-Za-z0-9_-]{12,}"
    r"|\b(?:sid|phpsessid|sessionid)\s*[=:]\s*[^\s,;]+"
    r"|\b(?:authorization|cookie)\s*:\s*[^\s,;]+"
    r")"
)


class HostedCompositionError(RuntimeError):
    """The hosted composition could not preserve its authorized lineage or output contract."""

    code = "hosted-composition-failed"


def require_safe_model_text(label: str, value: object, *, maximum: int) -> str:
    """Accept bounded printable model text only when it contains no raw auth material."""

    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or "\x00" in value
        or any(ord(character) < 32 and character not in "\n\t" for character in value)
        or looks_like_provider_key(value.strip())
        or _RAW_AUTH_MATERIAL.search(value) is not None
    ):
        raise HostedCompositionError(f"{label} is unsafe or outside its bound")
    return value


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
    execution_id: str
    parent_execution_id: str | None
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
    physical_attempts: int


class HostedExecutionLifecycle(Protocol):
    """Mandatory durable/Langfuse lifecycle seam for every hosted provider invocation."""

    def start(
        self,
        *,
        role: AgentRole,
        parent_execution_id: str | None,
        input_payload: Mapping[str, Any],
        provider: str,
        model: str,
        upstream_provider: str,
        configuration_sha256: str,
        role_configuration_sha256: str,
        generation_policy_sha256: str,
        judge_calibration_id: str | None,
    ) -> str: ...

    def finish(
        self,
        *,
        execution_id: str,
        status: Literal["succeeded", "failed"],
        output_payload: Mapping[str, Any],
        lineage: HostedExecutionLineage | None,
        error_code: str | None,
        failed_physical_attempts: int | None = None,
    ) -> None: ...

    def provider_context(
        self,
        *,
        execution_id: str,
        prompt_version: str,
        prompt_sha256: str,
    ) -> ProviderLogicalContextV1: ...


@dataclass(frozen=True, slots=True)
class HostedRoleInvocation:
    """One durable hosted result with the provider and execution identities kept together."""

    result: OpenRouterResult
    execution_id: str
    lineage: HostedExecutionLineage

    @property
    def provider_request_id(self) -> str:
        return self.lineage.provider_request_id


def _validate_hosted_authority(
    *,
    configuration: HostedConfigurationSet,
    authorization: HostedRunBinding,
    call_bounds: Mapping[AgentRole, HostedCallBounds],
) -> dict[AgentRole, HostedCallBounds]:
    try:
        validate_hosted_configuration_set(configuration)
    except (TypeError, ValueError) as exc:
        raise HostedCompositionError("hosted configuration failed integrity validation") from exc
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
    roles = {role.role: role for role in configuration.roles}
    if set(call_bounds) != set(roles):
        raise HostedCompositionError("call bounds must cover the exact four roles")
    normalized = dict(call_bounds)
    for role, bounds in normalized.items():
        if not isinstance(bounds, HostedCallBounds):
            raise HostedCompositionError("hosted call bounds are invalid")
        limits = roles[role].limits
        if (
            bounds.input_tokens > limits.max_input_tokens
            or bounds.output_tokens > limits.max_output_tokens
            or bounds.reasoning_tokens > limits.max_reasoning_tokens
        ):
            raise HostedCompositionError("hosted call bounds exceed the authorized role limits")
        if bounds.timeout_seconds > authorization.provider_timeout_seconds:
            raise HostedCompositionError("hosted call timeout exceeds campaign authorization")
    return normalized


class HostedRoleRuntime:
    """Make one authorization-bound OpenRouter call and durably close its execution lifecycle.

    Semantic role adapters validate their inputs before calling this boundary and provide an
    optional output validator. The validator runs before a successful output is persisted, so an
    invalid or unsafe model response is recorded only as a typed failed execution.
    """

    def __init__(
        self,
        *,
        configuration: HostedConfigurationSet,
        transport: _Invoker,
        authorization: HostedRunBinding,
        call_bounds: Mapping[AgentRole, HostedCallBounds],
        execution_lifecycle: HostedExecutionLifecycle,
    ) -> None:
        if (
            not callable(getattr(transport, "invoke", None))
            or not callable(getattr(execution_lifecycle, "start", None))
            or not callable(getattr(execution_lifecycle, "finish", None))
            or not callable(getattr(execution_lifecycle, "provider_context", None))
        ):
            raise HostedCompositionError("hosted runtime dependency is unavailable")
        self._configuration = configuration
        self._authorization = authorization
        self._call_bounds = _validate_hosted_authority(
            configuration=configuration,
            authorization=authorization,
            call_bounds=call_bounds,
        )
        self._roles = {role.role: role for role in configuration.roles}
        self._transport = transport
        self._execution_lifecycle = execution_lifecycle

    def invoke(
        self,
        role: AgentRole,
        *,
        input_payload: Mapping[str, Any],
        output_schema: Mapping[str, Any],
        schema_name: str,
        parent_request_id: str | None = None,
        parent_execution_id: str | None = None,
        judge_calibration_id: str | None = None,
        validate_output: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    ) -> HostedRoleInvocation:
        """Invoke one exact configured role through its shared ledger and lifecycle."""

        # Recompute the complete binding immediately before every provider call. This catches
        # object tampering and prevents construction-time validation from becoming stale authority.
        _validate_hosted_authority(
            configuration=self._configuration,
            authorization=self._authorization,
            call_bounds=self._call_bounds,
        )
        configuration = self._roles.get(role)
        if configuration is None:
            raise HostedCompositionError("hosted role is outside the authorized configuration")
        if not isinstance(input_payload, Mapping) or not isinstance(output_schema, Mapping):
            raise HostedCompositionError("hosted invocation payload or schema is invalid")
        if not isinstance(schema_name, str) or _SCHEMA_NAME.fullmatch(schema_name) is None:
            raise HostedCompositionError("hosted response schema name is invalid")
        if role != "judge" and judge_calibration_id is not None:
            raise HostedCompositionError("Judge calibration identity cannot bind another role")
        if judge_calibration_id is not None and (
            not isinstance(judge_calibration_id, str)
            or not judge_calibration_id
            or len(judge_calibration_id) > 160
        ):
            raise HostedCompositionError("Judge calibration identity is invalid")
        if validate_output is not None and not callable(validate_output):
            raise HostedCompositionError("hosted output validator is unavailable")

        try:
            prompt = resolve_hosted_prompt(role, configuration.prompt_sha256)
        except ValueError:
            raise HostedCompositionError(
                "configured prompt identity differs from the server-owned role prompt"
            ) from None
        try:
            canonical_input = json.loads(
                json.dumps(
                    dict(input_payload),
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        except (TypeError, ValueError) as exc:
            raise HostedCompositionError("hosted input is not canonical JSON") from exc

        execution_id = self._execution_lifecycle.start(
            role=role,
            parent_execution_id=parent_execution_id,
            input_payload=canonical_input,
            provider=configuration.provider,
            model=configuration.model_id,
            upstream_provider=configuration.upstream_provider,
            configuration_sha256=self._configuration.configuration_sha256,
            role_configuration_sha256=configuration.configuration_sha256,
            generation_policy_sha256=self._authorization.generation_policy_sha256,
            judge_calibration_id=(judge_calibration_id if role == "judge" else None),
        )
        if not isinstance(execution_id, str) or not execution_id:
            raise HostedCompositionError("hosted execution lifecycle returned no identity")

        result: OpenRouterResult | None = None
        try:
            bounds = self._call_bounds[role]
            provider_context = self._execution_lifecycle.provider_context(
                execution_id=execution_id,
                prompt_version=prompt.version,
                prompt_sha256=prompt.sha256,
            )
            if not isinstance(provider_context, ProviderLogicalContextV1):
                raise HostedCompositionError("hosted provider lineage context is invalid")
            result = self._transport.invoke(
                role=role,
                messages=(
                    {"role": "system", "content": prompt.content},
                    {
                        "role": "user",
                        "content": json.dumps(
                            canonical_input,
                            allow_nan=False,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                    },
                ),
                output_schema=output_schema,
                schema_name=schema_name,
                generation_policy_sha256=self._authorization.generation_policy_sha256,
                input_tokens_upper_bound=bounds.input_tokens,
                max_output_tokens=bounds.output_tokens,
                max_reasoning_tokens=bounds.reasoning_tokens,
                timeout_seconds=bounds.timeout_seconds,
                provider_context=provider_context,
            )
            self._validate_result(role=role, result=result, bounds=bounds)
            if validate_output is not None:
                validated_output = validate_output(result.output)
                if not isinstance(validated_output, Mapping):
                    raise HostedCompositionError("hosted output validator returned invalid data")
                result = replace(result, output=dict(validated_output))
        except Exception as exc:
            observed_result = getattr(exc, "observed_result", None)
            if not isinstance(observed_result, OpenRouterResult):
                observed_result = result
            observed_lineage = self._observed_failure_lineage(
                execution_id=execution_id,
                parent_execution_id=parent_execution_id,
                role=role,
                parent_request_id=parent_request_id,
                result=observed_result,
            )
            physical_attempts = getattr(exc, "physical_attempts", None)
            if (
                physical_attempts is None
                and isinstance(observed_result, OpenRouterResult)
                and type(observed_result.physical_attempts) is int
            ):
                physical_attempts = observed_result.physical_attempts
            max_attempts = 1 + min(
                configuration.limits.max_retries,
                self._configuration.global_limits.max_retries,
            )
            if type(physical_attempts) is not int or not 1 <= physical_attempts <= max_attempts:
                physical_attempts = None
            self._record_failure(
                execution_id=execution_id,
                cause=exc,
                lineage=observed_lineage,
                physical_attempts=(None if observed_lineage is not None else physical_attempts),
            )
            raise

        record = HostedExecutionLineage(
            execution_id=execution_id,
            parent_execution_id=parent_execution_id,
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
            physical_attempts=result.physical_attempts,
        )
        try:
            self._execution_lifecycle.finish(
                execution_id=execution_id,
                status="succeeded",
                output_payload=result.output,
                lineage=record,
                error_code=None,
            )
        except Exception as exc:
            failure = HostedCompositionError(
                "hosted provider result could not be durably terminally recorded"
            )
            failure.add_note(f"lifecycle failure type: {type(exc).__name__}")
            # The output is refused, but the execution must not be left open. Generating text that
            # looks like a credential is the Red Team's actual job, so an honest in-contract
            # response routinely trips the store's screening — and stranding the row on that would
            # mean the platform disables itself the first time an attack works.
            self._record_failure(
                execution_id=execution_id,
                cause=failure,
                lineage=record,
                # The observation already carries its own attempt count; passing it separately
                # alongside lineage is a combination the runner refuses outright.
                physical_attempts=None,
            )
            raise failure from exc
        return HostedRoleInvocation(
            result=result,
            execution_id=execution_id,
            lineage=record,
        )

    def _validate_result(
        self,
        *,
        role: AgentRole,
        result: OpenRouterResult,
        bounds: HostedCallBounds,
    ) -> None:
        configuration = self._roles[role]
        if not isinstance(result, OpenRouterResult):
            raise HostedCompositionError("hosted provider returned an invalid result")
        if (
            result.configuration_sha256 != self._configuration.configuration_sha256
            or result.role_configuration_sha256 != configuration.configuration_sha256
            or result.generation_policy_sha256 != self._authorization.generation_policy_sha256
        ):
            raise HostedCompositionError("provider result lineage differs from authorization")
        if (
            result.requested_model != configuration.model_id
            or result.returned_model != configuration.model_id
            or not isinstance(result.upstream_provider, str)
            or not result.upstream_provider
            or len(result.upstream_provider) > 64
            or not isinstance(result.request_id, str)
            or not result.request_id
        ):
            raise HostedCompositionError("provider result identity differs from authorization")
        if any(
            type(value) is not int or value < 0
            for value in (
                result.input_tokens,
                result.output_tokens,
                result.reasoning_tokens,
            )
        ):
            raise HostedCompositionError("provider result usage is invalid")
        # OpenRouter's measured usage is already reconciled by HostedUsageLedger against the
        # authorization-bound role and campaign totals. Per-call bounds are admission estimates,
        # not a second response contract: some endpoints legitimately report prompt or reasoning
        # usage above the requested estimate.
        try:
            measured_cost = Decimal(result.measured_cost_usd)
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise HostedCompositionError("provider result measured cost is invalid") from exc
        if not measured_cost.is_finite() or measured_cost < 0:
            raise HostedCompositionError("provider result measured cost is invalid")
        max_attempts = 1 + min(
            configuration.limits.max_retries,
            self._configuration.global_limits.max_retries,
        )
        if (
            type(result.physical_attempts) is not int
            or not 1 <= result.physical_attempts <= max_attempts
        ):
            raise HostedCompositionError("provider result physical-attempt count is invalid")

    def _observed_failure_lineage(
        self,
        *,
        execution_id: str,
        parent_execution_id: str | None,
        role: AgentRole,
        parent_request_id: str | None,
        result: OpenRouterResult | None,
    ) -> HostedExecutionLineage | None:
        """Preserve exact charged usage without trusting a rejected response's output."""

        if not isinstance(result, OpenRouterResult):
            return None
        configuration = self._roles[role]
        if (
            result.requested_model != configuration.model_id
            or result.returned_model != configuration.model_id
            or not isinstance(result.upstream_provider, str)
            or not result.upstream_provider
            or len(result.upstream_provider) > 64
            or result.configuration_sha256 != self._configuration.configuration_sha256
            or result.role_configuration_sha256 != configuration.configuration_sha256
            or result.generation_policy_sha256 != self._authorization.generation_policy_sha256
            or not isinstance(result.request_id, str)
            or not result.request_id
            or any(
                type(value) is not int or value < 0
                for value in (
                    result.input_tokens,
                    result.output_tokens,
                    result.reasoning_tokens,
                )
            )
        ):
            return None
        try:
            measured_cost = Decimal(result.measured_cost_usd)
        except (InvalidOperation, TypeError, ValueError):
            return None
        max_attempts = 1 + min(
            configuration.limits.max_retries,
            self._configuration.global_limits.max_retries,
        )
        if (
            not measured_cost.is_finite()
            or measured_cost < 0
            or type(result.physical_attempts) is not int
            or not 1 <= result.physical_attempts <= max_attempts
        ):
            return None
        return HostedExecutionLineage(
            execution_id=execution_id,
            parent_execution_id=parent_execution_id,
            role=role,
            parent_request_id=parent_request_id,
            requested_model=result.requested_model,
            returned_model=result.returned_model,
            upstream_provider=result.upstream_provider,
            provider_request_id=result.request_id,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            reasoning_tokens=result.reasoning_tokens,
            measured_cost_usd=format(measured_cost, "f"),
            configuration_sha256=result.configuration_sha256,
            role_configuration_sha256=result.role_configuration_sha256,
            generation_policy_sha256=result.generation_policy_sha256,
            physical_attempts=result.physical_attempts,
        )

    def _record_failure(
        self,
        *,
        execution_id: str,
        cause: Exception,
        lineage: HostedExecutionLineage | None,
        physical_attempts: int | None,
    ) -> None:
        error_code = getattr(cause, "code", "hosted-agent-failed")
        # The store accepts only a lowercase typed reason. An exception carrying anything else
        # would be refused on both attempts identically, so normalize before the first one
        # rather than spending the single retry on a write that cannot succeed either.
        if not isinstance(error_code, str) or _TYPED_REASON.fullmatch(error_code) is None:
            error_code = "hosted-agent-failed"
        try:
            terminal: dict[str, Any] = {
                "execution_id": execution_id,
                "status": "failed",
                "output_payload": {"status": "failed"},
                "lineage": lineage,
                "error_code": error_code,
            }
            if physical_attempts is not None:
                terminal["failed_physical_attempts"] = physical_attempts
            self._execution_lifecycle.finish(
                **terminal,
            )
        except Exception as lifecycle_exc:
            # The store can refuse the observation itself — a token count beyond the column, an
            # output that trips credential screening, a payload over the size bound. Leaving the
            # row `running` is the worst outcome available: no terminal record, no audit event,
            # and nothing can ever close it because the execution context is already gone. So
            # degrade to the smallest record the store cannot refuse and keep the execution
            # closed. What is lost is the observation, never the fact that the call ended.
            if lineage is None:
                failure = HostedCompositionError(
                    "hosted execution failure could not be terminally recorded"
                )
                failure.add_note(f"lifecycle failure type: {type(lifecycle_exc).__name__}")
                raise failure from cause
            self._record_failure(
                execution_id=execution_id,
                cause=cause,
                lineage=None,
                physical_attempts=physical_attempts,
            )


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
        execution_lifecycle: HostedExecutionLifecycle,
        judge_calibration: Mapping[str, Any] | None = None,
    ) -> None:
        if not callable(policy_gateway_dispatch) or not callable(deterministic_judge):
            raise HostedCompositionError("hosted runtime dependency is unavailable")
        role_runtime = HostedRoleRuntime(
            configuration=configuration,
            transport=transport,
            authorization=authorization,
            call_bounds=call_bounds,
            execution_lifecycle=execution_lifecycle,
        )
        judge_identity = hosted_judge_identity(configuration)
        try:
            calibration = require_model_judge_enablement(
                judge_calibration or {},
                current_identity=judge_identity,
            )
        except CalibrationGateClosed as exc:
            raise HostedCompositionError("model Judge calibration gate is closed") from exc
        self._role_runtime = role_runtime
        self._policy_gateway_dispatch = policy_gateway_dispatch
        self._deterministic_judge = deterministic_judge
        self._judge_calibration_id = calibration["calibration_id"]

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
            parent_execution_id=None,
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
        if orchestrator.result.output["case_ref"] != authorized_case.get("case_id"):
            raise HostedCompositionError("Orchestrator selected an unauthorized case")

        red_team = self._invoke(
            "red_team",
            parent_request_id=orchestrator.result.request_id,
            parent_execution_id=orchestrator.execution_id,
            input_payload={
                "authorized_case": dict(authorized_case),
                "directive": dict(orchestrator.result.output),
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
        if red_team.result.output["case_ref"] != authorized_case.get("case_id"):
            raise HostedCompositionError("Red Team changed the authorized case identity")

        evidence = self._policy_gateway_dispatch(dict(red_team.result.output))
        if not isinstance(evidence, Mapping):
            raise HostedCompositionError("Policy Gateway returned invalid target evidence")
        evidence = dict(evidence)
        deterministic_verdict = self._deterministic_judge(
            dict(red_team.result.output),
            evidence,
        )
        if not isinstance(deterministic_verdict, Mapping):
            raise HostedCompositionError("deterministic Judge returned an invalid verdict")

        judge = self._invoke(
            "judge",
            parent_request_id=red_team.result.request_id,
            parent_execution_id=red_team.execution_id,
            input_payload={
                "attack_attempt": dict(red_team.result.output),
                "target_evidence": evidence,
            },
            output_schema={
                "type": "object",
                "properties": {
                    # No EXPLOIT_CONFIRMED, and no self-reported calibration flag: the model
                    # cannot claim a confirmation, and it cannot vouch for its own calibration.
                    "state": {"enum": list(_MODEL_ASSESSMENT_VERDICTS)},
                    "explanation": {"type": "string"},
                },
                "required": ["state", "explanation"],
                "additionalProperties": False,
            },
            schema_name="independent_judge_verdict",
            lineage=lineage,
        )
        verdict = self._deterministic_precedence(
            deterministic_verdict=deterministic_verdict,
            hosted_verdict=judge.result.output,
            # Authority comes from the enablement gate __init__ already passed, never from the
            # model's own output.
            model_calibration_enabled=self._judge_calibration_id is not None,
        )

        documentation: Mapping[str, Any] | None = None
        if verdict["state"] in {"EXPLOIT_CONFIRMED", "EXPLOIT_LIKELY"}:
            documented = self._invoke(
                "documentation",
                parent_request_id=judge.result.request_id,
                parent_execution_id=judge.execution_id,
                input_payload={
                    "attack_attempt": dict(red_team.result.output),
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
                **dict(documented.result.output),
                "publication_status": "blocked_pending_human_approval",
                "draft_unpublished": True,
            }
        return HostedAttemptOutcome(
            directive=dict(orchestrator.result.output),
            attack_attempt=dict(red_team.result.output),
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
        parent_execution_id: str | None,
        input_payload: Mapping[str, Any],
        output_schema: Mapping[str, Any],
        schema_name: str,
        lineage: list[HostedExecutionLineage],
    ) -> HostedRoleInvocation:
        invocation = self._role_runtime.invoke(
            role,
            parent_request_id=parent_request_id,
            parent_execution_id=parent_execution_id,
            input_payload=input_payload,
            output_schema=output_schema,
            schema_name=schema_name,
            judge_calibration_id=(self._judge_calibration_id if role == "judge" else None),
        )
        lineage.append(invocation.lineage)
        return invocation

    @staticmethod
    def _deterministic_precedence(
        *,
        deterministic_verdict: Mapping[str, Any],
        hosted_verdict: Mapping[str, Any],
        model_calibration_enabled: bool,
    ) -> dict[str, Any]:
        """Reconcile one model assessment against deterministic ground truth, in code.

        Two authorities are deliberately never taken from the model's own output:

        * **Confirmation.** Only an oracle, a canary, or a human confirms an exploit. The model's
          output schema omits ``EXPLOIT_CONFIRMED``; should one arrive anyway (a provider that
          ignores the schema, a replayed fixture, a future caller), it is DOWNGRADED to
          ``EXPLOIT_LIKELY`` rather than passed through. A model-sourced confirmation would
          otherwise reach Documentation and produce a vulnerability draft with no evidence
          behind it.
        * **Calibration status.** Whether the model may issue a decisive ``NO_EXPLOIT_OBSERVED``
          is decided by the caller's enablement gate, not by a boolean the model emits about
          itself. A model that asserts its own calibration could otherwise clear a case.
        """

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
        if hosted_state == "EXPLOIT_CONFIRMED":
            # Keep the unsafe signal, refuse the confirmation authority.
            return {
                **dict(hosted_verdict),
                "state": "EXPLOIT_LIKELY",
                "deterministic_precedence": False,
                "reason": "model_confirmation_refused",
            }
        if hosted_state == "NO_EXPLOIT_OBSERVED" and model_calibration_enabled is not True:
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


def hosted_judge_identity(configuration: HostedConfigurationSet) -> JudgeIdentity:
    """Bind calibration to the exact hosted Judge and independent Red Team identities."""

    judge = next(role for role in configuration.roles if role.role == "judge")
    red_team = next(role for role in configuration.roles if role.role == "red_team")
    return JudgeIdentity(
        judge_provider=f"{judge.provider}:{judge.upstream_provider}",
        judge_model=judge.model_id,
        judge_model_version=judge.configuration_sha256,
        criteria_version=_JUDGE_CRITERIA_VERSION,
        implementation_version=_JUDGE_IMPLEMENTATION_VERSION,
        red_team_provider=f"{red_team.provider}:{red_team.upstream_provider}",
        red_team_model=red_team.model_id,
    )


__all__ = [
    "HostedAttemptOutcome",
    "HostedCallBounds",
    "HostedCompositionError",
    "HostedExecutionLineage",
    "HostedExecutionLifecycle",
    "HostedFourRoleRuntime",
    "HostedRoleInvocation",
    "HostedRoleRuntime",
    "hosted_judge_identity",
    "payload_sha256",
    "require_safe_model_text",
]
