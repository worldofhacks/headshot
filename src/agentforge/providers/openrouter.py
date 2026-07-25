"""One strict OpenRouter transport shared by the four hosted roles.

Every physical request consumes the shared ledger before network I/O. The transport selects one
exact model and one exact upstream provider, disables fallback, admits one logical retry at most,
and rejects responses whose model, provider, usage, cost, or structured output is not verifiable.
It never returns or records a credential value.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import math
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx
from jsonschema import Draft202012Validator

from agentforge.agents.hosted import (
    HOSTED_MAX_LOGICAL_RETRIES,
    HostedConfigurationSet,
    HostedRoleConfiguration,
    resolve_hosted_prompt,
    validate_hosted_configuration_set,
)
from agentforge.agents.runtime import AgentRole
from agentforge.providers.lineage import (
    ProviderAttemptObserver,
    ProviderInvocationContextV1,
    ProviderLineageRecorder,
    ProviderLogicalContextV1,
    ProviderTerminalEventV1,
    served_provider_matches_configured,
)
from agentforge.secrets import Secret

OPENROUTER_CHAT_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"
_MILLION = Decimal(1_000_000)
_COST_QUANTUM = Decimal("0.000000000001")
_MAX_COST = Decimal("99999999.999999999999")
_RETRYABLE_STATUS = frozenset({429, 502, 503})
_EVENT_ERRORS = {
    "timeout": "provider_timeout",
    "retryable_failure": "provider_retryable",
    "terminal_failure": "provider_terminal",
    "model_mismatch": "returned_model_mismatch",
    "invalid_usage": "invalid_provider_usage",
    "invalid_output": "invalid_structured_output",
    "outcome_unknown": "provider_outcome_unknown",
}


class HostedProviderError(RuntimeError):
    """A typed terminal provider refusal with no credential or prompt content."""

    code = "hosted-provider-unavailable"

    def __init__(self, message: str, *, physical_attempts: int = 0) -> None:
        super().__init__(message)
        if type(physical_attempts) is not int or physical_attempts < 0:
            raise ValueError("physical attempt count must be a non-negative integer")
        self.physical_attempts = physical_attempts

    def account_physical_attempts(self, physical_attempts: int) -> None:
        """Attach a conservative consumed-call count without changing the safe error text."""

        if type(physical_attempts) is not int or physical_attempts < self.physical_attempts:
            raise ValueError("physical attempt count cannot move backwards")
        self.physical_attempts = physical_attempts


class HostedBudgetExceeded(HostedProviderError):
    """A physical-call, token, or measured-spend gate refused before another call."""

    code = "hosted-budget-exceeded"


@dataclass(frozen=True, slots=True)
class HostedLedgerSnapshot:
    physical_calls: int
    measured_usd: Decimal
    unresolved_exposure_usd: Decimal


@dataclass(frozen=True, slots=True)
class _Reservation:
    role: AgentRole
    maximum_cost: Decimal
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int


class HostedUsageLedger:
    """Thread-safe shared authority for all four roles in one campaign."""

    def __init__(self, configuration: HostedConfigurationSet) -> None:
        validate_hosted_configuration_set(configuration)
        self._configuration = configuration
        self._roles = {role.role: role for role in configuration.roles}
        self._physical_calls = 0
        self._measured_usd = Decimal(0)
        self._unresolved_usd = Decimal(0)
        self._role_calls = {role: 0 for role in self._roles}
        self._role_measured_usd = {role: Decimal(0) for role in self._roles}
        self._role_unresolved_usd = {role: Decimal(0) for role in self._roles}
        self._tokens = {role: {"input": 0, "output": 0, "reasoning": 0} for role in self._roles}
        self._global_tokens = {"input": 0, "output": 0, "reasoning": 0}
        self._lock = threading.Lock()

    @property
    def snapshot(self) -> HostedLedgerSnapshot:
        with self._lock:
            return HostedLedgerSnapshot(
                physical_calls=self._physical_calls,
                measured_usd=self._measured_usd,
                unresolved_exposure_usd=self._unresolved_usd,
            )

    def restore(
        self,
        role: AgentRole,
        *,
        physical_calls: int,
        measured_usd: Decimal,
        input_tokens: int,
        output_tokens: int,
        reasoning_tokens: int,
    ) -> None:
        """Hydrate terminal durable usage before any new provider reservation."""

        configuration = self._roles.get(role)
        if configuration is None:
            raise HostedProviderError("hosted role is not configured")
        if (
            type(physical_calls) is not int
            or physical_calls < 0
            or not isinstance(measured_usd, Decimal)
            or not measured_usd.is_finite()
            or measured_usd < 0
            or any(
                type(value) is not int or value < 0
                for value in (input_tokens, output_tokens, reasoning_tokens)
            )
        ):
            raise HostedProviderError("persisted hosted usage is invalid")
        with self._lock:
            if (
                self._role_calls[role] != 0
                or self._role_measured_usd[role] != 0
                or any(self._tokens[role].values())
            ):
                raise HostedProviderError("persisted hosted usage was restored more than once")
            proposed_global_calls = self._physical_calls + physical_calls
            proposed_global_usd = self._measured_usd + measured_usd
            proposed_global_tokens = {
                "input": self._global_tokens["input"] + input_tokens,
                "output": self._global_tokens["output"] + output_tokens,
                "reasoning": self._global_tokens["reasoning"] + reasoning_tokens,
            }
            role_limits = configuration.limits
            global_limits = self._configuration.global_limits
            if (
                physical_calls > role_limits.max_calls
                or measured_usd > role_limits.max_usd
                or input_tokens > role_limits.max_input_tokens
                or output_tokens > role_limits.max_output_tokens
                or reasoning_tokens > role_limits.max_reasoning_tokens
                or proposed_global_calls > global_limits.max_calls
                or proposed_global_usd > global_limits.max_usd
                or proposed_global_tokens["input"] > global_limits.max_input_tokens
                or proposed_global_tokens["output"] > global_limits.max_output_tokens
                or proposed_global_tokens["reasoning"] > global_limits.max_reasoning_tokens
            ):
                raise HostedBudgetExceeded("persisted hosted usage exceeds its authorized cap")
            self._role_calls[role] = physical_calls
            self._role_measured_usd[role] = measured_usd
            self._tokens[role] = {
                "input": input_tokens,
                "output": output_tokens,
                "reasoning": reasoning_tokens,
            }
            self._physical_calls = proposed_global_calls
            self._measured_usd = proposed_global_usd
            self._global_tokens = proposed_global_tokens

    def reserve(
        self,
        role: AgentRole,
        *,
        input_tokens: int,
        output_tokens: int,
        reasoning_tokens: int,
    ) -> _Reservation:
        for label, value in (
            ("input", input_tokens),
            ("output", output_tokens),
            ("reasoning", reasoning_tokens),
        ):
            if type(value) is not int or value < 0:
                raise HostedProviderError(f"{label} token bound is invalid")
        configuration = self._roles.get(role)
        if configuration is None:
            raise HostedProviderError("hosted role is not configured")
        prices = configuration.prices
        reasoning_price = max(
            prices.output_usd_per_million_tokens,
            prices.reasoning_usd_per_million_tokens,
        )
        maximum_cost = (
            prices.input_usd_per_million_tokens * input_tokens
            + prices.output_usd_per_million_tokens * output_tokens
            + reasoning_price * reasoning_tokens
        ) / _MILLION
        with self._lock:
            global_limits = self._configuration.global_limits
            role_limits = configuration.limits
            if self._physical_calls + 1 > global_limits.max_calls:
                raise HostedBudgetExceeded("shared physical model-call cap is exhausted")
            if self._role_calls[role] + 1 > role_limits.max_calls:
                raise HostedBudgetExceeded("role physical model-call cap is exhausted")
            projected_global = self._measured_usd + self._unresolved_usd + maximum_cost
            projected_role = (
                self._role_measured_usd[role] + self._role_unresolved_usd[role] + maximum_cost
            )
            if projected_global > global_limits.max_usd:
                raise HostedBudgetExceeded("shared measured-spend exposure cap would be exceeded")
            if projected_role > role_limits.max_usd:
                raise HostedBudgetExceeded("role measured-spend exposure cap would be exceeded")
            proposed_tokens = {
                "input": self._tokens[role]["input"] + input_tokens,
                "output": self._tokens[role]["output"] + output_tokens,
                "reasoning": self._tokens[role]["reasoning"] + reasoning_tokens,
            }
            proposed_global_tokens = {
                "input": self._global_tokens["input"] + input_tokens,
                "output": self._global_tokens["output"] + output_tokens,
                "reasoning": self._global_tokens["reasoning"] + reasoning_tokens,
            }
            if (
                proposed_tokens["input"] > role_limits.max_input_tokens
                or proposed_tokens["output"] > role_limits.max_output_tokens
                or proposed_tokens["reasoning"] > role_limits.max_reasoning_tokens
            ):
                raise HostedBudgetExceeded("role token cap would be exceeded")
            if (
                proposed_global_tokens["input"] > global_limits.max_input_tokens
                or proposed_global_tokens["output"] > global_limits.max_output_tokens
                or proposed_global_tokens["reasoning"] > global_limits.max_reasoning_tokens
            ):
                raise HostedBudgetExceeded("shared token cap would be exceeded")
            self._physical_calls += 1
            self._role_calls[role] += 1
            self._unresolved_usd += maximum_cost
            self._role_unresolved_usd[role] += maximum_cost
            self._tokens[role] = proposed_tokens
            self._global_tokens = proposed_global_tokens
        return _Reservation(
            role=role,
            maximum_cost=maximum_cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            reasoning_tokens=reasoning_tokens,
        )

    def settle(
        self,
        reservation: _Reservation,
        *,
        measured_cost: Decimal,
        input_tokens: int,
        output_tokens: int,
        reasoning_tokens: int,
    ) -> None:
        if (
            not measured_cost.is_finite()
            or measured_cost < 0
            or any(
                type(value) is not int or value < 0
                for value in (input_tokens, output_tokens, reasoning_tokens)
            )
        ):
            raise HostedProviderError("provider usage accounting is invalid")
        if (
            input_tokens > reservation.input_tokens
            or output_tokens > reservation.output_tokens
            or reasoning_tokens > reservation.reasoning_tokens
        ):
            raise HostedBudgetExceeded("provider usage exceeded its preflight token reservation")
        with self._lock:
            role = reservation.role
            self._unresolved_usd -= reservation.maximum_cost
            self._role_unresolved_usd[role] -= reservation.maximum_cost
            self._measured_usd += measured_cost
            self._role_measured_usd[role] += measured_cost
            self._tokens[role]["input"] += input_tokens - reservation.input_tokens
            self._tokens[role]["output"] += output_tokens - reservation.output_tokens
            self._tokens[role]["reasoning"] += reasoning_tokens - reservation.reasoning_tokens
            self._global_tokens["input"] += input_tokens - reservation.input_tokens
            self._global_tokens["output"] += output_tokens - reservation.output_tokens
            self._global_tokens["reasoning"] += reasoning_tokens - reservation.reasoning_tokens
            if (
                self._measured_usd + self._unresolved_usd
                > self._configuration.global_limits.max_usd
                or self._role_measured_usd[role] + self._role_unresolved_usd[role]
                > self._roles[role].limits.max_usd
            ):
                raise HostedBudgetExceeded("provider measured cost exceeded its authorized cap")


@dataclass(frozen=True, slots=True)
class OpenRouterResult:
    output: Mapping[str, Any]
    requested_model: str
    returned_model: str
    upstream_provider: str
    request_id: str
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    measured_cost_usd: Decimal
    configuration_sha256: str
    role_configuration_sha256: str
    generation_policy_sha256: str
    physical_attempts: int


class HostedProviderResponseError(HostedProviderError):
    """A charged provider response whose exact measurements survived terminal rejection."""

    def __init__(
        self,
        message: str,
        *,
        observed_result: OpenRouterResult,
        code: str,
        provider_event_status: str = "invalid_output",
    ) -> None:
        super().__init__(
            message,
            physical_attempts=observed_result.physical_attempts,
        )
        if not isinstance(observed_result, OpenRouterResult):
            raise TypeError("observed provider result is invalid")
        if not isinstance(code, str) or not code:
            raise ValueError("observed provider failure code is invalid")
        if provider_event_status not in {"invalid_usage", "invalid_output"}:
            raise ValueError("observed provider event status is invalid")
        self.observed_result = observed_result
        self.code = code
        self.provider_event_status = provider_event_status


class _PhysicalCallError(HostedProviderError):
    """A safe failure plus any content-free facts observed from one physical response."""

    def __init__(
        self,
        message: str,
        *,
        provider_event_status: str,
        returned_model: str | None = None,
        upstream_provider: str | None = None,
        provider_request_id: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        reasoning_tokens: int | None = None,
        cost_measurement_state: str = "not_observed",
        measured_cost_usd: Decimal | None = None,
    ) -> None:
        super().__init__(message)
        if provider_event_status not in _EVENT_ERRORS:
            raise ValueError("physical provider event status is invalid")
        self.provider_event_status = provider_event_status
        self.returned_model = returned_model
        self.upstream_provider = upstream_provider
        self.provider_request_id = provider_request_id
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.reasoning_tokens = reasoning_tokens
        self.cost_measurement_state = cost_measurement_state
        self.measured_cost_usd = measured_cost_usd


class OpenRouterTransport:
    """Synchronous concurrency-one transport intended for the private Runner only."""

    def __init__(
        self,
        *,
        configuration: HostedConfigurationSet,
        credential_resolver: Callable[[str], Secret],
        client: httpx.Client | None = None,
        ledger: HostedUsageLedger | None = None,
        lineage_recorder: ProviderLineageRecorder | None = None,
        attempt_observer: ProviderAttemptObserver | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        validate_hosted_configuration_set(configuration)
        self._configuration = configuration
        self._roles = {role.role: role for role in configuration.roles}
        self._credential_resolver = credential_resolver
        self._client = client or httpx.Client()
        self._owns_client = client is None
        self._ledger = ledger or HostedUsageLedger(configuration)
        if lineage_recorder is not None and (
            not callable(getattr(lineage_recorder, "begin_physical_attempt", None))
            or not callable(getattr(lineage_recorder, "finish_physical_attempt", None))
        ):
            raise TypeError("provider lineage recorder is invalid")
        self._lineage_recorder = lineage_recorder
        if attempt_observer is not None and (
            not callable(getattr(attempt_observer, "begin_provider_attempt", None))
            or not callable(getattr(attempt_observer, "finish_provider_attempt", None))
        ):
            raise TypeError("provider attempt observer is invalid")
        if attempt_observer is not None and lineage_recorder is None:
            raise TypeError("provider attempt observer requires durable lineage")
        self._attempt_observer = attempt_observer
        self._observed_invocation_ids: set[str] = set()
        self._sleeper = sleeper
        self._monotonic = monotonic
        self._last_request_at: float | None = None
        self._concurrency = threading.BoundedSemaphore(configuration.global_limits.max_concurrency)

    @property
    def ledger(self) -> HostedUsageLedger:
        return self._ledger

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def invoke(
        self,
        *,
        role: AgentRole,
        messages: Sequence[Mapping[str, str]],
        output_schema: Mapping[str, Any],
        schema_name: str,
        generation_policy_sha256: str,
        input_tokens_upper_bound: int,
        max_output_tokens: int,
        max_reasoning_tokens: int,
        timeout_seconds: float,
        provider_context: ProviderLogicalContextV1 | None = None,
    ) -> OpenRouterResult:
        configuration = self._roles.get(role)
        if configuration is None:
            raise HostedProviderError("hosted role is not configured")
        self._validate_invocation(
            messages=messages,
            output_schema=output_schema,
            schema_name=schema_name,
            generation_policy_sha256=generation_policy_sha256,
            timeout_seconds=timeout_seconds,
        )
        self._validate_prompt_authority(
            configuration=configuration,
            messages=messages,
        )
        if self._lineage_recorder is not None and not isinstance(
            provider_context,
            ProviderLogicalContextV1,
        ):
            raise HostedProviderError("provider lineage context is unavailable")
        if provider_context is not None and (
            provider_context.agent_role != role
            or provider_context.requested_model != configuration.model_id
            or provider_context.configured_upstream != configuration.upstream_provider
            or provider_context.configuration_set_sha256 != self._configuration.configuration_sha256
            or provider_context.role_configuration_sha256 != configuration.configuration_sha256
            or provider_context.generation_policy_sha256 != generation_policy_sha256
            or provider_context.prompt_sha256 != configuration.prompt_sha256
            or provider_context.prompt_version
            != resolve_hosted_prompt(role, configuration.prompt_sha256).version
        ):
            raise HostedProviderError("provider lineage context differs from authorization")
        attempts = 1 + min(
            HOSTED_MAX_LOGICAL_RETRIES,
            configuration.limits.max_retries,
            self._configuration.global_limits.max_retries,
        )
        last_error: Exception | None = None
        physical_attempts = 0
        conservative_input_bound = self._conservative_input_token_bound(messages)
        if conservative_input_bound > input_tokens_upper_bound:
            raise HostedProviderError(
                "encoded hosted messages exceed the authorization-bound input token ceiling"
            )
        with self._concurrency:
            for attempt in range(1, attempts + 1):
                try:
                    self._pace(configuration)
                except HostedProviderError as exc:
                    exc.account_physical_attempts(physical_attempts)
                    raise
                except Exception as exc:
                    raise HostedProviderError(
                        "provider pacing failed before another physical send",
                        physical_attempts=physical_attempts,
                    ) from exc
                invocation: ProviderInvocationContextV1 | None = None
                try:
                    credential = self._credential_resolver(configuration.credential_reference)
                    if not isinstance(credential, Secret) or not credential:
                        raise HostedProviderError("hosted credential reference is unavailable")
                except HostedProviderError as exc:
                    exc.account_physical_attempts(physical_attempts)
                    raise
                except Exception as exc:
                    raise HostedProviderError(
                        "hosted credential reference is unavailable",
                        physical_attempts=physical_attempts,
                    ) from exc
                try:
                    reservation = self._ledger.reserve(
                        role,
                        input_tokens=input_tokens_upper_bound,
                        output_tokens=max_output_tokens,
                        reasoning_tokens=max_reasoning_tokens,
                    )
                except HostedProviderError as exc:
                    exc.account_physical_attempts(physical_attempts)
                    raise
                try:
                    invocation = self._begin_physical_attempt(
                        provider_context,
                        sequence=attempt,
                    )
                    physical_attempts = attempt
                    self._begin_attempt_observation(invocation)
                    result = self._send(
                        configuration=configuration,
                        credential=credential,
                        messages=messages,
                        output_schema=output_schema,
                        schema_name=schema_name,
                        generation_policy_sha256=generation_policy_sha256,
                        max_output_tokens=max_output_tokens,
                        timeout_seconds=timeout_seconds,
                        reservation=reservation,
                        physical_attempts=attempt,
                    )
                except httpx.TimeoutException as exc:
                    self._record_unobserved_failure(
                        invocation,
                        status="timeout",
                    )
                    last_error = exc
                    if attempt >= attempts:
                        break
                except httpx.TransportError as exc:
                    self._record_unobserved_failure(
                        invocation,
                        status="retryable_failure",
                    )
                    last_error = exc
                    if attempt >= attempts:
                        break
                except _RetryableResponse as exc:
                    self._record_unobserved_failure(
                        invocation,
                        status="retryable_failure",
                    )
                    last_error = exc
                    if attempt >= attempts:
                        break
                    if exc.retry_after_seconds > 0:
                        try:
                            self._sleeper(min(exc.retry_after_seconds, 5.0))
                        except Exception as sleep_error:
                            raise HostedProviderError(
                                "provider retry pacing failed",
                                physical_attempts=physical_attempts,
                            ) from sleep_error
                except HostedProviderResponseError as exc:
                    self._record_observed_failure(invocation, exc)
                    exc.account_physical_attempts(physical_attempts)
                    raise
                except _PhysicalCallError as exc:
                    self._record_physical_failure(invocation, exc)
                    exc.account_physical_attempts(physical_attempts)
                    raise
                except HostedProviderError as exc:
                    if invocation is not None:
                        self._record_unobserved_failure(
                            invocation,
                            status="terminal_failure",
                        )
                    exc.account_physical_attempts(physical_attempts)
                    raise
                except Exception as exc:
                    if invocation is not None:
                        self._record_unobserved_failure(
                            invocation,
                            status="outcome_unknown",
                        )
                    raise HostedProviderError(
                        "provider call outcome could not be determined",
                        physical_attempts=physical_attempts,
                    ) from exc
                else:
                    self._record_success(invocation, result)
                    return result
        raise HostedProviderError(
            "OpenRouter request failed after the authorized retry",
            physical_attempts=physical_attempts,
        ) from last_error

    def _begin_physical_attempt(
        self,
        context: ProviderLogicalContextV1 | None,
        *,
        sequence: int,
    ) -> ProviderInvocationContextV1 | None:
        if self._lineage_recorder is None:
            return None
        if not isinstance(context, ProviderLogicalContextV1):
            raise HostedProviderError("provider lineage context is unavailable")
        try:
            invocation = self._lineage_recorder.begin_physical_attempt(
                context,
                sequence,
            )
        except Exception as exc:
            raise HostedProviderError(
                "physical provider invocation could not be durably reserved"
            ) from exc
        if (
            not isinstance(invocation, ProviderInvocationContextV1)
            or invocation.logical_execution_id != context.logical_execution_id
            or invocation.physical_sequence != sequence
        ):
            raise HostedProviderError("physical provider invocation returned invalid identity")
        return invocation

    def _begin_attempt_observation(
        self,
        invocation: ProviderInvocationContextV1 | None,
    ) -> None:
        if self._attempt_observer is None:
            return
        if invocation is None:
            raise HostedProviderError("physical provider observation has no durable identity")
        try:
            self._attempt_observer.begin_provider_attempt(invocation)
        except Exception as exc:
            raise HostedProviderError(
                "physical provider observation could not start",
                physical_attempts=invocation.physical_sequence,
            ) from exc
        self._observed_invocation_ids.add(invocation.invocation_id)

    def _record_success(
        self,
        invocation: ProviderInvocationContextV1 | None,
        result: OpenRouterResult,
    ) -> None:
        self._record_terminal_event(
            invocation,
            status="succeeded",
            returned_model=result.returned_model,
            upstream_provider=result.upstream_provider,
            provider_request_id=result.request_id,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            reasoning_tokens=result.reasoning_tokens,
            cost_measurement_state="measured",
            measured_cost_usd=result.measured_cost_usd,
        )

    def _record_observed_failure(
        self,
        invocation: ProviderInvocationContextV1 | None,
        error: HostedProviderResponseError,
    ) -> None:
        result = error.observed_result
        self._record_terminal_event(
            invocation,
            status=error.provider_event_status,
            returned_model=result.returned_model,
            upstream_provider=result.upstream_provider,
            provider_request_id=result.request_id,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            reasoning_tokens=result.reasoning_tokens,
            cost_measurement_state="measured",
            measured_cost_usd=result.measured_cost_usd,
        )

    def _record_physical_failure(
        self,
        invocation: ProviderInvocationContextV1 | None,
        error: _PhysicalCallError,
    ) -> None:
        self._record_terminal_event(
            invocation,
            status=error.provider_event_status,
            returned_model=error.returned_model,
            upstream_provider=error.upstream_provider,
            provider_request_id=error.provider_request_id,
            input_tokens=error.input_tokens,
            output_tokens=error.output_tokens,
            reasoning_tokens=error.reasoning_tokens,
            cost_measurement_state=error.cost_measurement_state,
            measured_cost_usd=error.measured_cost_usd,
        )

    def _record_unobserved_failure(
        self,
        invocation: ProviderInvocationContextV1 | None,
        *,
        status: str,
    ) -> None:
        self._record_terminal_event(
            invocation,
            status=status,
            returned_model=None,
            upstream_provider=None,
            provider_request_id=None,
            input_tokens=None,
            output_tokens=None,
            reasoning_tokens=None,
            cost_measurement_state="not_observed",
            measured_cost_usd=None,
        )

    def _record_terminal_event(
        self,
        invocation: ProviderInvocationContextV1 | None,
        *,
        status: str,
        returned_model: str | None,
        upstream_provider: str | None,
        provider_request_id: str | None,
        input_tokens: int | None,
        output_tokens: int | None,
        reasoning_tokens: int | None,
        cost_measurement_state: str,
        measured_cost_usd: Decimal | None,
    ) -> None:
        if invocation is None:
            return
        if self._lineage_recorder is None:
            raise HostedProviderError("provider lineage recorder is unavailable")
        try:
            event = ProviderTerminalEventV1(
                invocation_id=invocation.invocation_id,
                physical_sequence=invocation.physical_sequence,
                status=status,
                returned_model=returned_model,
                upstream_provider=upstream_provider,
                provider_request_id=provider_request_id,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                reasoning_tokens=reasoning_tokens,
                cost_measurement_state=cost_measurement_state,
                measured_cost_usd=measured_cost_usd,
                error_code=_EVENT_ERRORS.get(status),
                finished_at=datetime.datetime.now(datetime.UTC),
            )
            recorded = self._lineage_recorder.finish_physical_attempt(
                invocation,
                event,
            )
        except Exception as exc:
            raise HostedProviderError(
                "physical provider terminal facts could not be durably recorded",
                physical_attempts=invocation.physical_sequence,
            ) from exc
        if recorded != event:
            raise HostedProviderError(
                "physical provider terminal recorder changed observed facts",
                physical_attempts=invocation.physical_sequence,
            )
        if (
            self._attempt_observer is not None
            and invocation.invocation_id in self._observed_invocation_ids
        ):
            self._observed_invocation_ids.discard(invocation.invocation_id)
            try:
                self._attempt_observer.finish_provider_attempt(invocation, event)
            except Exception as exc:
                # The provider send and durable terminal append already happened. Propagate out of
                # the current attempt so the logical role fails, but never enter the retry loop.
                raise HostedProviderError(
                    "physical provider observation could not complete",
                    physical_attempts=invocation.physical_sequence,
                ) from exc

    def _pace(self, configuration: HostedRoleConfiguration) -> None:
        rate = min(
            configuration.limits.max_requests_per_second,
            self._configuration.global_limits.max_requests_per_second,
        )
        now = self._monotonic()
        if not math.isfinite(now):
            raise HostedProviderError("provider rate-limit clock is invalid")
        if self._last_request_at is not None:
            remaining = (1.0 / float(rate)) - (now - self._last_request_at)
            if remaining > 0:
                self._sleeper(remaining)
                now = self._monotonic()
                if not math.isfinite(now):
                    raise HostedProviderError("provider rate-limit clock is invalid")
        self._last_request_at = now

    def _send(
        self,
        *,
        configuration: HostedRoleConfiguration,
        credential: Secret,
        messages: Sequence[Mapping[str, str]],
        output_schema: Mapping[str, Any],
        schema_name: str,
        generation_policy_sha256: str,
        max_output_tokens: int,
        timeout_seconds: float,
        reservation: _Reservation,
        physical_attempts: int,
    ) -> OpenRouterResult:
        response = self._client.post(
            OPENROUTER_CHAT_COMPLETIONS_URL,
            headers={
                "Authorization": f"Bearer {credential.reveal()}",
                "Content-Type": "application/json",
                "X-OpenRouter-Metadata": "enabled",
            },
            json={
                "model": configuration.model_id,
                "messages": [dict(message) for message in messages],
                # OpenRouter's completion count includes reasoning tokens. The
                # configured output bound is only the final-answer allowance. The
                # endpoint-catalog-verified parameter name is part of the immutable
                # role configuration and must not fall back to its sibling spelling.
                configuration.completion_token_parameter: (
                    max_output_tokens + reservation.reasoning_tokens
                ),
                "stream": False,
                "provider": {
                    "only": [configuration.upstream_provider],
                    "allow_fallbacks": False,
                    "require_parameters": True,
                    "data_collection": "deny",
                    # OpenRouter interprets prompt/completion values as USD per
                    # million tokens and refuses the request if no endpoint satisfies
                    # them. Per-request pricing is disallowed.
                    "max_price": {
                        "prompt": float(configuration.prices.input_usd_per_million_tokens),
                        "completion": float(configuration.prices.output_usd_per_million_tokens),
                        "request": 0,
                    },
                },
                "reasoning": {"max_tokens": reservation.reasoning_tokens},
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": schema_name,
                        "strict": True,
                        "schema": dict(output_schema),
                    },
                },
            },
            timeout=timeout_seconds,
        )
        if response.status_code in _RETRYABLE_STATUS:
            raise _RetryableResponse(self._retry_after(response))
        if response.status_code < 200 or response.status_code >= 300:
            raise _PhysicalCallError(
                "OpenRouter returned a terminal HTTP error",
                provider_event_status="terminal_failure",
            )
        try:
            payload = response.json()
        except (TypeError, ValueError) as exc:
            raise _PhysicalCallError(
                "OpenRouter returned invalid JSON",
                provider_event_status="invalid_output",
            ) from exc
        if not isinstance(payload, dict):
            raise _PhysicalCallError(
                "OpenRouter response has an invalid shape",
                provider_event_status="invalid_output",
            )
        requested_model = configuration.model_id
        raw_returned_model = payload.get("model")
        returned_model = raw_returned_model if isinstance(raw_returned_model, str) else None
        raw_request_id = payload.get("id")
        request_id = raw_request_id if isinstance(raw_request_id, str) else None
        try:
            usage = self._usage(payload)
        except HostedProviderError as exc:
            raw_usage = payload.get("usage")
            cost_was_present = isinstance(raw_usage, Mapping) and "cost" in raw_usage
            raise _PhysicalCallError(
                str(exc),
                provider_event_status="invalid_usage",
                returned_model=returned_model,
                provider_request_id=request_id,
                cost_measurement_state=("invalid" if cost_was_present else "not_observed"),
            ) from exc
        try:
            upstream_provider, selected_model = self._selected_endpoint(
                payload,
                requested_model=requested_model,
            )
        except HostedProviderError as exc:
            raise _PhysicalCallError(
                str(exc),
                provider_event_status="invalid_output",
                returned_model=returned_model,
                provider_request_id=request_id,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                cost_measurement_state="measured",
                measured_cost_usd=usage["measured_cost"],
            ) from exc
        if not served_provider_matches_configured(
            configuration.upstream_provider,
            upstream_provider,
        ):
            raise _PhysicalCallError(
                "OpenRouter selected an unauthorized provider route",
                provider_event_status="invalid_output",
                returned_model=returned_model,
                upstream_provider=upstream_provider,
                provider_request_id=request_id,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                cost_measurement_state="measured",
                measured_cost_usd=usage["measured_cost"],
            )
        if returned_model != requested_model:
            raise _PhysicalCallError(
                "OpenRouter returned a different model",
                provider_event_status="model_mismatch",
                returned_model=returned_model,
                upstream_provider=upstream_provider,
                provider_request_id=request_id,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                cost_measurement_state="measured",
                measured_cost_usd=usage["measured_cost"],
            )
        if selected_model != returned_model:
            raise _PhysicalCallError(
                "OpenRouter selected a different endpoint model",
                provider_event_status="model_mismatch",
                returned_model=returned_model,
                upstream_provider=upstream_provider,
                provider_request_id=request_id,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                cost_measurement_state="measured",
                measured_cost_usd=usage["measured_cost"],
            )
        if request_id is None or not request_id:
            raise _PhysicalCallError(
                "OpenRouter response has no provider request id",
                provider_event_status="invalid_output",
                returned_model=returned_model,
                upstream_provider=upstream_provider,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                cost_measurement_state="measured",
                measured_cost_usd=usage["measured_cost"],
            )
        observed_result = OpenRouterResult(
            output={},
            requested_model=requested_model,
            returned_model=returned_model,
            upstream_provider=upstream_provider,
            request_id=request_id,
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            reasoning_tokens=usage["reasoning_tokens"],
            measured_cost_usd=usage["measured_cost"],
            configuration_sha256=self._configuration.configuration_sha256,
            role_configuration_sha256=configuration.configuration_sha256,
            generation_policy_sha256=generation_policy_sha256,
            physical_attempts=physical_attempts,
        )
        try:
            self._ledger.settle(reservation, **usage)
        except HostedProviderError as exc:
            raise HostedProviderResponseError(
                "OpenRouter response failed after measured usage was observed",
                observed_result=observed_result,
                code=exc.code,
                provider_event_status="invalid_usage",
            ) from exc
        try:
            output = self._structured_output(payload, output_schema)
        except HostedProviderError as exc:
            raise HostedProviderResponseError(
                "OpenRouter response failed after measured usage was observed",
                observed_result=observed_result,
                code=exc.code,
                provider_event_status="invalid_output",
            ) from exc
        return replace(observed_result, output=output)

    @staticmethod
    def _selected_endpoint(
        payload: Mapping[str, Any],
        *,
        requested_model: str,
    ) -> tuple[str, str]:
        metadata = payload.get("openrouter_metadata")
        if not isinstance(metadata, Mapping):
            raise HostedProviderError("OpenRouter response has no router metadata")
        if metadata.get("requested") != requested_model:
            raise HostedProviderError("OpenRouter router metadata has a different requested model")
        endpoints = metadata.get("endpoints")
        available = endpoints.get("available") if isinstance(endpoints, Mapping) else None
        if not isinstance(available, list):
            raise HostedProviderError("OpenRouter router metadata has an invalid endpoint list")
        selected = [
            endpoint
            for endpoint in available
            if isinstance(endpoint, Mapping) and endpoint.get("selected") is True
        ]
        if len(selected) != 1:
            raise HostedProviderError("OpenRouter router metadata has no unique selected endpoint")
        upstream_provider = selected[0].get("provider")
        selected_model = selected[0].get("model")
        if (
            not isinstance(upstream_provider, str)
            or not upstream_provider
            or not isinstance(selected_model, str)
            or not selected_model
        ):
            raise HostedProviderError("OpenRouter selected endpoint identity is invalid")
        return upstream_provider, selected_model

    @staticmethod
    def _conservative_input_token_bound(
        messages: Sequence[Mapping[str, str]],
    ) -> int:
        """Bound prompt tokens by encoded bytes plus fixed chat-format overhead.

        This deliberately overestimates.  The authorization-bound input ceiling must cover the
        result before any credential, budget, lineage, observation, or provider side effect.
        """

        content_bytes = sum(
            len(message["role"].encode("utf-8")) + len(message["content"].encode("utf-8"))
            for message in messages
        )
        return content_bytes + (64 * len(messages)) + 4096

    @staticmethod
    def _usage(payload: Mapping[str, Any]) -> dict[str, Any]:
        usage = payload.get("usage")
        if not isinstance(usage, Mapping):
            raise HostedProviderError("OpenRouter response has no measured usage")
        input_tokens = usage.get("prompt_tokens")
        completion_tokens = usage.get("completion_tokens")
        details = usage.get("completion_tokens_details", {})
        reasoning_tokens = details.get("reasoning_tokens", 0) if isinstance(details, Mapping) else 0
        if any(
            type(value) is not int or value < 0
            for value in (input_tokens, completion_tokens, reasoning_tokens)
        ):
            raise HostedProviderError("OpenRouter token accounting is invalid")
        if reasoning_tokens > completion_tokens:
            raise HostedProviderError("OpenRouter reasoning token accounting is invalid")
        # OpenRouter completion_tokens includes reasoning. Persist the disjoint
        # final-answer and reasoning counts so totals and caps never double-count.
        output_tokens = completion_tokens - reasoning_tokens
        try:
            measured_cost = Decimal(str(usage["cost"]))
        except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
            raise HostedProviderError("OpenRouter measured cost is unavailable") from exc
        if not measured_cost.is_finite() or measured_cost < 0 or measured_cost > _MAX_COST:
            raise HostedProviderError("OpenRouter measured cost is invalid")
        try:
            stored_cost = measured_cost.quantize(_COST_QUANTUM)
        except InvalidOperation as exc:
            raise HostedProviderError("OpenRouter measured cost exceeds storage precision") from exc
        if stored_cost != measured_cost:
            raise HostedProviderError("OpenRouter measured cost exceeds storage precision")
        return {
            "measured_cost": stored_cost,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "reasoning_tokens": reasoning_tokens,
        }

    @staticmethod
    def _structured_output(
        payload: Mapping[str, Any], output_schema: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        try:
            content = payload["choices"][0]["message"]["content"]  # type: ignore[index]
            decoded = json.loads(content)
            Draft202012Validator.check_schema(dict(output_schema))
            Draft202012Validator(dict(output_schema)).validate(decoded)
        except Exception as exc:
            raise HostedProviderError("OpenRouter structured output failed validation") from exc
        if not isinstance(decoded, Mapping):
            raise HostedProviderError("OpenRouter structured output must be an object")
        return dict(decoded)

    @staticmethod
    def _validate_prompt_authority(
        *,
        configuration: HostedRoleConfiguration,
        messages: Sequence[Mapping[str, str]],
    ) -> None:
        system_messages = [message for message in messages if message.get("role") == "system"]
        if (
            len(system_messages) != 1
            or messages[0].get("role") != "system"
            or hashlib.sha256(system_messages[0]["content"].encode("utf-8")).hexdigest()
            != configuration.prompt_sha256
        ):
            raise HostedProviderError(
                "hosted system prompt differs from immutable prompt authority"
            )

    @staticmethod
    def _validate_invocation(
        *,
        messages: Sequence[Mapping[str, str]],
        output_schema: Mapping[str, Any],
        schema_name: str,
        generation_policy_sha256: str,
        timeout_seconds: float,
    ) -> None:
        if not messages or any(
            set(message) != {"role", "content"}
            or message["role"] not in {"system", "user", "assistant"}
            or not isinstance(message["content"], str)
            or not message["content"]
            for message in messages
        ):
            raise HostedProviderError("hosted messages have an invalid shape")
        if (
            not isinstance(schema_name, str)
            or not schema_name
            or not isinstance(output_schema, Mapping)
        ):
            raise HostedProviderError("hosted structured-output schema is invalid")
        try:
            Draft202012Validator.check_schema(dict(output_schema))
        except Exception as exc:
            raise HostedProviderError("hosted structured-output schema is invalid") from exc
        if (
            not isinstance(generation_policy_sha256, str)
            or len(generation_policy_sha256) != 64
            or any(character not in "0123456789abcdef" for character in generation_policy_sha256)
        ):
            raise HostedProviderError("generation policy identity is invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
        ):
            raise HostedProviderError("provider timeout is invalid")

    @staticmethod
    def _retry_after(response: httpx.Response) -> float:
        try:
            value = float(response.headers.get("Retry-After", "0"))
        except ValueError:
            return 0
        return value if math.isfinite(value) and value > 0 else 0


class _RetryableResponse(Exception):
    def __init__(self, retry_after_seconds: float) -> None:
        super().__init__("retryable OpenRouter response")
        self.retry_after_seconds = retry_after_seconds


__all__ = [
    "HostedBudgetExceeded",
    "HostedLedgerSnapshot",
    "HostedProviderError",
    "HostedProviderResponseError",
    "HostedUsageLedger",
    "OPENROUTER_CHAT_COMPLETIONS_URL",
    "OpenRouterResult",
    "OpenRouterTransport",
]
