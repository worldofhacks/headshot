"""One strict OpenRouter transport shared by the four hosted roles.

Every physical request consumes the shared ledger before network I/O. The transport selects one
exact model and one exact upstream provider, disables fallback, admits one logical retry at most,
and rejects responses whose model, provider, usage, cost, or structured output is not verifiable.
It never returns or records a credential value.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx
from jsonschema import Draft202012Validator

from agentforge.agents.hosted import (
    HOSTED_MAX_LOGICAL_RETRIES,
    HostedConfigurationSet,
    HostedRoleConfiguration,
    validate_hosted_configuration_set,
)
from agentforge.agents.runtime import AgentRole
from agentforge.secrets import Secret

OPENROUTER_CHAT_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"
_MILLION = Decimal(1_000_000)
_RETRYABLE_STATUS = frozenset({429, 502, 503})


class HostedProviderError(RuntimeError):
    """A typed terminal provider refusal with no credential or prompt content."""

    code = "hosted-provider-unavailable"


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
        self._tokens = {
            role: {"input": 0, "output": 0, "reasoning": 0} for role in self._roles
        }
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
                self._role_measured_usd[role]
                + self._role_unresolved_usd[role]
                + maximum_cost
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


class OpenRouterTransport:
    """Synchronous concurrency-one transport intended for the private Runner only."""

    def __init__(
        self,
        *,
        configuration: HostedConfigurationSet,
        credential_resolver: Callable[[str], Secret],
        client: httpx.Client | None = None,
        ledger: HostedUsageLedger | None = None,
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
        self._sleeper = sleeper
        self._monotonic = monotonic
        self._last_request_at: float | None = None
        self._concurrency = threading.BoundedSemaphore(
            configuration.global_limits.max_concurrency
        )

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
        attempts = 1 + min(
            HOSTED_MAX_LOGICAL_RETRIES,
            configuration.limits.max_retries,
            self._configuration.global_limits.max_retries,
        )
        last_error: Exception | None = None
        conservative_input_bound = self._conservative_input_token_bound(messages)
        with self._concurrency:
            for attempt in range(1, attempts + 1):
                self._pace(configuration)
                reservation = self._ledger.reserve(
                    role,
                    input_tokens=max(
                        input_tokens_upper_bound,
                        conservative_input_bound,
                    ),
                    output_tokens=max_output_tokens,
                    reasoning_tokens=max_reasoning_tokens,
                )
                try:
                    result = self._send(
                        configuration=configuration,
                        messages=messages,
                        output_schema=output_schema,
                        schema_name=schema_name,
                        generation_policy_sha256=generation_policy_sha256,
                        max_output_tokens=max_output_tokens,
                        timeout_seconds=timeout_seconds,
                        reservation=reservation,
                        physical_attempts=attempt,
                    )
                    return result
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    last_error = exc
                    if attempt >= attempts:
                        break
                except _RetryableResponse as exc:
                    last_error = exc
                    if attempt >= attempts:
                        break
                    if exc.retry_after_seconds > 0:
                        self._sleeper(min(exc.retry_after_seconds, 5.0))
                except HostedProviderError:
                    raise
        raise HostedProviderError("OpenRouter request failed after the authorized retry") from (
            last_error
        )

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
        messages: Sequence[Mapping[str, str]],
        output_schema: Mapping[str, Any],
        schema_name: str,
        generation_policy_sha256: str,
        max_output_tokens: int,
        timeout_seconds: float,
        reservation: _Reservation,
        physical_attempts: int,
    ) -> OpenRouterResult:
        credential = self._credential_resolver(configuration.credential_reference)
        if not isinstance(credential, Secret) or not credential:
            raise HostedProviderError("hosted credential reference is unavailable")
        response = self._client.post(
            OPENROUTER_CHAT_COMPLETIONS_URL,
            headers={
                "Authorization": f"Bearer {credential.reveal()}",
                "Content-Type": "application/json",
            },
            json={
                "model": configuration.model_id,
                "messages": [dict(message) for message in messages],
                "max_tokens": max_output_tokens,
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
                        "prompt": float(
                            configuration.prices.input_usd_per_million_tokens
                        ),
                        "completion": float(
                            configuration.prices.output_usd_per_million_tokens
                        ),
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
            raise HostedProviderError("OpenRouter returned a terminal HTTP error")
        try:
            payload = response.json()
        except (TypeError, ValueError) as exc:
            raise HostedProviderError("OpenRouter returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise HostedProviderError("OpenRouter response has an invalid shape")
        requested_model = configuration.model_id
        returned_model = payload.get("model")
        upstream_provider = payload.get("provider")
        request_id = payload.get("id")
        if returned_model != requested_model:
            raise HostedProviderError("OpenRouter returned a different model")
        if upstream_provider != configuration.upstream_provider:
            raise HostedProviderError("OpenRouter returned a different upstream provider")
        if not isinstance(request_id, str) or not request_id:
            raise HostedProviderError("OpenRouter response has no provider request id")
        usage = self._usage(payload)
        self._ledger.settle(reservation, **usage)
        output = self._structured_output(payload, output_schema)
        return OpenRouterResult(
            output=output,
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

    @staticmethod
    def _conservative_input_token_bound(
        messages: Sequence[Mapping[str, str]],
    ) -> int:
        """Bound prompt tokens by encoded bytes plus fixed chat-format overhead.

        This deliberately over-reserves. A caller-supplied estimate can widen the
        reservation, but cannot lower it and make a large prompt look cheap.
        """

        content_bytes = sum(
            len(message["role"].encode("utf-8"))
            + len(message["content"].encode("utf-8"))
            for message in messages
        )
        return content_bytes + (64 * len(messages)) + 4096

    @staticmethod
    def _usage(payload: Mapping[str, Any]) -> dict[str, Any]:
        usage = payload.get("usage")
        if not isinstance(usage, Mapping):
            raise HostedProviderError("OpenRouter response has no measured usage")
        input_tokens = usage.get("prompt_tokens")
        output_tokens = usage.get("completion_tokens")
        details = usage.get("completion_tokens_details", {})
        reasoning_tokens = details.get("reasoning_tokens", 0) if isinstance(details, Mapping) else 0
        if any(
            type(value) is not int or value < 0
            for value in (input_tokens, output_tokens, reasoning_tokens)
        ):
            raise HostedProviderError("OpenRouter token accounting is invalid")
        try:
            measured_cost = Decimal(str(usage["cost"]))
        except (InvalidOperation, KeyError, TypeError, ValueError) as exc:
            raise HostedProviderError("OpenRouter measured cost is unavailable") from exc
        return {
            "measured_cost": measured_cost,
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
    def _validate_invocation(
        *,
        messages: Sequence[Mapping[str, str]],
        output_schema: Mapping[str, Any],
        schema_name: str,
        generation_policy_sha256: str,
        timeout_seconds: float,
    ) -> None:
        if (
            not messages
            or any(
                set(message) != {"role", "content"}
                or message["role"] not in {"system", "user", "assistant"}
                or not isinstance(message["content"], str)
                or not message["content"]
                for message in messages
            )
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
            raise HostedProviderError(
                "hosted structured-output schema is invalid"
            ) from exc
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
    "HostedUsageLedger",
    "OPENROUTER_CHAT_COMPLETIONS_URL",
    "OpenRouterResult",
    "OpenRouterTransport",
]
