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
from dataclasses import dataclass, field, replace
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Any, NoReturn

import httpx
from jsonschema import Draft202012Validator

from agentforge.agents.hosted import (
    HOSTED_MAX_LOGICAL_RETRIES,
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    resolve_hosted_prompt,
    validate_hosted_configuration_set,
)
from agentforge.agents.runtime import AGENT_ROLES, AgentRole
from agentforge.providers.lineage import (
    ProviderInvocationContextV1,
    ProviderLineageRecorder,
    ProviderLogicalContextV1,
    ProviderTerminalEventV1,
    capture_response_evidence,
    normalize_provider_observation,
    served_provider_matches_configured,
)
from agentforge.secrets import Secret
from agentforge.target.spec import HostedRunBinding

# The same redaction the outbound telemetry exporter applies to provider payloads. Response
# evidence and Langfuse spans must not disagree about what counts as a credential, so they share
# one implementation rather than growing a second, drifting copy here.
from agentforge.telemetry.outbound import _sanitize_text

OPENROUTER_CHAT_COMPLETIONS_URL = "https://openrouter.ai/api/v1/chat/completions"
_MILLION = Decimal(1_000_000)
_COST_QUANTUM = Decimal("0.000000000001")
_MAX_COST = Decimal("99999999.999999999999")
_MAX_PROVIDER_TOKEN_COUNT = 2_147_483_647
# ``max_tokens`` is sent as output + reasoning, and OpenRouter counts reasoning inside the
# completion. Requesting a smaller reasoning value therefore shrinks the whole completion
# allowance and can truncate the answer before it is emitted. Measured 2026-07-26 against Chutes
# with the exact hash-pinned Red Team prompt and a 34-case enum:
#   reasoning 256 / 512 -> 0% valid, 100% finish_reason=length
#   reasoning 4096      -> 75% valid, 25% finish_reason=length
#   reasoning 8192      -> 100% valid, 0% finish_reason=length (6/6)
# The successful calls reported only one actual reasoning token, so request the full
# authorization-reserved envelope and settle only the provider's measured usage.
_RED_TEAM_REQUEST_REASONING_TOKENS = 8_192
_RETRYABLE_STATUS = frozenset({429, 502, 503})
# OpenRouter returns the requested public model ID in ``model`` but identifies some selected
# upstream endpoints by a dated provider-canonical ID.  Those values are not substitutions: they
# are the currently reviewed physical endpoint identities behind the exact public IDs.  Keep this
# authority closed and fail-closed so an arbitrary endpoint alias can never satisfy the
# returned-model invariant.
_AUTHORIZED_ENDPOINT_MODELS: Mapping[str, frozenset[str]] = {
    "anthropic/claude-opus-4.8": frozenset(
        {
            "anthropic/claude-opus-4.8",
            "anthropic/claude-4.8-opus-20260528",
        }
    ),
    "qwen/qwen3.5-397b-a17b": frozenset(
        {
            "qwen/qwen3.5-397b-a17b",
            "qwen/qwen3.5-397b-a17b-20260216",
        }
    ),
    "google/gemini-2.5-pro": frozenset({"google/gemini-2.5-pro"}),
    "openai/gpt-5.4": frozenset(
        {
            "openai/gpt-5.4",
            "openai/gpt-5.4-20260305",
        }
    ),
}
_EVENT_ERRORS = {
    "timeout": "provider_timeout",
    "retryable_failure": "provider_retryable",
    "terminal_failure": "provider_terminal",
    "model_mismatch": "returned_model_mismatch",
    "identity_invalid": "provider_identity_invalid",
    "route_unauthorized": "provider_route_unauthorized",
    "invalid_usage": "invalid_provider_usage",
    "invalid_output": "invalid_structured_output",
    "outcome_unknown": "provider_outcome_unknown",
}


class _DuplicateStructuredKey(ValueError):
    """A model response repeated an object key, so its content is not single-valued."""


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse a repeated object key rather than silently keeping the last value.

    ``json.loads`` keeps the LAST value for a repeated key, while a schema validator that already
    ran over the decoded document approves whatever survived that collapse. So a response can
    present one document to validation and a different one to credential screening, hashing and
    storage, and the ``output_sha256`` we retain no longer identifies what the model actually
    said. For an UNTRUSTED generator whose whole job is smuggling payloads, that gap is a channel.

    The eval-corpus loader has always rejected duplicate keys for exactly this reason
    (``evals/validation.py``); the provider wire is where the untrusted text actually arrives, so
    the same rule belongs here. Ambiguity is refused, never resolved by parser convention.
    """

    decoded: dict[str, Any] = {}
    for key, value in pairs:
        if key in decoded:
            raise _DuplicateStructuredKey("structured output repeated an object key")
        decoded[key] = value
    return decoded


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


class HostedProviderUnavailable(HostedProviderError):
    """Every authorized physical attempt failed to reach the provider, observing nothing.

    Raised at exactly one site: the exhaustion of the retry loop, whose ``last_error`` can only
    ever be an ``httpx.TimeoutException``, an ``httpx.TransportError``, or a ``_RetryableResponse``
    — the three faults recorded as UNOBSERVED. Every other failure re-raises its own type before
    reaching that point, so this class cannot be reached by a settlement, identity, route, model,
    budget, or accounting failure.

    That exclusivity is the whole point. It names the one provider fault a caller may treat as
    being about a single unit of work rather than about the run's authority, without having to
    reason about a base class that also covers configuration and accounting faults under the same
    ``code``. The code is deliberately unchanged from the base, so durable statuses, recorded
    error codes, and console rendering are untouched; only the TYPE is new, and only so callers
    can discriminate.
    """


@dataclass(frozen=True, slots=True)
class HostedLedgerSnapshot:
    physical_calls: int
    measured_usd: Decimal
    unresolved_exposure_usd: Decimal


@dataclass(frozen=True, slots=True)
class HostedUsageEnvelope:
    """A configuration-contained physical usage sub-envelope for one hosted runtime."""

    role_limits: Mapping[AgentRole, HostedLimits]
    global_limits: HostedLimits
    envelope_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.role_limits, Mapping)
            or set(self.role_limits) != set(AGENT_ROLES)
            or any(not isinstance(value, HostedLimits) for value in self.role_limits.values())
            or not isinstance(self.global_limits, HostedLimits)
        ):
            raise ValueError("hosted usage envelope must cover the exact four roles")
        immutable_roles = MappingProxyType(dict(self.role_limits))
        object.__setattr__(self, "role_limits", immutable_roles)
        payload = {
            "roles": {
                role: immutable_roles[role].canonical_payload() for role in sorted(immutable_roles)
            },
            "global_limits": self.global_limits.canonical_payload(),
        }
        object.__setattr__(
            self,
            "envelope_sha256",
            hashlib.sha256(
                json.dumps(
                    payload,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
        )

    @classmethod
    def from_configuration(
        cls,
        configuration: HostedConfigurationSet,
    ) -> HostedUsageEnvelope:
        validate_hosted_configuration_set(configuration)
        return cls(
            role_limits={role.role: role.limits for role in configuration.roles},
            global_limits=configuration.global_limits,
        )

    def require_contained_by(self, configuration: HostedConfigurationSet) -> None:
        validate_hosted_configuration_set(configuration)
        configured_roles = {role.role: role.limits for role in configuration.roles}
        for role, limits in self.role_limits.items():
            configured = configured_roles[role]
            if (
                limits.max_calls > configured.max_calls
                or limits.max_input_tokens > configured.max_input_tokens
                or limits.max_output_tokens > configured.max_output_tokens
                or limits.max_reasoning_tokens > configured.max_reasoning_tokens
                or limits.max_usd > configured.max_usd
                or limits.max_retries > configured.max_retries
                or limits.max_requests_per_second > configured.max_requests_per_second
                or limits.max_concurrency > configured.max_concurrency
            ):
                raise ValueError(f"{role} hosted usage envelope exceeds the reviewed configuration")
        configured_global = configuration.global_limits
        limits = self.global_limits
        if (
            limits.max_calls > configured_global.max_calls
            or limits.max_input_tokens > configured_global.max_input_tokens
            or limits.max_output_tokens > configured_global.max_output_tokens
            or limits.max_reasoning_tokens > configured_global.max_reasoning_tokens
            or limits.max_usd > configured_global.max_usd
            or limits.max_retries > configured_global.max_retries
            or limits.max_requests_per_second > configured_global.max_requests_per_second
            or limits.max_concurrency > configured_global.max_concurrency
        ):
            raise ValueError("global hosted usage envelope exceeds the reviewed configuration")

    def matches_authorization(
        self,
        authorization: HostedRunBinding,
    ) -> bool:
        return bool(
            isinstance(authorization, HostedRunBinding)
            and authorization.provider_model_call_limit == self.global_limits.max_calls
            and Decimal(authorization.provider_model_spend_limit_usd) == self.global_limits.max_usd
            and authorization.provider_max_retries == self.global_limits.max_retries
            and authorization.provider_max_concurrency == self.global_limits.max_concurrency
        )


@dataclass(frozen=True, slots=True)
class _Reservation:
    ledger_scope: object
    reservation_id: int
    role: AgentRole
    maximum_cost: Decimal
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int


@dataclass(frozen=True, slots=True)
class _UsageObservation:
    measured_cost: Decimal | None
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    cost_measurement_state: str
    error_message: str | None

    @property
    def complete(self) -> bool:
        return (
            self.error_message is None
            and self.measured_cost is not None
            and self.input_tokens is not None
            and self.output_tokens is not None
            and self.reasoning_tokens is not None
        )

    def settlement(self) -> dict[str, Any]:
        if not self.complete:
            raise HostedProviderError("provider usage accounting is incomplete")
        assert self.measured_cost is not None
        assert self.input_tokens is not None
        assert self.output_tokens is not None
        assert self.reasoning_tokens is not None
        return {
            "measured_cost": self.measured_cost,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
        }


class HostedUsageLedger:
    """Thread-safe shared authority for all four roles in one campaign."""

    def __init__(
        self,
        configuration: HostedConfigurationSet,
        *,
        envelope: HostedUsageEnvelope | None = None,
    ) -> None:
        validate_hosted_configuration_set(configuration)
        resolved_envelope = envelope or HostedUsageEnvelope.from_configuration(configuration)
        if not isinstance(resolved_envelope, HostedUsageEnvelope):
            raise TypeError("hosted usage envelope is invalid")
        resolved_envelope.require_contained_by(configuration)
        self._configuration = configuration
        self._roles = {role.role: role for role in configuration.roles}
        self._role_limits = resolved_envelope.role_limits
        self._global_limits = resolved_envelope.global_limits
        self._envelope_sha256 = resolved_envelope.envelope_sha256
        self._physical_calls = 0
        self._measured_usd = Decimal(0)
        self._unresolved_usd = Decimal(0)
        self._role_calls = {role: 0 for role in self._roles}
        self._role_measured_usd = {role: Decimal(0) for role in self._roles}
        self._role_unresolved_usd = {role: Decimal(0) for role in self._roles}
        self._tokens = {role: {"input": 0, "output": 0, "reasoning": 0} for role in self._roles}
        self._global_tokens = {"input": 0, "output": 0, "reasoning": 0}
        self._ledger_scope = object()
        self._next_reservation_id = 1
        self._outstanding_reservations: dict[int, _Reservation] = {}
        self._lock = threading.Lock()

    @property
    def envelope_sha256(self) -> str:
        return self._envelope_sha256

    @property
    def configuration_sha256(self) -> str:
        return self._configuration.configuration_sha256

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
        unresolved_usd: Decimal = Decimal(0),
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
            or not isinstance(unresolved_usd, Decimal)
            or not unresolved_usd.is_finite()
            or unresolved_usd < 0
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
                or self._role_unresolved_usd[role] != 0
                or any(self._tokens[role].values())
            ):
                raise HostedProviderError("persisted hosted usage was restored more than once")
            proposed_global_calls = self._physical_calls + physical_calls
            proposed_global_usd = self._measured_usd + measured_usd
            proposed_global_unresolved_usd = self._unresolved_usd + unresolved_usd
            proposed_global_tokens = {
                "input": self._global_tokens["input"] + input_tokens,
                "output": self._global_tokens["output"] + output_tokens,
                "reasoning": self._global_tokens["reasoning"] + reasoning_tokens,
            }
            role_limits = self._role_limits[role]
            global_limits = self._global_limits
            if (
                physical_calls > role_limits.max_calls
                or measured_usd + unresolved_usd > role_limits.max_usd
                or input_tokens > role_limits.max_input_tokens
                or output_tokens + reasoning_tokens
                > role_limits.max_output_tokens + role_limits.max_reasoning_tokens
                or proposed_global_calls > global_limits.max_calls
                or proposed_global_usd + proposed_global_unresolved_usd > global_limits.max_usd
                or proposed_global_tokens["input"] > global_limits.max_input_tokens
                or proposed_global_tokens["output"] + proposed_global_tokens["reasoning"]
                > global_limits.max_output_tokens + global_limits.max_reasoning_tokens
            ):
                raise HostedBudgetExceeded("persisted hosted usage exceeds its authorized cap")
            self._role_calls[role] = physical_calls
            self._role_measured_usd[role] = measured_usd
            self._role_unresolved_usd[role] = unresolved_usd
            self._tokens[role] = {
                "input": input_tokens,
                "output": output_tokens,
                "reasoning": reasoning_tokens,
            }
            self._physical_calls = proposed_global_calls
            self._measured_usd = proposed_global_usd
            self._unresolved_usd = proposed_global_unresolved_usd
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
            if type(value) is not int or value < 0 or value > _MAX_PROVIDER_TOKEN_COUNT:
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
            global_limits = self._global_limits
            role_limits = self._role_limits[role]
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
                or proposed_tokens["output"] + proposed_tokens["reasoning"]
                > role_limits.max_output_tokens + role_limits.max_reasoning_tokens
            ):
                raise HostedBudgetExceeded("role token cap would be exceeded")
            if (
                proposed_global_tokens["input"] > global_limits.max_input_tokens
                or proposed_global_tokens["output"] + proposed_global_tokens["reasoning"]
                > global_limits.max_output_tokens + global_limits.max_reasoning_tokens
            ):
                raise HostedBudgetExceeded("shared token cap would be exceeded")
            self._physical_calls += 1
            self._role_calls[role] += 1
            self._unresolved_usd += maximum_cost
            self._role_unresolved_usd[role] += maximum_cost
            self._tokens[role] = proposed_tokens
            self._global_tokens = proposed_global_tokens
            reservation = _Reservation(
                ledger_scope=self._ledger_scope,
                reservation_id=self._next_reservation_id,
                role=role,
                maximum_cost=maximum_cost,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                reasoning_tokens=reasoning_tokens,
            )
            self._next_reservation_id += 1
            self._outstanding_reservations[reservation.reservation_id] = reservation
            return reservation

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
            not isinstance(reservation, _Reservation)
            or not isinstance(measured_cost, Decimal)
            or not measured_cost.is_finite()
            or measured_cost < 0
            or any(
                type(value) is not int or value < 0 or value > _MAX_PROVIDER_TOKEN_COUNT
                for value in (input_tokens, output_tokens, reasoning_tokens)
            )
        ):
            raise HostedProviderError("provider usage accounting is invalid")
        with self._lock:
            if (
                reservation.ledger_scope is not self._ledger_scope
                or self._outstanding_reservations.get(reservation.reservation_id) is not reservation
            ):
                raise HostedProviderError(
                    "provider usage reservation is invalid or already settled"
                )
            # Consuming the exact reservation under the accounting lock gives settlement
            # single-use authority even when two terminal handlers race.
            del self._outstanding_reservations[reservation.reservation_id]
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
            measured_cost_exceeded = (
                self._measured_usd + self._unresolved_usd > self._global_limits.max_usd
                or self._role_measured_usd[role] + self._role_unresolved_usd[role]
                > self._role_limits[role].max_usd
            )
            token_cap_exceeded = (
                self._tokens[role]["input"] > self._role_limits[role].max_input_tokens
                or self._tokens[role]["output"] + self._tokens[role]["reasoning"]
                > self._role_limits[role].max_output_tokens
                + self._role_limits[role].max_reasoning_tokens
                or self._global_tokens["input"] > self._global_limits.max_input_tokens
                or self._global_tokens["output"] + self._global_tokens["reasoning"]
                > self._global_limits.max_output_tokens + self._global_limits.max_reasoning_tokens
            )
        # A reservation is an admission-control estimate for the outgoing request, not a second
        # provider-response contract. OpenRouter completion usage is split into final-answer and
        # reasoning fields by the selected endpoint, and that split can differ from the request's
        # allocation. Enforce the authorization-bound combined completion pool so redistribution
        # cannot create a false overrun while total usage stays capped. Reconciliation is completed
        # before reporting a true aggregate overrun because the provider has already charged.
        if token_cap_exceeded:
            raise HostedBudgetExceeded("provider usage exceeded its authorized token cap")
        if measured_cost_exceeded:
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
        if not isinstance(observed_result, OpenRouterResult):
            raise TypeError("observed provider result is invalid")
        super().__init__(
            message,
            physical_attempts=observed_result.physical_attempts,
        )
        if not isinstance(code, str) or not code:
            raise ValueError("observed provider failure code is invalid")
        if provider_event_status not in {
            "model_mismatch",
            "identity_invalid",
            "route_unauthorized",
            "invalid_usage",
            "invalid_output",
        }:
            raise ValueError("observed provider event status is invalid")
        self.observed_result = observed_result
        self.code = code
        self.provider_event_status = provider_event_status


class HostedStructuredOutputInvalid(HostedProviderResponseError):
    """A fully measured, correctly routed response whose JSON failed the role's schema.

    This is the ONLY provider failure that may be retried. It is deliberately a distinct type
    rather than a ``provider_event_status`` check, because settlement failures (budget and token
    caps) previously shared ``HostedProviderResponseError`` with schema failures, and a single
    handler could not tell "the model formatted its answer badly" apart from "this call breached
    an authorized cap". Retrying the latter would spend authority a human never granted.

    By the time this is raised the response has already passed identity, route, model-substitution
    and usage/cost settlement, so a retry cannot launder any of those violations. The failed
    physical attempt stays durably recorded with its measured tokens, cost, request id and
    ``invalid_output`` status; the retry is a new physical sequence under the same logical
    execution and attempt.
    """

    code = "invalid_structured_output"


class HostedStructuredOutputTruncated(HostedStructuredOutputInvalid):
    """The model produced no content at all, almost always because it hit its output ceiling.

    A subclass, deliberately: truncation is still a formatting failure about ONE call, so it must
    keep the retry admission and per-case isolation that :class:`HostedStructuredOutputInvalid`
    already earns. Every ``isinstance`` check therefore continues to work unchanged.

    It exists because the old path was actively misleading. When a provider returns
    ``content: null`` — the shape OpenRouter uses when generation stops at the token cap before
    any content is emitted — ``json.loads(None)`` raises ``TypeError``, which the broad handler in
    :meth:`_structured_output` rewrote into a generic "failed validation". Operators then saw
    ``invalid_structured_output`` and went looking for a schema or prompt bug, when the real cause
    was a run-away generation that exhausted its budget. Naming truncation separately, and
    carrying the provider's own ``finish_reason``, points at the actual fault.
    """

    code = "structured_output_truncated"


class _StructuredOutputAbsent(HostedProviderError):
    """Internal: the response carried no assistant content to parse.

    Raised instead of letting ``json.loads(None)`` throw ``TypeError`` into a broad handler, so the
    call site can classify truncation accurately. Never escapes the transport.
    """

    def __init__(self, message: str, *, finish_reason: str | None) -> None:
        super().__init__(message)
        self.finish_reason = finish_reason


class HostedRetryAdmissionRefused(HostedProviderResponseError):
    """A retry was refused before it could be sent, by authority rather than by formatting.

    Deliberately NOT a :class:`HostedStructuredOutputInvalid`, even though a structured-output
    failure is what prompted the retry. Exhausted call/token/cost/rate authority is a governance
    fact about the whole campaign, so it must stay campaign-fatal; isolating it per case would let
    a run continue past the point where its authorized envelope ran out, reported as a formatting
    nuisance.

    It still carries the FIRST attempt's ``observed_result`` so the measured tokens and cost of a
    call that genuinely happened are never dropped from the logical execution, and the refusal
    itself is retained as ``__cause__``.
    """

    code = "retry-admission-refused"


class HostedSettlementFailed(HostedProviderResponseError):
    """Usage was measured but could not be settled against the authorized ledger."""


class HostedSettlementBudgetExceeded(HostedSettlementFailed):
    """Settlement was refused because a token or cost cap is exhausted.

    Separated from :class:`HostedSettlementAccountingInvalid` because the two demand different
    operator responses: this one means the run legitimately reached its authorized ceiling, which
    a human can raise through the governed configuration path.
    """

    code = "settlement-budget-exceeded"


class HostedSettlementAccountingInvalid(HostedSettlementFailed):
    """Settlement was refused because the usage record itself is not coherent.

    A double-settled reservation or malformed usage is a correctness fault in accounting, not a
    spending decision, and must never be mistaken for "we ran out of budget".
    """

    code = "settlement-accounting-invalid"


class _StructuredOutputAmbiguous(HostedProviderError):
    """Structured output whose meaning is not single-valued — refused, never retried.

    Distinct from :class:`HostedStructuredOutputInvalid`: that one means "the model failed to
    produce the shape we asked for", which a second attempt can legitimately fix. This one means
    "the response can be read two different ways", which is a smuggling channel rather than a
    formatting slip, and retrying it would simply re-offer the channel.
    """

    code = "provider-structured-output-ambiguous"


class _ModelSubstituted(HostedProviderError):
    """A measured response whose observed model differs from its authorization."""

    code = "provider-model-substituted"


class _InvalidProviderIdentity(HostedProviderError):
    """A provider-controlled identity was absent or not safe canonical text."""

    code = "provider-identity-invalid"


class _UnauthorizedProviderRoute(HostedProviderError):
    """The observed upstream did not match the configured route."""

    code = "provider-route-unauthorized"


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
        logical_error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        if provider_event_status not in _EVENT_ERRORS:
            raise ValueError("physical provider event status is invalid")
        if logical_error_code is not None:
            if not isinstance(logical_error_code, str) or not logical_error_code:
                raise ValueError("logical provider error code is invalid")
            self.code = logical_error_code
        self.provider_event_status = provider_event_status
        self.returned_model = returned_model
        self.upstream_provider = upstream_provider
        self.provider_request_id = provider_request_id
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.reasoning_tokens = reasoning_tokens
        self.cost_measurement_state = cost_measurement_state
        self.measured_cost_usd = measured_cost_usd


class HostedProviderResponseUnusable(_PhysicalCallError):
    """One physical response could not be used, with NO authority violation observed.

    Raised at exactly the four sites where a response is rejected for its own shape — a terminal
    HTTP status, a body that will not parse as JSON, a body that is not an object, and usage
    accounting that is incomplete for no attributable reason. Those are statements about ONE
    physical response, not about the run's authority.

    Its siblings under ``_PhysicalCallError`` are deliberately excluded: identity_invalid and
    route_unauthorized each carry a ``logical_error_code`` naming a violated authority, and a
    caller that isolated them would keep attacking through a provider it has already observed to
    be the wrong one. Discriminating on TYPE rather than on that code is what keeps the two
    apart without a caller having to reason about codes.

    ``code`` is deliberately inherited unchanged, exactly as ``HostedProviderUnavailable`` does,
    so durable statuses, recorded error codes and console rendering are untouched; only the TYPE
    is new, and only so callers can isolate one unit of work.

    This is the fault that ended run 94c141a2 at 13 of 34 authorized cases: an invalid-JSON body
    surfaced as a bare ``_PhysicalCallError``, which matched neither isolated type and fell to the
    campaign-abort branch.
    """


class OpenRouterTransport:
    """Synchronous concurrency-one transport intended for the private Runner only."""

    # Release marker consumed by the target-free four-role acceptance gate. The transport
    # requires a ProviderLineageRecorder at construction and a ProviderLogicalContextV1 for every
    # invocation, so declaring the contract makes that already-enforced composition discoverable
    # without weakening either runtime check.
    LINEAGE_RECORDER_CONTRACT = "provider-call-final-v1"

    def __init__(
        self,
        *,
        configuration: HostedConfigurationSet,
        credential_resolver: Callable[[str], Secret],
        client: httpx.Client | None = None,
        ledger: HostedUsageLedger | None = None,
        lineage_recorder: ProviderLineageRecorder,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        validate_hosted_configuration_set(configuration)
        if not callable(getattr(lineage_recorder, "begin_physical_attempt", None)) or not callable(
            getattr(lineage_recorder, "finish_physical_attempt", None)
        ):
            raise TypeError("provider lineage recorder is invalid")
        self._configuration = configuration
        self._roles = {role.role: role for role in configuration.roles}
        self._credential_resolver = credential_resolver
        self._client = client or httpx.Client()
        self._owns_client = client is None
        self._ledger = ledger or HostedUsageLedger(configuration)
        if self._ledger.configuration_sha256 != configuration.configuration_sha256:
            raise ValueError("hosted usage ledger differs from the transport configuration")
        self._lineage_recorder = lineage_recorder
        self._sleeper = sleeper
        self._monotonic = monotonic
        self._last_request_at: float | None = None
        self._concurrency = threading.BoundedSemaphore(configuration.global_limits.max_concurrency)
        # The observed response body travels from the send to the terminal record without passing
        # through the result or the exception, so it is never returned to a caller who did not ask
        # for evidence. It is thread-local because the concurrency semaphore admits more than one
        # in-flight send per transport, and evidence attributed to the wrong physical call would
        # be a fabrication, not a glitch.
        self._observed_response = threading.local()

    @property
    def ledger(self) -> HostedUsageLedger:
        return self._ledger

    @property
    def usage_envelope_sha256(self) -> str:
        return self._ledger.envelope_sha256

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
        try:
            prompt = resolve_hosted_prompt(role, configuration.prompt_sha256)
        except ValueError:
            raise HostedProviderError(
                "configured prompt identity differs from the immutable prompt authority"
            ) from None
        if not isinstance(
            provider_context,
            ProviderLogicalContextV1,
        ):
            raise HostedProviderError("provider lineage context is unavailable")
        if (
            provider_context.agent_role != role
            or provider_context.requested_model != configuration.model_id
            or provider_context.configured_upstream != configuration.upstream_provider
            or provider_context.configuration_set_sha256 != self._configuration.configuration_sha256
            or provider_context.role_configuration_sha256 != configuration.configuration_sha256
            or provider_context.generation_policy_sha256 != generation_policy_sha256
            or provider_context.prompt_sha256 != configuration.prompt_sha256
            or provider_context.prompt_version != prompt.version
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

        def refuse_before_send(
            exc: HostedProviderError,
            *,
            cause: BaseException | None = None,
        ) -> NoReturn:
            """Raise a pre-send failure so a retry never loses attempt 1's measurements.

            Pacing, credential resolution, reservation and lineage all run BEFORE the physical
            send, so failing there consumes no provider authority. On a first attempt there is
            nothing to preserve and the original error is re-raised untouched — deliberately
            WITHOUT ``from``, because chaining an exception to itself creates a self-referential
            __cause__ that renders as a confusing repeated frame.

            On a RETRY there is something to preserve: attempt 1 was really sent, really measured
            and really charged. Letting a measurement-free refusal escape would drop that charge
            from the logical execution and misreport a formatting fault as an authority fault. So
            the refusal is re-shaped to carry attempt 1's observed result — while remaining its own
            campaign-fatal type, never the case-isolatable structured-output type, because
            exhausted authority is a fact about the whole run.

            ``cause`` is the underlying non-Hosted exception when one exists (a raw pacing or
            credential-resolver failure); it becomes __cause__ instead of ``exc`` itself.
            """

            if not isinstance(last_error, HostedStructuredOutputInvalid):
                exc.account_physical_attempts(physical_attempts)
                if cause is None or cause is exc:
                    raise exc
                raise exc from cause
            refusal = HostedRetryAdmissionRefused(
                "authorized retry was refused before it could be sent",
                observed_result=last_error.observed_result,
                code=HostedRetryAdmissionRefused.code,
                provider_event_status="invalid_output",
            )
            refusal.account_physical_attempts(physical_attempts)
            raise refusal from (exc if cause is None else cause)

        with self._concurrency:
            for attempt in range(1, attempts + 1):
                try:
                    self._pace(configuration)
                except HostedProviderError as exc:
                    refuse_before_send(exc)
                except Exception as exc:
                    refuse_before_send(
                        HostedProviderError(
                            "provider pacing failed before another physical send",
                        ),
                        cause=exc,
                    )
                try:
                    credential = self._credential_resolver(configuration.credential_reference)
                    if not isinstance(credential, Secret) or not credential:
                        raise HostedProviderError("hosted credential reference is unavailable")
                except HostedProviderError as exc:
                    refuse_before_send(exc)
                except Exception as exc:
                    refuse_before_send(
                        HostedProviderError("hosted credential reference is unavailable"),
                        cause=exc,
                    )
                try:
                    reservation = self._ledger.reserve(
                        role,
                        input_tokens=max(
                            input_tokens_upper_bound,
                            conservative_input_bound,
                        ),
                        output_tokens=max_output_tokens,
                        reasoning_tokens=max_reasoning_tokens,
                    )
                except HostedProviderError as exc:
                    refuse_before_send(exc)
                try:
                    invocation = self._begin_physical_attempt(
                        provider_context,
                        sequence=attempt,
                    )
                except HostedProviderError as exc:
                    refuse_before_send(exc)
                physical_attempts = attempt
                try:
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
                except HostedStructuredOutputInvalid as exc:
                    # The one retryable provider failure. Ordered BEFORE the general
                    # HostedProviderResponseError handler below, which must keep refusing every
                    # settlement/identity/route/model failure without a second send.
                    #
                    # The failed attempt is recorded first, so its measured tokens, cost, request
                    # id and invalid_output status survive regardless of what the retry does. On
                    # exhaustion the typed cause is re-raised as-is rather than falling through to
                    # the generic "failed after the authorized retry" error, so callers and the
                    # console still see invalid_structured_output.
                    self._record_observed_failure(invocation, exc)
                    last_error = exc
                    if attempt >= attempts:
                        exc.account_physical_attempts(physical_attempts)
                        raise
                except HostedProviderResponseError as exc:
                    self._record_observed_failure(invocation, exc)
                    exc.account_physical_attempts(physical_attempts)
                    raise
                except _PhysicalCallError as exc:
                    self._record_physical_failure(invocation, exc)
                    exc.account_physical_attempts(physical_attempts)
                    raise
                except HostedProviderError as exc:
                    self._record_unobserved_failure(
                        invocation,
                        status="terminal_failure",
                    )
                    exc.account_physical_attempts(physical_attempts)
                    raise
                except Exception as exc:
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
        raise HostedProviderUnavailable(
            "OpenRouter request failed after the authorized retry",
            physical_attempts=physical_attempts,
        ) from last_error

    def _begin_physical_attempt(
        self,
        context: ProviderLogicalContextV1,
        *,
        sequence: int,
    ) -> ProviderInvocationContextV1:
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
            or invocation.physical_sequence != sequence
            or any(
                getattr(invocation, field_name) != getattr(context, field_name)
                for field_name in (
                    "organization_id",
                    "campaign_run_id",
                    "campaign_attempt_id",
                    "logical_execution_id",
                    "parent_execution_id",
                    "agent_role",
                    "requested_model",
                    "configured_upstream",
                    "prompt_version",
                    "prompt_sha256",
                    "configuration_set_sha256",
                    "role_configuration_sha256",
                    "generation_policy_sha256",
                )
            )
        ):
            raise HostedProviderError("physical provider invocation returned invalid identity")
        return invocation

    def _record_success(
        self,
        invocation: ProviderInvocationContextV1,
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
        invocation: ProviderInvocationContextV1,
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
        invocation: ProviderInvocationContextV1,
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
        invocation: ProviderInvocationContextV1,
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
        invocation: ProviderInvocationContextV1,
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
        response_text, response_truncated, response_sha256 = self._take_response_evidence()
        finished_at = datetime.datetime.now(datetime.UTC)

        def build(with_response: bool) -> ProviderTerminalEventV1:
            return ProviderTerminalEventV1(
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
                finished_at=finished_at,
                response_text=response_text if with_response else None,
                response_truncated=response_truncated if with_response else False,
                response_sha256=response_sha256 if with_response else None,
            )

        def settle(
            with_response: bool,
        ) -> tuple[ProviderTerminalEventV1, ProviderTerminalEventV1]:
            candidate = build(with_response)
            return candidate, self._lineage_recorder.finish_physical_attempt(
                invocation,
                candidate,
            )

        try:
            try:
                event, recorded = settle(True)
            except Exception:
                # Losing the response evidence is acceptable; losing the terminal record of a real,
                # already-billed provider call is not. The fallback re-runs the durable write and
                # not merely event construction, because evidence the store cannot accept is
                # refused at the INSERT rather than by validation — that write is transactional, so
                # the refused attempt left nothing behind and the retry starts from a clean slate.
                #
                # With no evidence to drop the retry would be byte-identical and would fail the
                # same way, so the original failure is reported instead of doubling the write.
                if response_text is None:
                    raise
                event, recorded = settle(False)
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

    def _capture_response_evidence(
        self,
        response: httpx.Response,
        credential: Secret,
    ) -> None:
        """Keep the provider's own bytes for this physical call, redacted and bounded.

        Best-effort by construction. Evidence is a byproduct of the call, never a precondition of
        it, so every failure mode here degrades to "no response recorded" — an honest ``NULL`` —
        and none of them can propagate into the caller's result.
        """

        try:
            body = response.text
            if not isinstance(body, str):
                return
            # The bearer value this exact call sent is passed as a literal redaction so an
            # upstream that echoes the Authorization header back cannot durably store our
            # credential, on top of the shared pattern-based screening.
            self._observed_response.evidence = capture_response_evidence(
                _sanitize_text(body, (credential.reveal(),))
            )
        except Exception:
            self._observed_response.evidence = None

    def _take_response_evidence(self) -> tuple[str | None, bool, str | None]:
        """Consume the evidence for the physical call being terminalized, exactly once."""

        evidence = getattr(self._observed_response, "evidence", None)
        self._observed_response.evidence = None
        if not isinstance(evidence, tuple) or len(evidence) != 3:
            return None, False, None
        return evidence

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
        # Nothing has been observed for THIS physical attempt yet. Clearing first is what makes a
        # timeout or transport failure record no response at all instead of the previous
        # attempt's.
        self._observed_response.evidence = None
        # The authorization ledger reserves headroom for provider-reported Qwen usage that can
        # exceed its requested thinking budget. The request itself remains a bounded one-choice
        # case selection and does not need the entire accounting envelope.
        requested_reasoning_tokens = (
            min(reservation.reasoning_tokens, _RED_TEAM_REQUEST_REASONING_TOKENS)
            if configuration.role == "red_team"
            else reservation.reasoning_tokens
        )
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
                # configured output bound is only the final-answer allowance.
                #
                # The parameter MUST be `max_tokens`, not `max_completion_tokens`: OpenRouter
                # advertises `max_tokens` in every endpoint's `supported_parameters`, and this
                # request sets `provider.require_parameters: true`, which refuses any endpoint
                # that does not support a parameter we send. Sending `max_completion_tokens`
                # therefore matched NO endpoint and failed routing with HTTP 404 "No endpoints
                # found that can handle the requested parameters" for every role — verified
                # against google/gemini-2.5-pro, whose supported set is
                # {max_tokens, reasoning, response_format, structured_outputs, ...}.
                "max_tokens": max_output_tokens + requested_reasoning_tokens,
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
                "reasoning": {"max_tokens": requested_reasoning_tokens},
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
        # Captured here, before any validation can reject the payload: the response that failed
        # schema validation is exactly the one an operator needs to read, and it is the only
        # moment those bytes exist.
        self._capture_response_evidence(response, credential)
        if response.status_code in _RETRYABLE_STATUS:
            raise _RetryableResponse(self._retry_after(response))
        if response.status_code < 200 or response.status_code >= 300:
            raise HostedProviderResponseUnusable(
                "OpenRouter returned a terminal HTTP error",
                provider_event_status="terminal_failure",
            )
        try:
            payload = response.json()
        except (TypeError, ValueError) as exc:
            raise HostedProviderResponseUnusable(
                "OpenRouter returned invalid JSON",
                provider_event_status="invalid_output",
            ) from exc
        if not isinstance(payload, dict):
            raise HostedProviderResponseUnusable(
                "OpenRouter response has an invalid shape",
                provider_event_status="invalid_output",
            )
        requested_model = configuration.model_id
        returned_model, returned_model_valid = normalize_provider_observation(
            payload.get("model"),
            field_name="returned_model",
            maximum=192,
        )
        request_id, request_id_valid = normalize_provider_observation(
            payload.get("id"),
            field_name="provider_request_id",
            maximum=256,
        )
        (
            upstream_provider,
            upstream_provider_valid,
            selected_model,
            selected_model_valid,
            router_metadata_valid,
        ) = self._selected_endpoint(
            payload,
            requested_model=requested_model,
        )
        model_substituted = returned_model_valid and returned_model != requested_model
        selected_model_authorized = (
            selected_model_valid
            and selected_model
            in _AUTHORIZED_ENDPOINT_MODELS.get(
                requested_model,
                frozenset({requested_model}),
            )
        )
        identity_invalid = (
            not router_metadata_valid
            or not returned_model_valid
            or not selected_model_valid
            or not selected_model_authorized
            or not upstream_provider_valid
            or not request_id_valid
        )
        route_authorized = False
        try:
            if upstream_provider_valid and router_metadata_valid:
                route_authorized = served_provider_matches_configured(
                    configuration.upstream_provider,
                    upstream_provider,
                )
        except ValueError:
            # Defensive only: normalized observations satisfy the shared lineage predicate.
            route_authorized = False

        usage_observation = self._usage(payload)
        if not usage_observation.complete:
            # The TYPE is chosen in the same branch that names the violated authority, so the two
            # can never disagree. Only the final branch — accounting incomplete with nothing
            # attributable — is a statement about this one response and therefore isolatable.
            unusable_response = False
            if model_substituted:
                status = "model_mismatch"
                logical_error_code = _ModelSubstituted.code
            elif identity_invalid:
                status = "identity_invalid"
                logical_error_code = _InvalidProviderIdentity.code
            elif not route_authorized:
                status = "route_unauthorized"
                logical_error_code = _UnauthorizedProviderRoute.code
            else:
                status = "invalid_usage"
                logical_error_code = None
                unusable_response = True
            physical_error = (
                HostedProviderResponseUnusable if unusable_response else _PhysicalCallError
            )
            raise physical_error(
                usage_observation.error_message
                or "OpenRouter provider usage accounting is incomplete",
                provider_event_status=status,
                returned_model=returned_model,
                upstream_provider=upstream_provider,
                provider_request_id=request_id,
                input_tokens=usage_observation.input_tokens,
                output_tokens=usage_observation.output_tokens,
                reasoning_tokens=usage_observation.reasoning_tokens,
                cost_measurement_state=usage_observation.cost_measurement_state,
                measured_cost_usd=usage_observation.measured_cost,
                logical_error_code=logical_error_code,
            )
        usage = usage_observation.settlement()

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
        settle_error: HostedProviderError | None = None
        try:
            self._ledger.settle(reservation, **usage)
        except HostedProviderError as exc:
            settle_error = exc

        if model_substituted:
            raise HostedProviderResponseError(
                "OpenRouter served a model other than the authorized one",
                observed_result=observed_result,
                code=_ModelSubstituted.code,
                provider_event_status="model_mismatch",
            ) from settle_error

        if identity_invalid:
            raise _PhysicalCallError(
                "OpenRouter response has an invalid provider identity",
                provider_event_status="identity_invalid",
                returned_model=returned_model,
                upstream_provider=upstream_provider,
                provider_request_id=request_id,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                cost_measurement_state="measured",
                measured_cost_usd=usage["measured_cost"],
                logical_error_code=_InvalidProviderIdentity.code,
            ) from settle_error
        if not route_authorized:
            raise _PhysicalCallError(
                "OpenRouter selected an unauthorized provider route",
                provider_event_status="route_unauthorized",
                returned_model=returned_model,
                upstream_provider=upstream_provider,
                provider_request_id=request_id,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                reasoning_tokens=usage["reasoning_tokens"],
                cost_measurement_state="measured",
                measured_cost_usd=usage["measured_cost"],
                logical_error_code=_UnauthorizedProviderRoute.code,
            ) from settle_error

        if settle_error is not None:
            # Settlement fails for two materially different reasons and the old funnel erased the
            # difference, so `except HostedBudgetExceeded` could not catch a settlement-time cap
            # breach — only the string code survived. Budget exhaustion is a governed ceiling a
            # human can raise; accounting corruption is a correctness fault that must never be
            # mistaken for one.
            settlement_type = (
                HostedSettlementBudgetExceeded
                if isinstance(settle_error, HostedBudgetExceeded)
                else HostedSettlementAccountingInvalid
            )
            raise settlement_type(
                "OpenRouter response failed after measured usage was observed",
                observed_result=observed_result,
                code=settle_error.code,
                provider_event_status="invalid_usage",
            ) from settle_error

        # Settlement (above) has already succeeded, so every cap this call could breach has been
        # charged and accepted. What remains is purely a formatting question, which is why this —
        # and only this — raises the retryable type.
        try:
            output = self._structured_output(payload, output_schema)
        except _StructuredOutputAmbiguous as exc:
            # Ambiguity is a refusal, not a retry. Keep the original non-retryable type so the
            # smuggling channel is terminalized at the wire exactly as before.
            raise HostedProviderResponseError(
                "OpenRouter response failed after measured usage was observed",
                observed_result=observed_result,
                code=exc.code,
                provider_event_status="invalid_output",
            ) from exc
        except _StructuredOutputAbsent as exc:
            # Same retry and per-case isolation as any other formatting failure (it is a subclass),
            # but named for what actually happened so the operator is not sent looking for a schema
            # bug that does not exist.
            reason = exc.finish_reason or "unreported"
            raise HostedStructuredOutputTruncated(
                "OpenRouter returned no assistant content after measured usage "
                f"(finish_reason={reason})",
                observed_result=observed_result,
                code=HostedStructuredOutputTruncated.code,
                provider_event_status="invalid_output",
            ) from exc
        except HostedProviderError as exc:
            raise HostedStructuredOutputInvalid(
                "OpenRouter structured output failed schema validation after measured usage",
                observed_result=observed_result,
                code=HostedStructuredOutputInvalid.code,
                provider_event_status="invalid_output",
            ) from exc
        return replace(observed_result, output=output)

    @staticmethod
    def _selected_endpoint(
        payload: Mapping[str, Any],
        *,
        requested_model: str,
    ) -> tuple[str, bool, str, bool, bool]:
        unknown_upstream, _ = normalize_provider_observation(
            None,
            field_name="upstream_provider",
            maximum=128,
        )
        unknown_model, _ = normalize_provider_observation(
            None,
            field_name="returned_model",
            maximum=192,
        )
        metadata = payload.get("openrouter_metadata")
        if not isinstance(metadata, Mapping):
            return unknown_upstream, False, unknown_model, False, False
        requested_model_matches = metadata.get("requested") == requested_model
        endpoints = metadata.get("endpoints")
        available = endpoints.get("available") if isinstance(endpoints, Mapping) else None
        if not isinstance(available, list):
            return unknown_upstream, False, unknown_model, False, False
        selected = [
            endpoint
            for endpoint in available
            if isinstance(endpoint, Mapping) and endpoint.get("selected") is True
        ]
        if len(selected) != 1:
            return unknown_upstream, False, unknown_model, False, False
        upstream_provider, upstream_provider_valid = normalize_provider_observation(
            selected[0].get("provider"),
            field_name="upstream_provider",
            maximum=128,
        )
        selected_model, selected_model_valid = normalize_provider_observation(
            selected[0].get("model"),
            field_name="returned_model",
            maximum=192,
        )
        return (
            upstream_provider,
            upstream_provider_valid,
            selected_model,
            selected_model_valid,
            requested_model_matches,
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
            len(message["role"].encode("utf-8")) + len(message["content"].encode("utf-8"))
            for message in messages
        )
        return content_bytes + (64 * len(messages)) + 4096

    @staticmethod
    def _usage(payload: Mapping[str, Any]) -> _UsageObservation:
        usage = payload.get("usage")
        if not isinstance(usage, Mapping):
            return _UsageObservation(
                measured_cost=None,
                input_tokens=None,
                output_tokens=None,
                reasoning_tokens=None,
                cost_measurement_state="not_observed",
                error_message="OpenRouter response has no measured usage",
            )

        token_error = False
        reasoning_error = False

        def observed_token(value: object) -> int | None:
            nonlocal token_error
            if type(value) is not int or value < 0 or value > _MAX_PROVIDER_TOKEN_COUNT:
                token_error = True
                return None
            return value

        input_tokens = observed_token(usage.get("prompt_tokens"))
        completion_tokens = observed_token(usage.get("completion_tokens"))
        if "completion_tokens_details" not in usage:
            reasoning_tokens = 0
        else:
            details = usage.get("completion_tokens_details")
            if not isinstance(details, Mapping):
                token_error = True
                reasoning_tokens = None
            else:
                reasoning_tokens = observed_token(details.get("reasoning_tokens", 0))
        output_tokens: int | None = None
        if completion_tokens is not None and reasoning_tokens is not None:
            if reasoning_tokens > completion_tokens:
                reasoning_error = True
            else:
                # OpenRouter completion_tokens includes reasoning. Persist the disjoint
                # final-answer and reasoning counts so totals and caps never double-count.
                output_tokens = completion_tokens - reasoning_tokens

        measured_cost: Decimal | None = None
        cost_error: str | None = None
        try:
            raw_cost = usage["cost"]
            measured_cost = Decimal(str(raw_cost))
        except (InvalidOperation, KeyError, TypeError, ValueError):
            cost_error = "OpenRouter measured cost is unavailable"
        else:
            if not measured_cost.is_finite() or measured_cost < 0 or measured_cost > _MAX_COST:
                cost_error = "OpenRouter measured cost is invalid"
                measured_cost = None
            else:
                try:
                    stored_cost = measured_cost.quantize(_COST_QUANTUM)
                except InvalidOperation:
                    cost_error = "OpenRouter measured cost exceeds storage precision"
                    measured_cost = None
                else:
                    if stored_cost != measured_cost:
                        cost_error = "OpenRouter measured cost exceeds storage precision"
                        measured_cost = None
                    else:
                        measured_cost = stored_cost

        tokens_complete = (
            input_tokens is not None
            and output_tokens is not None
            and reasoning_tokens is not None
            and not reasoning_error
        )
        if measured_cost is not None:
            cost_measurement_state = "measured" if tokens_complete else "partial"
        elif "cost" in usage:
            cost_measurement_state = "invalid"
        else:
            cost_measurement_state = "not_observed"

        if reasoning_error:
            error_message = "OpenRouter reasoning token accounting is invalid"
        elif token_error or not tokens_complete:
            error_message = "OpenRouter token accounting is invalid"
        else:
            error_message = cost_error
        return _UsageObservation(
            measured_cost=measured_cost,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            reasoning_tokens=reasoning_tokens,
            cost_measurement_state=cost_measurement_state,
            error_message=error_message,
        )

    @staticmethod
    def _structured_output(
        payload: Mapping[str, Any], output_schema: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        # Checked before the broad handler below, because `json.loads(None)` raises TypeError and
        # that handler would rewrite it into a generic "failed validation" — reporting a run-away
        # generation that hit its token ceiling as though the model had emitted malformed JSON.
        try:
            choice = payload["choices"][0]  # type: ignore[index]
            absent = choice["message"].get("content") is None
            finish_reason = choice.get("finish_reason")
        except Exception:
            absent, finish_reason = False, None
        if absent:
            raise _StructuredOutputAbsent(
                "OpenRouter returned no assistant content to parse",
                finish_reason=str(finish_reason) if finish_reason is not None else None,
            )
        try:
            content = payload["choices"][0]["message"]["content"]  # type: ignore[index]
            decoded = json.loads(content, object_pairs_hook=_pairs_without_duplicates)
            Draft202012Validator.check_schema(dict(output_schema))
            Draft202012Validator(dict(output_schema)).validate(decoded)
        except _DuplicateStructuredKey as exc:
            # NOT a formatting slip and NOT retryable. A repeated key validates against the FIRST
            # value while json.loads keeps the LAST, so the payload that was screened is not the
            # payload that gets stored — a smuggling channel through the generator's own output.
            # Retrying would hand the same channel a second attempt, so this keeps its own type
            # and terminalizes at the wire.
            raise _StructuredOutputAmbiguous(
                "OpenRouter structured output repeated an object key"
            ) from exc
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
    "HostedProviderResponseUnusable",
    "HostedProviderUnavailable",
    "HostedUsageEnvelope",
    "HostedUsageLedger",
    "OPENROUTER_CHAT_COMPLETIONS_URL",
    "OpenRouterResult",
    "OpenRouterTransport",
]
