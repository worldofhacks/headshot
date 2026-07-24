"""Validated, content-free contracts for physical hosted-provider call lineage."""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Final
from uuid import uuid4

_ROLES: Final = frozenset({"orchestrator", "red_team", "judge", "documentation"})
_STATUSES: Final = {
    "succeeded": None,
    "timeout": "provider_timeout",
    "retryable_failure": "provider_retryable",
    "terminal_failure": "provider_terminal",
    "model_mismatch": "returned_model_mismatch",
    "invalid_usage": "invalid_provider_usage",
    "invalid_output": "invalid_structured_output",
    "outcome_unknown": "provider_outcome_unknown",
}
_COST_STATES: Final = frozenset({"measured", "partial", "not_observed", "invalid"})
_COST_QUANTUM: Final = Decimal("0.000001")
_MAX_COST: Final = Decimal("99999999.999999")
_MAX_INTEGER: Final = 2_147_483_647
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_SENSITIVE = re.compile(
    r"\bsk-(?:(?:ant|or|proj)-)?[A-Za-z0-9_-]{8,}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"private\s+key|hostile[_-]?evidence|"
    r"(?:api[_ -]?key|token|secret|password|authorization|credential|"
    r"provider[_-]?key|target[_-]?session|session[_-]?id)[\"']?\s*[:=]",
    re.IGNORECASE,
)


def _safe_text(value: object, *, field_name: str, maximum: int = 192) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _SAFE_IDENTIFIER.fullmatch(value) is None
        or _SENSITIVE.search(value)
    ):
        raise ValueError(f"{field_name} is invalid or contains sensitive content")
    return value


def _sha(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _aware(value: object, *, field_name: str) -> datetime.datetime:
    if (
        not isinstance(value, datetime.datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _validate_logical_fields(value: object) -> None:
    for name, maximum in (
        ("organization_id", 64),
        ("campaign_run_id", 64),
        ("campaign_attempt_id", 64),
        ("logical_execution_id", 64),
        ("requested_model", 192),
        ("configured_upstream", 128),
        ("prompt_version", 64),
    ):
        _safe_text(getattr(value, name), field_name=name, maximum=maximum)
    parent_execution_id = value.parent_execution_id
    if parent_execution_id is not None:
        _safe_text(parent_execution_id, field_name="parent_execution_id", maximum=64)
    if value.agent_role not in _ROLES:
        raise ValueError("agent_role is invalid")
    for name in (
        "prompt_sha256",
        "configuration_set_sha256",
        "role_configuration_sha256",
        "generation_policy_sha256",
    ):
        _sha(getattr(value, name), field_name=name)


@dataclass(frozen=True, slots=True)
class ProviderLogicalContextV1:
    """Immutable logical identity from which the Runner reserves physical attempts."""

    organization_id: str
    campaign_run_id: str
    campaign_attempt_id: str
    logical_execution_id: str
    parent_execution_id: str | None
    agent_role: str
    requested_model: str
    configured_upstream: str
    prompt_version: str
    prompt_sha256: str
    configuration_set_sha256: str
    role_configuration_sha256: str
    generation_policy_sha256: str

    def __post_init__(self) -> None:
        _validate_logical_fields(self)


@dataclass(frozen=True, slots=True)
class ProviderInvocationContextV1:
    """A committed pre-call reservation for exactly one physical provider attempt."""

    invocation_id: str
    organization_id: str
    campaign_run_id: str
    campaign_attempt_id: str
    logical_execution_id: str
    parent_execution_id: str | None
    agent_role: str
    physical_sequence: int
    idempotency_key: str
    requested_model: str
    configured_upstream: str
    prompt_version: str
    prompt_sha256: str
    configuration_set_sha256: str
    role_configuration_sha256: str
    generation_policy_sha256: str
    started_at: datetime.datetime

    def __post_init__(self) -> None:
        if (
            isinstance(self.physical_sequence, bool)
            or not isinstance(self.physical_sequence, int)
            or not 1 <= self.physical_sequence <= _MAX_INTEGER
        ):
            raise ValueError("physical_sequence must be a positive integer")
        _safe_text(self.invocation_id, field_name="invocation_id", maximum=64)
        _safe_text(self.idempotency_key, field_name="idempotency_key", maximum=128)
        _validate_logical_fields(self)
        _aware(self.started_at, field_name="started_at")


@dataclass(frozen=True, slots=True)
class ProviderTerminalEventV1:
    """Validated terminal facts for one already-committed physical invocation."""

    invocation_id: str
    physical_sequence: int
    status: str
    returned_model: str | None
    upstream_provider: str | None
    provider_request_id: str | None
    input_tokens: int | None
    output_tokens: int | None
    reasoning_tokens: int | None
    cost_measurement_state: str
    measured_cost_usd: Decimal | None
    error_code: str | None
    finished_at: datetime.datetime
    event_id: str = field(default_factory=lambda: uuid4().hex)

    def __post_init__(self) -> None:
        _safe_text(self.invocation_id, field_name="invocation_id", maximum=64)
        _safe_text(self.event_id, field_name="event_id", maximum=64)
        if (
            isinstance(self.physical_sequence, bool)
            or not isinstance(self.physical_sequence, int)
            or not 1 <= self.physical_sequence <= _MAX_INTEGER
        ):
            raise ValueError("physical_sequence must be a positive integer")
        if self.status not in _STATUSES:
            raise ValueError("status is invalid")
        expected_error = _STATUSES[self.status]
        if self.error_code != expected_error:
            raise ValueError("error_code is invalid for status")
        for name in ("returned_model", "upstream_provider", "provider_request_id"):
            value = getattr(self, name)
            if value is not None:
                maximum = 128 if name == "upstream_provider" else 192
                _safe_text(value, field_name=name, maximum=maximum)
        for name in ("input_tokens", "output_tokens", "reasoning_tokens"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= _MAX_INTEGER
            ):
                raise ValueError("token usage is invalid")
        if self.cost_measurement_state not in _COST_STATES:
            raise ValueError("cost measurement state is invalid")
        if self.cost_measurement_state in {"measured", "partial"}:
            if (
                not isinstance(self.measured_cost_usd, Decimal)
                or not self.measured_cost_usd.is_finite()
                or self.measured_cost_usd < 0
            ):
                raise TypeError("measured cost must be a non-negative Decimal")
            try:
                canonical_cost = self.measured_cost_usd.quantize(_COST_QUANTUM)
            except InvalidOperation as exc:
                raise ValueError("measured cost exceeds storage precision") from exc
            if canonical_cost != self.measured_cost_usd or canonical_cost > _MAX_COST:
                raise ValueError("measured cost exceeds storage precision")
        elif self.measured_cost_usd is not None:
            raise ValueError("unavailable cost measurement must be null")
        _aware(self.finished_at, field_name="finished_at")


__all__ = [
    "ProviderInvocationContextV1",
    "ProviderLogicalContextV1",
    "ProviderTerminalEventV1",
]
