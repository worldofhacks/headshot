"""Validated, content-free contracts for physical hosted-provider call lineage.

The physical ledger records one reservation and one terminal event for every network attempt.
It deliberately has no API for terminalizing a logical ``agent_executions`` row: role-output
validation and independent Judge reconciliation remain the logical lifecycle's responsibility.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Final, Protocol
from uuid import uuid4

from agentforge.secrets import looks_like_provider_key

_ROLES: Final = frozenset({"orchestrator", "red_team", "judge", "documentation"})
_STATUSES: Final = {
    "succeeded": None,
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
_COST_STATES: Final = frozenset({"measured", "partial", "not_observed", "invalid"})
_COST_QUANTUM: Final = Decimal("0.000000000001")
_MAX_COST: Final = Decimal("99999999.999999999999")
_MAX_INTEGER: Final = 2_147_483_647
# Mirrors the ``provider_event_response_bounded`` check added in migration 0028. Provider response
# bytes are untrusted input recorded on the physical hot path, so the ceiling lives in the contract
# as well as the schema and a violation is refused here rather than at the INSERT.
MAX_PROVIDER_RESPONSE_BYTES: Final = 65_536
# Codepoints a PostgreSQL TEXT column cannot hold, and therefore codepoints this contract may not
# carry. U+0000 is refused outright by the protocol ("PostgreSQL text fields cannot contain NUL
# (0x00) bytes"); an unpaired surrogate has no UTF-8 encoding at all, so ``str.encode`` fails before
# the database is even reached. A provider response is untrusted bytes decoded on the physical hot
# path, so both are reachable remotely — a single one of either would otherwise turn a billed call
# into a lost terminal record.
_UNSTORABLE_TEXT = re.compile("[\x00\ud800-\udfff]")
# Replaced, not dropped: U+FFFD is the standard "something was here that cannot be represented"
# marker, so offsets, surrounding bytes, and the fact that the provider emitted something anomalous
# all survive. Deleting would silently shorten the evidence and hide the anomaly.
UNSTORABLE_TEXT_REPLACEMENT: Final = "�"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/@+-]*$")
_SENSITIVE = re.compile(
    r"\bsk-(?:(?:ant|or|proj)-)?[A-Za-z0-9_-]{8,}\b|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|"
    r"private\s+key|hostile[_-]?evidence|"
    r"(?:api[_ -]?key|token|secret|password|authorization|credential|"
    r"provider[_-]?key|target[_-]?session|session[_-]?id)[\"']?\s*[:=]",
    re.IGNORECASE,
)
_RAW_AUTH_MATERIAL = re.compile(
    r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}\b|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
    r"\bglpat-[A-Za-z0-9_-]{20,}\b|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"\bAIza[0-9A-Za-z_-]{20,}\b|"
    r"\bya29\.[0-9A-Za-z_-]{20,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|"
    r"\b[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@|"
    r"\b(?:authorization|x-api-key|api-key)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_PROVIDER_IDENTITY_FIELDS: Final = frozenset(
    {
        "requested_model",
        "configured_upstream",
        "returned_model",
        "upstream_provider",
        "provider_request_id",
    }
)
# OpenRouter routing authorization uses lowercase provider slugs, while router metadata reports a
# human-facing provider name. Keep the two identities distinct and normalize only explicitly
# documented/tested routes. Unknown slugs fail closed.
_OPENROUTER_SERVED_NAMES: Final = {
    "anthropic": frozenset({"Anthropic"}),
    "together": frozenset({"Together"}),
    "google-vertex": frozenset({"Google", "Google Vertex"}),
    "openai": frozenset({"OpenAI"}),
    "atlas-cloud": frozenset({"AtlasCloud"}),
    "digitalocean": frozenset({"DigitalOcean"}),
    "chutes": frozenset({"Chutes"}),
}


def _new_event_id() -> str:
    return hashlib.sha256(uuid4().bytes).hexdigest()


def _safe_text(value: object, *, field_name: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or _SAFE_IDENTIFIER.fullmatch(value) is None
        or _SENSITIVE.search(value)
        or _RAW_AUTH_MATERIAL.search(value)
        or (field_name in _PROVIDER_IDENTITY_FIELDS and looks_like_provider_key(value.strip()))
    ):
        raise ValueError(f"{field_name} is invalid or contains sensitive content")
    return value


def _optional_safe_text(
    value: object,
    *,
    field_name: str,
    maximum: int,
) -> str | None:
    if value is None:
        return None
    return _safe_text(value, field_name=field_name, maximum=maximum)


def normalize_provider_observation(
    value: object,
    *,
    field_name: str,
    maximum: int,
) -> tuple[str, bool]:
    """Make a provider-controlled identity durably recordable without trusting it.

    A valid observation is preserved byte-for-byte. Anything that the canonical lineage validator
    would reject, including absence, becomes a stable, bounded digest marker. The accompanying
    boolean retains raw validity for authorization decisions. In particular, padding is not
    stripped: malformed text must never be laundered into an authorized identity merely so it can
    be stored.
    """

    try:
        if isinstance(value, str) and value.startswith("unsafe-provider-text-"):
            raise ValueError("provider observation uses the reserved sanitizer prefix")
        return _safe_text(value, field_name=field_name, maximum=maximum), True
    except ValueError:
        raw = value if isinstance(value, str) else repr(value)
        digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
        normalized = f"unsafe-provider-text-{digest[:32]}"
        return (
            _safe_text(
                normalized,
                field_name=field_name,
                maximum=maximum,
            ),
            False,
        )


def capture_response_evidence(value: object) -> tuple[str | None, bool, str | None]:
    """Bound and digest one observed provider response body for durable evidence.

    Returns ``(response_text, response_truncated, response_sha256)`` ready for
    :class:`ProviderTerminalEventV1`. The digest always covers the bytes that are actually kept:
    codepoints PostgreSQL TEXT cannot store are replaced and over-long text is cut to
    :data:`MAX_PROVIDER_RESPONSE_BYTES`, both *before* hashing, and the cut is made on a UTF-8
    boundary so the stored text re-encodes to exactly the digested bytes.

    Anything that is not text — including absence — yields ``(None, False, None)``. This function
    never raises: a caller on the provider hot path must be able to give up on evidence without
    giving up on the call.
    """

    if not isinstance(value, str):
        return None, False, None
    # Sanitize before measuring. The replacement is wider than what it replaces, so bounding or
    # digesting the raw text would describe bytes that are not the bytes that get stored.
    value = _UNSTORABLE_TEXT.sub(UNSTORABLE_TEXT_REPLACEMENT, value)
    encoded = value.encode("utf-8")
    truncated = len(encoded) > MAX_PROVIDER_RESPONSE_BYTES
    if truncated:
        # ``errors="ignore"`` drops the partial code point the byte cut may have split, so the
        # kept text is valid UTF-8 and encodes to at most the bound.
        value = encoded[:MAX_PROVIDER_RESPONSE_BYTES].decode("utf-8", "ignore")
        encoded = value.encode("utf-8")
    return value, truncated, hashlib.sha256(encoded).hexdigest()


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
        ("logical_execution_id", 64),
        ("requested_model", 192),
        ("configured_upstream", 128),
        ("prompt_version", 64),
    ):
        _safe_text(getattr(value, name), field_name=name, maximum=maximum)
    _optional_safe_text(
        value.campaign_attempt_id,
        field_name="campaign_attempt_id",
        maximum=64,
    )
    _optional_safe_text(
        value.parent_execution_id,
        field_name="parent_execution_id",
        maximum=64,
    )
    if value.agent_role not in _ROLES:
        raise ValueError("agent_role is invalid")
    for name in (
        "prompt_sha256",
        "configuration_set_sha256",
        "role_configuration_sha256",
        "generation_policy_sha256",
    ):
        _sha(getattr(value, name), field_name=name)


def served_provider_matches_configured(
    configured_upstream: str,
    served_provider: str,
) -> bool:
    """Return whether router metadata names the configured OpenRouter route.

    Configured values are exact lowercase routing slugs. Served values are OpenRouter's display
    identities, so equality/case-folding is intentionally not used as authorization.
    """

    configured = _safe_text(
        configured_upstream,
        field_name="configured_upstream",
        maximum=128,
    )
    served = _safe_text(
        served_provider,
        field_name="upstream_provider",
        maximum=128,
    )
    base_slug = configured.split("/", 1)[0]
    return served in _OPENROUTER_SERVED_NAMES.get(base_slug, frozenset())


@dataclass(frozen=True, slots=True)
class ProviderLogicalContextV1:
    """Immutable logical identity from which the Runner reserves physical attempts."""

    organization_id: str
    campaign_run_id: str
    campaign_attempt_id: str | None
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
    """A committed pre-send reservation for exactly one physical provider attempt."""

    invocation_id: str
    organization_id: str
    campaign_run_id: str
    campaign_attempt_id: str | None
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
        _sha(self.invocation_id, field_name="invocation_id")
        _safe_text(self.idempotency_key, field_name="idempotency_key", maximum=128)
        if self.idempotency_key != f"provider-call:{self.invocation_id}":
            raise ValueError("idempotency_key must derive from invocation_id")
        _validate_logical_fields(self)
        _aware(self.started_at, field_name="started_at")


@dataclass(frozen=True, slots=True)
class ProviderTerminalEventV1:
    """Validated terminal facts for one already-committed physical invocation.

    The optional response fields carry the exact bytes the provider returned for THIS physical
    call, already credential-redacted and bounded by the producer. They default to absent so that
    a caller with nothing to record — a timeout, a transport failure, a crash-recovered row —
    states that fact rather than inventing a body. Use :func:`capture_response_evidence` to
    produce them; constructing them by hand is validated, not trusted.
    """

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
    event_id: str = field(default_factory=_new_event_id)
    response_text: str | None = None
    response_truncated: bool = False
    response_sha256: str | None = None

    def __post_init__(self) -> None:
        _sha(self.invocation_id, field_name="invocation_id")
        if not isinstance(self.event_id, str) or _SHA256.fullmatch(self.event_id) is None:
            raise ValueError("event_id must be a lowercase SHA-256 identity")
        if (
            isinstance(self.physical_sequence, bool)
            or not isinstance(self.physical_sequence, int)
            or not 1 <= self.physical_sequence <= _MAX_INTEGER
        ):
            raise ValueError("physical_sequence must be a positive integer")
        if self.status not in _STATUSES:
            raise ValueError("status is invalid")
        if self.error_code != _STATUSES[self.status]:
            raise ValueError("error_code is invalid for status")
        for name, maximum in (
            ("returned_model", 192),
            ("upstream_provider", 128),
            ("provider_request_id", 256),
        ):
            _optional_safe_text(
                getattr(self, name),
                field_name=name,
                maximum=maximum,
            )
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
        if self.status == "succeeded" and (
            self.returned_model is None
            or self.upstream_provider is None
            or self.provider_request_id is None
            or self.input_tokens is None
            or self.output_tokens is None
            or self.reasoning_tokens is None
            or self.cost_measurement_state != "measured"
        ):
            raise ValueError("successful provider event requires complete measured observations")
        self._validate_response_evidence()
        _aware(self.finished_at, field_name="finished_at")

    def _validate_response_evidence(self) -> None:
        """Refuse any response evidence the row could not honestly stand behind.

        Deliberately strict rather than self-correcting: silently truncating or re-digesting a
        caller's text would make the event disagree with what the caller believes it recorded.
        Producers call :func:`capture_response_evidence` first, which cannot fail these checks.
        """

        if not isinstance(self.response_truncated, bool):
            raise ValueError("response_truncated must be a boolean")
        if self.response_text is None:
            if self.response_sha256 is not None:
                raise ValueError("an unobserved response cannot carry a digest")
            if self.response_truncated:
                raise ValueError("an unobserved response cannot be truncated")
            return
        if not isinstance(self.response_text, str):
            raise ValueError("response_text must be text or absent")
        # Defence in depth against a lost terminal record. ``capture_response_evidence`` already
        # removes these, so reaching here means a producer built the event by hand; refusing it in
        # the contract is the difference between one dropped piece of evidence and an INSERT the
        # database rejects, which would strand the whole billed call as unsettled.
        if _UNSTORABLE_TEXT.search(self.response_text):
            raise ValueError(
                "response_text contains codepoints PostgreSQL text cannot store; "
                "sanitize before hashing"
            )
        encoded = self.response_text.encode("utf-8")
        if len(encoded) > MAX_PROVIDER_RESPONSE_BYTES:
            raise ValueError("response_text exceeds the evidence bound; truncate before hashing")
        if self.response_sha256 != hashlib.sha256(encoded).hexdigest():
            raise ValueError("response_sha256 must digest the exact recorded response text")


class ProviderLineageRecorder(Protocol):
    """Persistence seam called immediately around each physical provider send."""

    def begin_physical_attempt(
        self,
        logical_context: ProviderLogicalContextV1,
        sequence: int,
    ) -> ProviderInvocationContextV1: ...

    def finish_physical_attempt(
        self,
        invocation: ProviderInvocationContextV1,
        event: ProviderTerminalEventV1,
    ) -> ProviderTerminalEventV1: ...


__all__ = [
    "MAX_PROVIDER_RESPONSE_BYTES",
    "UNSTORABLE_TEXT_REPLACEMENT",
    "capture_response_evidence",
    "normalize_provider_observation",
    "ProviderInvocationContextV1",
    "ProviderLineageRecorder",
    "ProviderLogicalContextV1",
    "ProviderTerminalEventV1",
    "served_provider_matches_configured",
]
