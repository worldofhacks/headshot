"""Immutable, network-free authority for one four-role OpenRouter configuration set.

This module deliberately stops before activation, credential resolution, or transport construction.
It validates and content-addresses the exact hosted configuration proposed for all four agents. A
passing preflight is evidence that the configuration is internally coherent; it is never permission
to invoke a provider.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from agentforge.agents.prompts import PromptRecord, PromptRegistryError, load_prompt_registry
from agentforge.agents.runtime import AGENT_ROLES, AgentRole
from agentforge.secrets import looks_like_provider_key

HOSTED_CONFIGURATION_SCHEMA_VERSION = "2"
HOSTED_PROVIDER = "openrouter"
HOSTED_MAX_PHYSICAL_CALLS = 56
HOSTED_MAX_MEASURED_USD = Decimal("10")
HOSTED_MAX_LOGICAL_RETRIES = 1
HOSTED_MAX_CONCURRENCY = 1
HOSTED_ROLE_MODELS: Mapping[AgentRole, str] = MappingProxyType(
    {
        "orchestrator": "anthropic/claude-opus-4.8",
        "red_team": "qwen/qwen3.5-397b-a17b",
        "judge": "google/gemini-2.5-pro",
        "documentation": "openai/gpt-5.4",
    }
)
HOSTED_ROLE_MAX_MEASURED_USD: Mapping[AgentRole, Decimal] = MappingProxyType(
    {
        "orchestrator": Decimal("1.50"),
        "red_team": Decimal("1"),
        "judge": Decimal("4"),
        "documentation": Decimal("1"),
    }
)

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_MODEL_ID = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}\Z")
_UPSTREAM_PROVIDER = re.compile(r"\A[a-z0-9][a-z0-9-]{0,63}(?:/[a-z0-9][a-z0-9-]{0,63})*\Z")
_REFERENCE_AUTHORITY = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
_REFERENCE_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._~-]{0,127}\Z")
_ALIAS_MODEL_NAMES = frozenset({"auto", "default", "latest"})
_RAW_PROVIDER_KEY = re.compile(r"(?:\A|[^A-Za-z0-9])sk-(?:(?:ant|or|proj)-)?[A-Za-z0-9_-]{16,}")

_MAX_CALLS = HOSTED_MAX_PHYSICAL_CALLS
_MAX_TOKENS = 10_000_000_000
_MAX_USD = HOSTED_MAX_MEASURED_USD
_MAX_PRICE_PER_MILLION = Decimal("1000000")
_MAX_REQUESTS_PER_SECOND = Decimal("0.5")
_MAX_CONCURRENCY = HOSTED_MAX_CONCURRENCY

_ROLE_ORDER = {role: index for index, role in enumerate(AGENT_ROLES)}
CompletionTokenParameter = Literal["max_tokens", "max_completion_tokens"]
_COMPLETION_TOKEN_PARAMETERS = frozenset({"max_tokens", "max_completion_tokens"})


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _decimal_text(value: Decimal) -> str:
    """Return one representation-independent fixed-point encoding for a finite Decimal."""

    # Decimal.normalize() applies the ambient decimal context and can round authority-bound
    # values. Formatting the original Decimal is exact and context independent.
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _require_decimal(
    label: str,
    value: object,
    *,
    maximum: Decimal,
    allow_zero: bool = False,
) -> Decimal:
    if not isinstance(value, Decimal):
        raise TypeError(f"{label} must be a Decimal with explicit units")
    if not value.is_finite():
        raise ValueError(f"{label} must be finite")
    if value < 0 or (value == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise ValueError(f"{label} must be {qualifier}")
    if value > maximum:
        raise ValueError(f"{label} exceeds the closed platform maximum {maximum}")
    return value


def _require_positive_int(label: str, value: object, *, maximum: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if value <= 0:
        raise ValueError(f"{label} must be positive")
    if value > maximum:
        raise ValueError(f"{label} exceeds the closed platform maximum")
    return value


def _require_sha256(label: str, value: object) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def resolve_hosted_prompt(role: str, prompt_sha256: str) -> PromptRecord:
    """Resolve one package-owned prompt only through its configured role/hash identity.

    The staged configuration deliberately retains ``prompt_sha256`` as its authorization-bound
    wire field. The prompt version and content come only from the validated package manifest;
    callers cannot select a role-only fallback or supply prompt text.
    """

    if role not in AGENT_ROLES:
        raise ValueError("hosted prompt role is outside the exact four-role catalog")
    _require_sha256("prompt identity", prompt_sha256)
    try:
        matches = tuple(
            record
            for record in load_prompt_registry()
            if record.role == role and record.sha256 == prompt_sha256
        )
    except PromptRegistryError:
        raise ValueError(
            "configured prompt identity does not match the server-owned role prompt"
        ) from None
    if len(matches) != 1:
        raise ValueError("configured prompt identity does not match the server-owned role prompt")
    return matches[0]


def _validate_model_id(value: object) -> str:
    if not isinstance(value, str) or _MODEL_ID.fullmatch(value) is None:
        raise ValueError("model identifier must be one exact provider/model id")
    family, model_name = value.split("/", 1)
    if family == HOSTED_PROVIDER:
        raise ValueError(
            "OpenRouter routing aliases are forbidden; an exact upstream model id is required"
        )
    if model_name in _ALIAS_MODEL_NAMES or model_name.endswith(("-latest", ".latest", "_latest")):
        raise ValueError("model aliases are forbidden; an exact immutable model id is required")
    return value


def _validate_upstream_provider(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or _UPSTREAM_PROVIDER.fullmatch(value) is None
        or value in {"auto", "default", "any"}
    ):
        raise ValueError("upstream provider must be one exact OpenRouter provider slug")
    return value


def _validate_completion_token_parameter(value: object) -> CompletionTokenParameter:
    if not isinstance(value, str) or value not in _COMPLETION_TOKEN_PARAMETERS:
        raise ValueError("completion token parameter must be max_tokens or max_completion_tokens")
    return cast(CompletionTokenParameter, value)


def _validate_credential_reference(value: object) -> str:
    message = "credential reference must be an opaque secretref URI, never a raw or ambient key"
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 512
        or looks_like_provider_key(value)
        or any(character in value for character in ("%", "\\", "\x00"))
    ):
        raise ValueError(message)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(message) from exc
    segments = parsed.path.removeprefix("/").split("/")
    reference_components = (parsed.netloc, *segments)
    if (
        parsed.scheme != "secretref"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or not parsed.netloc
        or _REFERENCE_AUTHORITY.fullmatch(parsed.netloc) is None
        or parsed.query
        or parsed.fragment
        or len(segments) < 2
        or any(
            segment in {"", ".", ".."} or _REFERENCE_SEGMENT.fullmatch(segment) is None
            for segment in segments
        )
        or any(
            looks_like_provider_key(component) or _RAW_PROVIDER_KEY.search(component) is not None
            for component in reference_components
        )
    ):
        raise ValueError(message)
    return value


@dataclass(frozen=True, slots=True)
class TokenPrices:
    """Authorization-bound catalog prices, expressed exactly as Decimal USD per million tokens."""

    input_usd_per_million_tokens: Decimal
    output_usd_per_million_tokens: Decimal
    reasoning_usd_per_million_tokens: Decimal

    def __post_init__(self) -> None:
        for label, value in (
            ("input token price", self.input_usd_per_million_tokens),
            ("output token price", self.output_usd_per_million_tokens),
            ("reasoning token price", self.reasoning_usd_per_million_tokens),
        ):
            _require_decimal(label, value, maximum=_MAX_PRICE_PER_MILLION)

    def canonical_payload(self) -> dict[str, str]:
        return {
            "input_usd_per_million_tokens": _decimal_text(self.input_usd_per_million_tokens),
            "output_usd_per_million_tokens": _decimal_text(self.output_usd_per_million_tokens),
            "reasoning_usd_per_million_tokens": _decimal_text(
                self.reasoning_usd_per_million_tokens
            ),
        }


@dataclass(frozen=True, slots=True)
class HostedLimits:
    """One explicit physical-call, token, cash, retry, rate, and concurrency envelope."""

    max_calls: int
    max_input_tokens: int
    max_output_tokens: int
    max_reasoning_tokens: int
    max_usd: Decimal
    max_retries: int
    max_requests_per_second: Decimal
    max_concurrency: int

    def __post_init__(self) -> None:
        _require_positive_int("maximum calls", self.max_calls, maximum=_MAX_CALLS)
        _require_positive_int("maximum input tokens", self.max_input_tokens, maximum=_MAX_TOKENS)
        _require_positive_int("maximum output tokens", self.max_output_tokens, maximum=_MAX_TOKENS)
        _require_positive_int(
            "maximum reasoning tokens", self.max_reasoning_tokens, maximum=_MAX_TOKENS
        )
        _require_decimal("maximum USD", self.max_usd, maximum=_MAX_USD)
        if type(self.max_retries) is not int:
            raise TypeError("maximum retries must be an integer")
        if self.max_retries < 0 or self.max_retries > HOSTED_MAX_LOGICAL_RETRIES:
            raise ValueError(
                f"maximum retries must be between zero and {HOSTED_MAX_LOGICAL_RETRIES}"
            )
        rate = _require_decimal(
            "maximum requests per second",
            self.max_requests_per_second,
            maximum=_MAX_REQUESTS_PER_SECOND,
        )
        if rate > _MAX_REQUESTS_PER_SECOND:
            raise ValueError(
                f"maximum requests per second cannot exceed {_MAX_REQUESTS_PER_SECOND}"
            )
        concurrency = _require_positive_int(
            "maximum concurrency",
            self.max_concurrency,
            maximum=_MAX_CONCURRENCY,
        )
        if concurrency > _MAX_CONCURRENCY:
            raise ValueError(f"maximum concurrency cannot exceed {_MAX_CONCURRENCY}")

    def canonical_payload(self) -> dict[str, int | str]:
        return {
            "max_calls": self.max_calls,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_reasoning_tokens": self.max_reasoning_tokens,
            "max_usd": _decimal_text(self.max_usd),
            "max_retries": self.max_retries,
            "max_requests_per_second": _decimal_text(self.max_requests_per_second),
            "max_concurrency": self.max_concurrency,
        }

    @classmethod
    def from_payload(cls, payload: object) -> HostedLimits:
        if not isinstance(payload, dict) or set(payload) != {
            "max_calls",
            "max_input_tokens",
            "max_output_tokens",
            "max_reasoning_tokens",
            "max_usd",
            "max_retries",
            "max_requests_per_second",
            "max_concurrency",
        }:
            raise ValueError("hosted limits payload has an invalid shape")
        try:
            return cls(
                max_calls=payload["max_calls"],
                max_input_tokens=payload["max_input_tokens"],
                max_output_tokens=payload["max_output_tokens"],
                max_reasoning_tokens=payload["max_reasoning_tokens"],
                max_usd=Decimal(payload["max_usd"]),
                max_retries=payload["max_retries"],
                max_requests_per_second=Decimal(payload["max_requests_per_second"]),
                max_concurrency=payload["max_concurrency"],
            )
        except (ArithmeticError, TypeError, ValueError) as exc:
            raise ValueError("hosted limits payload is invalid") from exc


@dataclass(frozen=True, slots=True)
class HostedRoleConfiguration:
    """One immutable role identity and its authorization-bound provider envelope.

    ``upstream_provider`` is the exact lowercase OpenRouter routing slug sent in
    ``provider.only``. The provider display identity returned by router metadata
    is observed separately on each execution.
    """

    role: AgentRole
    provider: str
    model_id: str
    upstream_provider: str
    completion_token_parameter: CompletionTokenParameter
    credential_reference: str = field(repr=False)
    prompt_sha256: str
    policy_sha256: str
    prices: TokenPrices
    limits: HostedLimits
    configuration_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if self.role not in AGENT_ROLES:
            raise ValueError("hosted role is outside the exact four-role catalog")
        if self.provider != HOSTED_PROVIDER:
            raise ValueError("hosted provider must be openrouter")
        _validate_model_id(self.model_id)
        if self.model_id != HOSTED_ROLE_MODELS[self.role]:
            raise ValueError("hosted role model differs from the frozen recovery assignment")
        _validate_upstream_provider(self.upstream_provider)
        _validate_completion_token_parameter(self.completion_token_parameter)
        _validate_credential_reference(self.credential_reference)
        resolve_hosted_prompt(self.role, self.prompt_sha256)
        _require_sha256("policy identity", self.policy_sha256)
        if not isinstance(self.prices, TokenPrices):
            raise TypeError("hosted prices must use TokenPrices")
        if not isinstance(self.limits, HostedLimits):
            raise TypeError("hosted role limits must use HostedLimits")
        role_usd_ceiling = HOSTED_ROLE_MAX_MEASURED_USD[self.role]
        if self.limits.max_usd > role_usd_ceiling:
            raise ValueError(
                f"{self.role} measured-spend cap exceeds the closed role ceiling {role_usd_ceiling}"
            )
        object.__setattr__(
            self,
            "configuration_sha256",
            _sha256(_canonical_json(self.canonical_payload())),
        )

    @property
    def model_family(self) -> str:
        return self.model_id.split("/", 1)[0]

    @property
    def prompt_version(self) -> str:
        return resolve_hosted_prompt(self.role, self.prompt_sha256).version

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "provider": self.provider,
            "model_id": self.model_id,
            "upstream_provider": self.upstream_provider,
            "completion_token_parameter": self.completion_token_parameter,
            "credential_reference": self.credential_reference,
            "prompt_sha256": self.prompt_sha256,
            "policy_sha256": self.policy_sha256,
            "prices": self.prices.canonical_payload(),
            "limits": self.limits.canonical_payload(),
        }

    @classmethod
    def from_payload(cls, payload: object) -> HostedRoleConfiguration:
        if not isinstance(payload, dict) or set(payload) != {
            "role",
            "provider",
            "model_id",
            "upstream_provider",
            "completion_token_parameter",
            "credential_reference",
            "prompt_sha256",
            "policy_sha256",
            "prices",
            "limits",
        }:
            raise ValueError("hosted role payload has an invalid shape")
        prices = payload["prices"]
        if not isinstance(prices, dict) or set(prices) != {
            "input_usd_per_million_tokens",
            "output_usd_per_million_tokens",
            "reasoning_usd_per_million_tokens",
        }:
            raise ValueError("hosted role prices payload has an invalid shape")
        try:
            token_prices = TokenPrices(
                input_usd_per_million_tokens=Decimal(prices["input_usd_per_million_tokens"]),
                output_usd_per_million_tokens=Decimal(prices["output_usd_per_million_tokens"]),
                reasoning_usd_per_million_tokens=Decimal(
                    prices["reasoning_usd_per_million_tokens"]
                ),
            )
            return cls(
                role=payload["role"],
                provider=payload["provider"],
                model_id=payload["model_id"],
                upstream_provider=payload["upstream_provider"],
                completion_token_parameter=payload["completion_token_parameter"],
                credential_reference=payload["credential_reference"],
                prompt_sha256=payload["prompt_sha256"],
                policy_sha256=payload["policy_sha256"],
                prices=token_prices,
                limits=HostedLimits.from_payload(payload["limits"]),
            )
        except (ArithmeticError, TypeError, ValueError) as exc:
            raise ValueError("hosted role payload is invalid") from exc


def _validate_role_set(roles: tuple[HostedRoleConfiguration, ...]) -> None:
    if len(roles) != len(AGENT_ROLES) or {role.role for role in roles} != set(AGENT_ROLES):
        raise ValueError("each exact hosted agent role must appear exactly once")
    if len({role.model_id for role in roles}) != len(roles):
        raise ValueError("hosted model identifiers must be pairwise distinct")
    if len({role.credential_reference for role in roles}) != len(roles):
        raise ValueError("hosted credential references must be pairwise distinct")

    by_role = {role.role: role for role in roles}
    red_team = by_role["red_team"]
    judge = by_role["judge"]
    if red_team.model_family == judge.model_family:
        raise ValueError("Judge and Red Team must use independent model families")
    if red_team.prompt_sha256 == judge.prompt_sha256:
        raise ValueError("Judge and Red Team must use independent prompt identities")
    if red_team.policy_sha256 == judge.policy_sha256:
        raise ValueError("Judge and Red Team must use independent policy identities")


@dataclass(frozen=True, slots=True)
class HostedConfigurationSet:
    """All four staged OpenRouter roles, canonically ordered and content-addressed as one unit."""

    roles: tuple[HostedRoleConfiguration, ...]
    global_limits: HostedLimits
    schema_version: str = HOSTED_CONFIGURATION_SCHEMA_VERSION
    configuration_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if self.schema_version != HOSTED_CONFIGURATION_SCHEMA_VERSION:
            raise ValueError("hosted configuration schema version is unsupported")
        if not isinstance(self.roles, tuple) or any(
            not isinstance(role, HostedRoleConfiguration) for role in self.roles
        ):
            raise TypeError("hosted roles must be a tuple of HostedRoleConfiguration values")
        if not isinstance(self.global_limits, HostedLimits):
            raise TypeError("global hosted limits must use HostedLimits")
        _validate_role_set(self.roles)
        for role in self.roles:
            if role.limits.max_calls > self.global_limits.max_calls:
                raise ValueError("role call cap cannot exceed the shared physical-call cap")
            if role.limits.max_usd > self.global_limits.max_usd:
                raise ValueError("role cash cap cannot exceed the shared measured-spend cap")
        ordered = tuple(sorted(self.roles, key=lambda item: _ROLE_ORDER[item.role]))
        object.__setattr__(self, "roles", ordered)
        object.__setattr__(self, "configuration_sha256", _sha256(self.canonical_bytes()))

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "roles": [role.canonical_payload() for role in self.roles],
            "global_limits": self.global_limits.canonical_payload(),
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.canonical_payload())

    @classmethod
    def from_payload(cls, payload: object) -> HostedConfigurationSet:
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "roles",
            "global_limits",
        }:
            raise ValueError("hosted configuration-set payload has an invalid shape")
        roles = payload["roles"]
        if not isinstance(roles, list):
            raise ValueError("hosted configuration-set roles must be a list")
        return cls(
            schema_version=payload["schema_version"],
            roles=tuple(HostedRoleConfiguration.from_payload(role) for role in roles),
            global_limits=HostedLimits.from_payload(payload["global_limits"]),
        )


@dataclass(frozen=True, slots=True)
class HostedRolePreflight:
    """Secret-free identity projection for one validated role."""

    role: AgentRole
    provider: str
    model_id: str
    upstream_provider: str
    completion_token_parameter: CompletionTokenParameter
    role_configuration_sha256: str
    credential_reference_sha256: str


@dataclass(frozen=True, slots=True)
class HostedConfigurationPreflight:
    """A zero-I/O validation result; passing it does not activate or authorize provider calls."""

    ok: bool
    schema_version: str
    configuration_sha256: str
    global_limits_sha256: str
    roles: tuple[HostedRolePreflight, ...]
    authorization_required: bool = True


def validate_hosted_configuration_set(configuration: HostedConfigurationSet) -> None:
    """Recompute all identities and fail closed on type, content, or stored-hash drift."""

    if not isinstance(configuration, HostedConfigurationSet):
        raise TypeError("hosted configuration must use HostedConfigurationSet")
    _validate_role_set(configuration.roles)
    for role in configuration.roles:
        expected_role_hash = _sha256(_canonical_json(role.canonical_payload()))
        if role.configuration_sha256 != expected_role_hash:
            raise ValueError("hosted role configuration hash does not match its content")
    expected_set_hash = _sha256(configuration.canonical_bytes())
    if configuration.configuration_sha256 != expected_set_hash:
        raise ValueError("hosted configuration-set hash does not match its content")


def preflight_hosted_configuration_set(
    configuration: HostedConfigurationSet,
) -> HostedConfigurationPreflight:
    """Validate and project one set without environment reads, secret resolution, or I/O."""

    validate_hosted_configuration_set(configuration)
    roles = tuple(
        HostedRolePreflight(
            role=role.role,
            provider=role.provider,
            model_id=role.model_id,
            upstream_provider=role.upstream_provider,
            completion_token_parameter=role.completion_token_parameter,
            role_configuration_sha256=role.configuration_sha256,
            credential_reference_sha256=_sha256(
                b"hosted-credential-reference-v1\0" + role.credential_reference.encode("utf-8")
            ),
        )
        for role in configuration.roles
    )
    return HostedConfigurationPreflight(
        ok=True,
        schema_version=configuration.schema_version,
        configuration_sha256=configuration.configuration_sha256,
        global_limits_sha256=_sha256(
            _canonical_json(configuration.global_limits.canonical_payload())
        ),
        roles=roles,
    )


__all__ = [
    "HOSTED_CONFIGURATION_SCHEMA_VERSION",
    "HOSTED_MAX_CONCURRENCY",
    "HOSTED_MAX_LOGICAL_RETRIES",
    "HOSTED_MAX_MEASURED_USD",
    "HOSTED_MAX_PHYSICAL_CALLS",
    "HOSTED_PROVIDER",
    "HOSTED_ROLE_MAX_MEASURED_USD",
    "HOSTED_ROLE_MODELS",
    "CompletionTokenParameter",
    "HostedConfigurationPreflight",
    "HostedConfigurationSet",
    "HostedLimits",
    "HostedRoleConfiguration",
    "HostedRolePreflight",
    "TokenPrices",
    "preflight_hosted_configuration_set",
    "resolve_hosted_prompt",
    "validate_hosted_configuration_set",
]
