"""Immutable target-domain definitions for trusted registry configuration.

This module is the framework-neutral vocabulary for target and attack-surface identity.  It
contains no transport implementation, dynamic import, credential value, or network operation.
All routing facts are immutable references that trusted runtime code can bind into one canonical
authorization scope before any dispatch.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, replace
from decimal import Decimal
from enum import StrEnum
from urllib.parse import urlsplit

_IDENTIFIER_RE = re.compile(r"\A[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_VERSION_RE = re.compile(r"\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REFERENCE_RE = re.compile(r"\A[a-z][a-z0-9+.-]*://[^\s\x00-\x1f\x7f]+\Z")
_HOST_LABEL_RE = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_METHOD_RE = re.compile(r"\A[A-Z][A-Z0-9_-]{0,31}\Z")
_CORPUS_HASH_RE = re.compile(r"\A[a-f0-9]{64}\Z")
_RUN_NONCE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{15,127}\Z")
_SESSION_GENERATION_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_RELATIVE_SEGMENT_RE = re.compile(r"\A[A-Za-z0-9._~-]+\Z")
# A single path-parameter placeholder segment, e.g. ``{document_id}``. The name grammar is the
# strict lowercase identifier used elsewhere so a template can never smuggle traversal, a second
# authority, or URL-override syntax through a parameter name.
_PATH_PARAM_RE = re.compile(r"\A\{[a-z][a-z0-9_]*\}\Z")
_MEDIA_TYPE_RE = re.compile(r"\A[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,127}\Z")
_FORWARD_TRANSITIONS: dict[TargetLifecycle, TargetLifecycle] = {}
_SURFACE_POLICY_SCHEMA = "agentforge.target-surface-policy"
_SURFACE_POLICY_SCHEMA_VERSION = 2
_MAX_RESPONSE_SIZE_BYTES = 10_485_760
_MAX_REQUEST_TIMEOUT_SECONDS = 120.0


class DefinitionError(ValueError):
    """A typed, fail-closed definition or canonical-scope validation failure."""


class TargetEnvironment(StrEnum):
    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"


class ExecutionProfile(StrEnum):
    """Closed execution modes bound into every campaign authorization hash."""

    SYNTHETIC = "synthetic"
    LIVE = "live"


class AuthMode(StrEnum):
    NONE = "none"
    BEARER = "bearer"
    SESSION = "session"
    OAUTH = "oauth"


class TargetLifecycle(StrEnum):
    DRAFT = "draft"
    VALIDATING = "validating"
    READY = "ready"
    DISABLED = "disabled"
    ARCHIVED = "archived"


_FORWARD_TRANSITIONS.update(
    {
        TargetLifecycle.DRAFT: TargetLifecycle.VALIDATING,
        TargetLifecycle.VALIDATING: TargetLifecycle.READY,
        TargetLifecycle.READY: TargetLifecycle.DISABLED,
        TargetLifecycle.DISABLED: TargetLifecycle.ARCHIVED,
    }
)


class SurfaceKind(StrEnum):
    CHAT = "chat"
    COMPLETION = "completion"
    RESPONSES = "responses"
    MESSAGES = "messages"
    TOOL = "tool"
    RAG = "rag"
    MEMORY = "memory"
    FILE = "file"
    ACTION = "action"
    CUSTOM = "custom"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _coerce_enum(value: object, enum_type: type[StrEnum], field: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise DefinitionError(f"{field} is not an allowed value") from exc


def _require_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise DefinitionError(f"{field} must be a stable lowercase identifier")
    return value


def _require_version(value: object, field: str = "version") -> str:
    if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
        raise DefinitionError(f"{field} must be a semantic version")
    return value


def _version_key(value: str) -> tuple[int, int, int]:
    _require_version(value)
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _requires_surface_policy(target_version: str) -> bool:
    """Whether a target version uses the schema-v2 per-surface policy contract."""

    return _version_key(target_version)[0] == 2


def _require_text(value: object, field: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DefinitionError(f"{field} must be non-empty bounded text")
    return value


def _require_reference(value: object, field: str) -> str:
    if not isinstance(value, str) or _REFERENCE_RE.fullmatch(value) is None or ".." in value:
        raise DefinitionError(f"{field} must be an opaque reference, never an inline value")
    return value


def _require_credential_reference(value: object) -> str:
    reference = _require_reference(value, "credential reference")
    if "%" in reference or "\\" in reference:
        raise DefinitionError("credential reference must use canonical unencoded segments")
    parts = urlsplit(reference)
    if (
        parts.scheme != "secretref"
        or _IDENTIFIER_RE.fullmatch(parts.netloc) is None
        or not parts.path.startswith("/")
    ):
        raise DefinitionError("credential reference must be a non-empty secretref:// handle")
    segments = parts.path[1:].split("/")
    if any(
        not segment or segment in {".", ".."} or _RELATIVE_SEGMENT_RE.fullmatch(segment) is None
        for segment in segments
    ):
        raise DefinitionError("credential reference must use canonical non-traversing segments")
    if parts.query or parts.fragment or parts.username or parts.password:
        raise DefinitionError("credential reference must be an opaque secretref:// handle")
    canonical = f"secretref://{parts.netloc}/{'/'.join(segments)}"
    if reference != canonical:
        raise DefinitionError("credential reference must have one byte-exact canonical form")
    return reference


def _require_host(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise DefinitionError("allowlisted host must be a non-empty exact host")
    lowered = value.lower()
    if any(character in lowered for character in "/\\@?#*\x00"):
        raise DefinitionError("allowlisted host must not contain URL or wildcard syntax")
    hostname, separator, port_text = lowered.rpartition(":")
    if separator and port_text.isdigit() and "." in hostname:
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise DefinitionError("allowlisted host has an invalid port")
        host_only = hostname
    else:
        host_only = lowered
    if host_only.endswith(".") or len(host_only) > 253:
        raise DefinitionError("allowlisted host is not canonical")
    labels = host_only.split(".")
    if any(_HOST_LABEL_RE.fullmatch(label) is None for label in labels):
        raise DefinitionError("allowlisted host is not a valid exact DNS host")
    return lowered


def _validate_base_url(value: object) -> tuple[str, str]:
    url = _require_text(value, "base_url", maximum=2048)
    if "%" in url or "\\" in url:
        raise DefinitionError("base_url must use canonical unencoded URL syntax")
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise DefinitionError("base_url has an invalid port") from exc
    if not url.startswith("https://") or parts.scheme != "https" or not parts.hostname:
        raise DefinitionError("base_url must be an exact HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise DefinitionError("base_url must not contain user information")
    if parts.query or parts.fragment:
        raise DefinitionError("base_url must not contain a query or fragment")
    host = parts.hostname.lower()
    authority = host if port is None else f"{host}:{port}"
    _require_host(authority)
    if parts.netloc != authority:
        raise DefinitionError("base_url authority must have one exact canonical form")
    if parts.path not in {"", "/"}:
        if not parts.path.startswith("/"):
            raise DefinitionError("base_url path must be absolute within its exact host")
        segments = parts.path[1:].split("/")
        if any(
            not segment or segment in {".", ".."} or _RELATIVE_SEGMENT_RE.fullmatch(segment) is None
            for segment in segments
        ):
            raise DefinitionError("base_url path must use canonical non-traversing segments")
    if url != f"https://{authority}{parts.path}":
        raise DefinitionError("base_url must have one exact canonical form")
    return url, authority


def _normalize_references(values: object, field: str) -> tuple[str, ...]:
    if not isinstance(values, (tuple, list)):
        raise DefinitionError(f"{field} must be a sequence of opaque references")
    normalized = tuple(_require_reference(value, field) for value in values)
    if len(set(normalized)) != len(normalized):
        raise DefinitionError(f"{field} must not contain duplicates")
    return normalized


def validate_relative_path(value: object) -> str:
    """Validate a trusted endpoint path relative to a target base URL.

    Percent encoding and URL-like syntax are rejected rather than normalized, removing the
    ambiguity that otherwise enables traversal or a second authority after a later decode.
    """

    path = _require_text(value, "relative path", maximum=1024)
    if path.startswith(("/", "\\")) or any(token in path for token in ("%", "\\", "?", "#")):
        raise DefinitionError("relative path must not be absolute or contain URL override syntax")
    parts = urlsplit(path)
    if parts.scheme or parts.netloc or parts.query or parts.fragment:
        raise DefinitionError("relative path must not contain a scheme, host, query, or fragment")
    segments = path.split("/")
    if any(not _relative_segment_is_valid(segment) for segment in segments):
        raise DefinitionError("relative path contains empty, traversal, or invalid segments")
    parameters = [segment[1:-1] for segment in segments if _PATH_PARAM_RE.fullmatch(segment)]
    if len(set(parameters)) != len(parameters):
        raise DefinitionError("relative path must not repeat a parameter name")
    return path


def _relative_segment_is_valid(segment: str) -> bool:
    """A path segment is a literal token OR exactly one ``{name}`` parameter placeholder.

    Traversal (``.`` / ``..``), empty, and mixed literal+parameter segments (``x{id}``) are all
    refused, so a template never resolves to a second authority or a traversal after substitution.
    """

    if not segment or segment in {".", ".."}:
        return False
    return (
        _RELATIVE_SEGMENT_RE.fullmatch(segment) is not None
        or _PATH_PARAM_RE.fullmatch(segment) is not None
    )


def relative_path_parameters(value: str) -> tuple[str, ...]:
    """Ordered names of the ``{param}`` placeholders in a validated relative path.

    Returns ``()`` for a fully static path. The trusted dispatch boundary substitutes exactly
    these names from the authorized attempt; an unfilled or unknown parameter is a fail-closed
    dispatch error, never a partially-templated URL sent to the target.
    """

    return tuple(
        segment[1:-1]
        for segment in value.split("/")
        if _PATH_PARAM_RE.fullmatch(segment) is not None
    )


def _finite_positive(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DefinitionError(f"{field} must be a finite positive number")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0:
        raise DefinitionError(f"{field} must be a finite positive number")
    return numeric


def _require_positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DefinitionError(f"{field} must be a positive integer")
    return value


def _require_nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DefinitionError(f"{field} must be a non-negative integer")
    return value


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or _CORPUS_HASH_RE.fullmatch(value) is None:
        raise DefinitionError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_media_type(value: object, field: str) -> str:
    if not isinstance(value, str) or _MEDIA_TYPE_RE.fullmatch(value) is None:
        raise DefinitionError(f"{field} must be a canonical media type")
    return value


def _require_fixture_reference(value: object) -> str:
    reference = _require_reference(value, "fixture opaque reference")
    if "%" in reference or "\\" in reference:
        raise DefinitionError("fixture opaque reference must use canonical unencoded segments")
    parts = urlsplit(reference)
    if (
        parts.scheme != "fixture"
        or _IDENTIFIER_RE.fullmatch(parts.netloc) is None
        or not parts.path.startswith("/")
        or parts.query
        or parts.fragment
        or parts.username is not None
        or parts.password is not None
    ):
        raise DefinitionError("fixture opaque reference must be a path-free fixture:// handle")
    segments = parts.path[1:].split("/")
    if any(
        not segment or segment in {".", ".."} or _RELATIVE_SEGMENT_RE.fullmatch(segment) is None
        for segment in segments
    ):
        raise DefinitionError("fixture opaque reference must use canonical immutable segments")
    canonical = f"fixture://{parts.netloc}/{'/'.join(segments)}"
    if reference != canonical:
        raise DefinitionError("fixture opaque reference must have one byte-exact canonical form")
    return reference


@dataclass(frozen=True, slots=True)
class SafetyCaps:
    """Target-specific maxima that an authorized run scope may only narrow."""

    budget_usd: float
    max_attempts_per_run: int
    target_requests_per_second: float
    run_timeout_seconds: float
    logical_case_limit: int | None = None
    physical_request_limit: int | None = None
    target_retries_per_turn: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "budget_usd", _finite_positive(self.budget_usd, "budget_usd"))
        attempts = self.max_attempts_per_run
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
            raise DefinitionError("max_attempts_per_run must be a positive integer")
        for field in ("logical_case_limit", "physical_request_limit"):
            value = getattr(self, field)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
            ):
                raise DefinitionError(f"{field} must be a positive integer when declared")
        retries = self.target_retries_per_turn
        if retries is not None and (
            isinstance(retries, bool) or not isinstance(retries, int) or retries < 0
        ):
            raise DefinitionError(
                "target_retries_per_turn must be a non-negative integer when declared"
            )
        object.__setattr__(
            self,
            "target_requests_per_second",
            _finite_positive(self.target_requests_per_second, "target_requests_per_second"),
        )
        object.__setattr__(
            self,
            "run_timeout_seconds",
            _finite_positive(self.run_timeout_seconds, "run_timeout_seconds"),
        )

    def canonical_payload(self) -> dict[str, float | int]:
        payload: dict[str, float | int] = {
            "budget_usd": self.budget_usd,
            "max_attempts_per_run": self.max_attempts_per_run,
            "target_requests_per_second": self.target_requests_per_second,
            "run_timeout_seconds": self.run_timeout_seconds,
        }
        if self.logical_case_limit is not None:
            payload["logical_case_limit"] = self.logical_case_limit
        if self.physical_request_limit is not None:
            payload["physical_request_limit"] = self.physical_request_limit
        if self.target_retries_per_turn is not None:
            payload["target_retries_per_turn"] = self.target_retries_per_turn
        return payload

    def is_within(self, maximum: SafetyCaps) -> bool:
        legacy_within = (
            self.budget_usd <= maximum.budget_usd
            and self.max_attempts_per_run <= maximum.max_attempts_per_run
            and self.target_requests_per_second <= maximum.target_requests_per_second
            and self.run_timeout_seconds <= maximum.run_timeout_seconds
        )
        if not legacy_within:
            return False
        for field in (
            "logical_case_limit",
            "physical_request_limit",
            "target_retries_per_turn",
        ):
            requested = getattr(self, field)
            trusted_maximum = getattr(maximum, field)
            if trusted_maximum is None:
                if requested is not None:
                    return False
                continue
            if requested is None or requested > trusted_maximum:
                return False
        return True


@dataclass(frozen=True, slots=True)
class HostedRunBinding:
    """Non-secret four-model authority included in the campaign scope hash."""

    configuration_set_sha256: str
    generation_policy_sha256: str
    session_generation: str
    provider_model_call_limit: int
    provider_model_spend_limit_usd: str
    provider_max_retries: int
    provider_max_concurrency: int
    provider_timeout_seconds: float

    def __post_init__(self) -> None:
        for field, value in (
            ("configuration_set_sha256", self.configuration_set_sha256),
            ("generation_policy_sha256", self.generation_policy_sha256),
        ):
            if not isinstance(value, str) or _CORPUS_HASH_RE.fullmatch(value) is None:
                raise DefinitionError(f"{field} must be a lowercase SHA-256 digest")
        if (
            not isinstance(self.session_generation, str)
            or _SESSION_GENERATION_RE.fullmatch(self.session_generation) is None
        ):
            raise DefinitionError("session_generation must be a non-secret immutable generation")
        if (
            type(self.provider_model_call_limit) is not int
            or not 1 <= self.provider_model_call_limit <= 56
        ):
            raise DefinitionError("provider_model_call_limit must be between 1 and 56")
        try:
            spend = Decimal(self.provider_model_spend_limit_usd)
        except (ArithmeticError, TypeError, ValueError) as exc:
            raise DefinitionError(
                "provider_model_spend_limit_usd must be exact decimal text"
            ) from exc
        if (
            not spend.is_finite()
            or spend <= 0
            or spend > Decimal("5")
            or self.provider_model_spend_limit_usd != format(spend, "f")
        ):
            raise DefinitionError(
                "provider_model_spend_limit_usd must be canonical decimal text at most 5"
            )
        if type(self.provider_max_retries) is not int or not 0 <= self.provider_max_retries <= 1:
            raise DefinitionError("provider_max_retries must be zero or one")
        if self.provider_max_concurrency != 1:
            raise DefinitionError("provider_max_concurrency must be exactly one")
        _finite_positive(self.provider_timeout_seconds, "provider_timeout_seconds")

    def canonical_payload(self) -> dict[str, object]:
        return {
            "configuration_set_sha256": self.configuration_set_sha256,
            "generation_policy_sha256": self.generation_policy_sha256,
            "session_generation": self.session_generation,
            "provider_model_call_limit": self.provider_model_call_limit,
            "provider_model_spend_limit_usd": self.provider_model_spend_limit_usd,
            "provider_max_retries": self.provider_max_retries,
            "provider_max_concurrency": self.provider_max_concurrency,
            "provider_timeout_seconds": self.provider_timeout_seconds,
        }


@dataclass(frozen=True, slots=True)
class OwaspMapping:
    framework: str
    version: str
    identifier: str
    name: str

    def __post_init__(self) -> None:
        allowed = {"OWASP Web": "2021", "OWASP LLM": "2025"}
        if allowed.get(self.framework) != self.version:
            raise DefinitionError("OWASP mapping must use the anchored framework version")
        identifier_pattern = (
            r"A(?:0[1-9]|10)" if self.framework == "OWASP Web" else r"LLM(?:0[1-9]|10)"
        )
        if re.fullmatch(identifier_pattern, self.identifier) is None:
            raise DefinitionError("OWASP mapping identifier is invalid for its framework")
        _require_text(self.name, "OWASP mapping name", maximum=160)

    def canonical_payload(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "version": self.version,
            "id": self.identifier,
            "name": self.name,
        }


@dataclass(frozen=True, slots=True)
class FixtureDescriptor:
    """Immutable identity for a Runner-owned synthetic fixture.

    The descriptor is authorization metadata only.  It deliberately cannot carry a filesystem
    path, mutable URL, fixture bytes, or any other locator that could escape the later trusted
    fixture-binding boundary.
    """

    opaque_ref: str
    sha256: str
    byte_length: int
    media_type: str
    doc_type: str
    workflow_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "opaque_ref", _require_fixture_reference(self.opaque_ref))
        object.__setattr__(self, "sha256", _require_sha256(self.sha256, "fixture sha256"))
        object.__setattr__(
            self,
            "byte_length",
            _require_positive_integer(self.byte_length, "fixture byte_length"),
        )
        object.__setattr__(
            self,
            "media_type",
            _require_media_type(self.media_type, "fixture media_type"),
        )
        object.__setattr__(self, "doc_type", _require_identifier(self.doc_type, "doc_type"))
        object.__setattr__(
            self,
            "workflow_id",
            _require_identifier(self.workflow_id, "workflow_id"),
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "opaque_ref": self.opaque_ref,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
            "media_type": self.media_type,
            "doc_type": self.doc_type,
            "workflow_id": self.workflow_id,
        }


@dataclass(frozen=True, slots=True)
class SurfaceOperationTemplate:
    """One typed, bounded operation admitted by a canonical surface policy."""

    operation_class: str
    method: str
    relative_path: str
    request_content_type: str | None
    response_content_types: tuple[str, ...]
    credential_placement: str
    credential_field_name: str | None
    retry_count: int
    maximum_logical_operations: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "operation_class",
            _require_identifier(self.operation_class, "operation_class"),
        )
        if not isinstance(self.method, str) or _METHOD_RE.fullmatch(self.method) is None:
            raise DefinitionError("operation method must be an uppercase protocol method")
        object.__setattr__(self, "relative_path", validate_relative_path(self.relative_path))
        if self.request_content_type is not None:
            object.__setattr__(
                self,
                "request_content_type",
                _require_media_type(
                    self.request_content_type,
                    "operation request_content_type",
                ),
            )
        if (
            not isinstance(self.response_content_types, (tuple, list))
            or not self.response_content_types
        ):
            raise DefinitionError("operation response_content_types must be non-empty")
        response_types = tuple(
            _require_media_type(value, "operation response_content_types")
            for value in self.response_content_types
        )
        if len(set(response_types)) != len(response_types):
            raise DefinitionError("operation response_content_types must not contain duplicates")
        object.__setattr__(self, "response_content_types", response_types)

        allowed_placements = {"json", "query", "multipart", "none"}
        if (
            not isinstance(self.credential_placement, str)
            or self.credential_placement not in allowed_placements
        ):
            raise DefinitionError("operation credential_placement is not allowed")
        if self.credential_placement == "none":
            if self.credential_field_name is not None:
                raise DefinitionError("credential-free operation cannot name a credential field")
        elif self.credential_field_name is None:
            raise DefinitionError("credential-bearing operation requires an exact field name")
        else:
            object.__setattr__(
                self,
                "credential_field_name",
                _require_identifier(
                    self.credential_field_name,
                    "credential_field_name",
                ),
            )
        object.__setattr__(
            self,
            "retry_count",
            _require_nonnegative_integer(self.retry_count, "operation retry_count"),
        )
        object.__setattr__(
            self,
            "maximum_logical_operations",
            _require_positive_integer(
                self.maximum_logical_operations,
                "operation maximum_logical_operations",
            ),
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "operation_class": self.operation_class,
            "method": self.method,
            "relative_path": self.relative_path,
            "request_content_type": self.request_content_type,
            "response_content_types": list(self.response_content_types),
            "credential_placement": self.credential_placement,
            "credential_field_name": self.credential_field_name,
            "retry_count": self.retry_count,
            "maximum_logical_operations": self.maximum_logical_operations,
        }


_EXACT_OPERATION_CREDENTIALS: dict[str, tuple[str, str | None]] = {
    "chat": ("json", "session_id"),
    "ui_shell": ("query", "sid"),
    "evidence_search": ("none", None),
    "upload": ("multipart", "session_id"),
    "duplicate_check": ("multipart", "session_id"),
    "status_poll": ("query", "session_id"),
    "report": ("query", "session_id"),
    "preview": ("query", "session_id"),
    "readback": ("query", "session_id"),
}
_DOCUMENT_OPERATION_CLASSES = frozenset(
    {
        "upload",
        "duplicate_check",
        "status_poll",
        "report",
        "preview",
        "readback",
    }
)
_DOCUMENT_UPLOAD_OPERATION_CLASSES = frozenset({"upload", "duplicate_check"})
_DOCUMENT_READ_OPERATION_CLASSES = _DOCUMENT_OPERATION_CLASSES - _DOCUMENT_UPLOAD_OPERATION_CLASSES
_DOCUMENT_WORKFLOW_OPERATION_CONTRACTS = {
    frozenset({"upload", "status_poll", "report", "preview", "readback"}): {
        "upload": (1, 0),
        "status_poll": (30, 1),
        "report": (1, 1),
        "preview": (1, 1),
        "readback": (1, 1),
    },
    frozenset({"upload", "duplicate_check"}): {
        "upload": (1, 0),
        "duplicate_check": (1, 0),
    },
}
_SESSION_OPERATION_CLASSES = frozenset(_EXACT_OPERATION_CREDENTIALS) - {"evidence_search"}


@dataclass(frozen=True, slots=True)
class SurfacePolicy:
    """Canonical per-surface transport and authorization contract (schema v2)."""

    schema: str
    schema_version: int
    adapter_profile: str
    auth_mode: AuthMode
    credential_ref: str | None
    explicit_no_auth: bool
    redirect_policy: str
    response_size_limit_bytes: int
    request_timeout_seconds: float
    tls_required: bool
    operation_templates: tuple[SurfaceOperationTemplate, ...]
    maximum_logical_operations: int
    physical_request_limit: int
    fixture_descriptors: tuple[FixtureDescriptor, ...]

    def __post_init__(self) -> None:
        if self.schema != _SURFACE_POLICY_SCHEMA:
            raise DefinitionError("surface policy schema is not supported")
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SURFACE_POLICY_SCHEMA_VERSION
        ):
            raise DefinitionError("surface policy schema_version must be exactly 2")
        object.__setattr__(
            self,
            "adapter_profile",
            _require_identifier(self.adapter_profile, "adapter_profile"),
        )
        auth_mode = _coerce_enum(self.auth_mode, AuthMode, "surface policy auth_mode")
        object.__setattr__(self, "auth_mode", auth_mode)
        if not isinstance(self.explicit_no_auth, bool):
            raise DefinitionError("surface policy explicit_no_auth must be a boolean")
        if auth_mode is AuthMode.NONE:
            if not self.explicit_no_auth or self.credential_ref is not None:
                raise DefinitionError("no-auth surface policy must be explicit and credential-free")
        else:
            if self.explicit_no_auth or self.credential_ref is None:
                raise DefinitionError(
                    "authenticated surface policy requires its credential reference"
                )
            object.__setattr__(
                self,
                "credential_ref",
                _require_credential_reference(self.credential_ref),
            )
        if self.redirect_policy != "deny":
            raise DefinitionError("surface policy redirects must be denied")
        if (
            isinstance(self.response_size_limit_bytes, bool)
            or not isinstance(self.response_size_limit_bytes, int)
            or not 1 <= self.response_size_limit_bytes <= _MAX_RESPONSE_SIZE_BYTES
        ):
            raise DefinitionError("surface policy response_size_limit_bytes is invalid")
        timeout = _finite_positive(
            self.request_timeout_seconds,
            "surface policy request_timeout_seconds",
        )
        if timeout > _MAX_REQUEST_TIMEOUT_SECONDS:
            raise DefinitionError("surface policy request timeout exceeds its hard maximum")
        object.__setattr__(self, "request_timeout_seconds", timeout)
        if self.tls_required is not True:
            raise DefinitionError("surface policy must require TLS")

        if not isinstance(self.operation_templates, (tuple, list)) or not self.operation_templates:
            raise DefinitionError("surface policy requires typed operation templates")
        operations = tuple(self.operation_templates)
        if any(not isinstance(operation, SurfaceOperationTemplate) for operation in operations):
            raise DefinitionError(
                "surface policy operation_templates must be validated operation values"
            )
        operation_classes = tuple(operation.operation_class for operation in operations)
        if len(set(operation_classes)) != len(operation_classes):
            raise DefinitionError("surface policy operation classes must not be duplicated")
        object.__setattr__(self, "operation_templates", operations)

        logical_maximum = sum(operation.maximum_logical_operations for operation in operations)
        physical_maximum = sum(
            operation.maximum_logical_operations * (operation.retry_count + 1)
            for operation in operations
        )
        supplied_logical = _require_positive_integer(
            self.maximum_logical_operations,
            "surface policy maximum_logical_operations",
        )
        supplied_physical = _require_positive_integer(
            self.physical_request_limit,
            "surface policy physical_request_limit",
        )
        if supplied_logical != logical_maximum:
            raise DefinitionError(
                "surface policy maximum_logical_operations must equal its operation sum"
            )
        if supplied_physical != physical_maximum:
            raise DefinitionError("surface policy physical_request_limit must include every retry")

        if not isinstance(self.fixture_descriptors, (tuple, list)):
            raise DefinitionError("surface policy fixture_descriptors must be a sequence")
        descriptors = tuple(self.fixture_descriptors)
        if any(not isinstance(descriptor, FixtureDescriptor) for descriptor in descriptors):
            raise DefinitionError(
                "surface policy fixture_descriptors must be validated descriptors"
            )
        opaque_refs = tuple(descriptor.opaque_ref for descriptor in descriptors)
        if len(set(opaque_refs)) != len(opaque_refs):
            raise DefinitionError("surface policy fixture refs must not be duplicated")
        object.__setattr__(self, "fixture_descriptors", descriptors)
        self._validate_operation_contract()

    def _validate_operation_contract(self) -> None:
        operations = self.operation_templates
        operation_classes = {operation.operation_class for operation in operations}

        if "chat" in operation_classes and operation_classes != {"chat"}:
            raise DefinitionError("chat must be the only operation in its surface policy")
        if "evidence_search" in operation_classes and operation_classes != {"evidence_search"}:
            raise DefinitionError(
                "anonymous evidence search must be the only operation in its surface policy"
            )
        if operation_classes.intersection(_DOCUMENT_OPERATION_CLASSES):
            expected_contract = _DOCUMENT_WORKFLOW_OPERATION_CONTRACTS.get(
                frozenset(operation_classes)
            )
            actual_contract = {
                operation.operation_class: (
                    operation.maximum_logical_operations,
                    operation.retry_count,
                )
                for operation in operations
            }
            if expected_contract is None or actual_contract != expected_contract:
                raise DefinitionError(
                    "document surface policy requires one complete canonical workflow"
                )

        if "evidence_search" in operation_classes:
            if self.auth_mode is not AuthMode.NONE:
                raise DefinitionError("evidence surface policy must be explicitly anonymous")
        elif (
            operation_classes.intersection(_SESSION_OPERATION_CLASSES)
            and self.auth_mode is not AuthMode.SESSION
        ):
            raise DefinitionError("session-bound operation classes require session auth")

        for operation in operations:
            expected_credential = _EXACT_OPERATION_CREDENTIALS.get(operation.operation_class)
            if (
                expected_credential is not None
                and (
                    operation.credential_placement,
                    operation.credential_field_name,
                )
                != expected_credential
            ):
                raise DefinitionError(
                    "operation credential placement or exact field name is not canonical"
                )
            if self.auth_mode is AuthMode.NONE:
                if (
                    operation.credential_placement != "none"
                    or operation.credential_field_name is not None
                ):
                    raise DefinitionError("anonymous surface operations cannot place a credential")
            elif operation.credential_placement == "none":
                raise DefinitionError(
                    "authenticated surface operations require credential placement"
                )

            if operation.operation_class in _DOCUMENT_UPLOAD_OPERATION_CLASSES:
                if operation.retry_count != 0:
                    raise DefinitionError("state-changing document uploads cannot be retried")
            elif (
                operation.operation_class in _DOCUMENT_READ_OPERATION_CLASSES
                and operation.retry_count > 1
            ):
                raise DefinitionError("document poll and read operations permit at most one retry")

        has_upload = bool(operation_classes.intersection(_DOCUMENT_UPLOAD_OPERATION_CLASSES))
        if has_upload and not self.fixture_descriptors:
            raise DefinitionError("upload surface policy requires a complete fixture descriptor")
        if self.fixture_descriptors and not operation_classes.intersection(
            _DOCUMENT_OPERATION_CLASSES
        ):
            raise DefinitionError(
                "fixture descriptors are valid only for document workflow policies"
            )

    def canonical_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "adapter_profile": self.adapter_profile,
            "auth_mode": self.auth_mode.value,
            "credential_ref": self.credential_ref,
            "explicit_no_auth": self.explicit_no_auth,
            "redirect_policy": self.redirect_policy,
            "response_size_limit_bytes": self.response_size_limit_bytes,
            "request_timeout_seconds": self.request_timeout_seconds,
            "tls_required": self.tls_required,
            "operation_templates": [
                operation.canonical_payload() for operation in self.operation_templates
            ],
            "maximum_logical_operations": self.maximum_logical_operations,
            "physical_request_limit": self.physical_request_limit,
            "fixture_descriptors": [
                descriptor.canonical_payload() for descriptor in self.fixture_descriptors
            ],
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_payload(),
            allow_nan=False,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def policy_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class TargetDefinition:
    target_id: str
    name: str
    version: str
    adapter_kind: str
    environment: TargetEnvironment
    base_url: str
    allowlisted_hosts: tuple[str, ...]
    auth_mode: AuthMode
    credential_ref: str | None
    synthetic_data_only: bool
    synthetic_data_attestation_ref: str
    canary_refs: tuple[str, ...]
    oracle_refs: tuple[str, ...]
    safety_caps: SafetyCaps
    lifecycle: TargetLifecycle = TargetLifecycle.DRAFT

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_id", _require_identifier(self.target_id, "target_id"))
        object.__setattr__(self, "name", _require_text(self.name, "name"))
        object.__setattr__(self, "version", _require_version(self.version))
        object.__setattr__(
            self, "adapter_kind", _require_identifier(self.adapter_kind, "adapter_kind")
        )
        environment = _coerce_enum(self.environment, TargetEnvironment, "environment")
        auth_mode = _coerce_enum(self.auth_mode, AuthMode, "auth_mode")
        lifecycle = _coerce_enum(self.lifecycle, TargetLifecycle, "lifecycle")
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "auth_mode", auth_mode)
        object.__setattr__(self, "lifecycle", lifecycle)
        base_url, exact_host = _validate_base_url(self.base_url)
        object.__setattr__(self, "base_url", base_url)
        if not isinstance(self.allowlisted_hosts, (tuple, list)) or not self.allowlisted_hosts:
            raise DefinitionError("allowlisted_hosts must contain exact trusted hosts")
        hosts = tuple(_require_host(host) for host in self.allowlisted_hosts)
        if len(set(hosts)) != len(hosts):
            raise DefinitionError("allowlisted_hosts must not contain duplicates")
        if exact_host not in hosts:
            raise DefinitionError("base_url exact host must appear in allowlisted_hosts")
        object.__setattr__(self, "allowlisted_hosts", hosts)

        if auth_mode is AuthMode.NONE:
            if self.credential_ref is not None:
                raise DefinitionError("auth_mode none must not carry a credential reference")
        elif self.credential_ref is None:
            raise DefinitionError("authenticated auth_mode requires a credential reference")
        else:
            object.__setattr__(
                self, "credential_ref", _require_credential_reference(self.credential_ref)
            )

        if self.synthetic_data_only is not True:
            raise DefinitionError("synthetic-data attestation must require synthetic data only")
        object.__setattr__(
            self,
            "synthetic_data_attestation_ref",
            _require_reference(
                self.synthetic_data_attestation_ref, "synthetic-data attestation reference"
            ),
        )
        canary_refs = _normalize_references(self.canary_refs, "canary references")
        oracle_refs = _normalize_references(self.oracle_refs, "oracle references")
        if not canary_refs and not oracle_refs:
            raise DefinitionError("target requires at least one canary or oracle reference")
        object.__setattr__(self, "canary_refs", canary_refs)
        object.__setattr__(self, "oracle_refs", oracle_refs)
        if not isinstance(self.safety_caps, SafetyCaps):
            raise DefinitionError("safety_caps must be a validated SafetyCaps value")

    @property
    def exact_host(self) -> str:
        return _validate_base_url(self.base_url)[1]

    @property
    def explicit_no_auth(self) -> bool:
        return self.auth_mode is AuthMode.NONE

    def revise(self, *, version: str, name: str | None = None) -> TargetDefinition:
        next_version = _require_version(version)
        if _version_key(next_version) <= _version_key(self.version):
            raise DefinitionError("target revision version must increase")
        return replace(
            self,
            version=next_version,
            name=self.name if name is None else name,
            lifecycle=TargetLifecycle.DRAFT,
        )

    def transition(self, lifecycle: TargetLifecycle) -> TargetDefinition:
        next_lifecycle = _coerce_enum(lifecycle, TargetLifecycle, "lifecycle")
        if _FORWARD_TRANSITIONS.get(self.lifecycle) is not next_lifecycle:
            raise DefinitionError(
                f"invalid lifecycle transition {self.lifecycle.value} -> {next_lifecycle.value}"
            )
        return replace(self, lifecycle=next_lifecycle)


@dataclass(frozen=True, slots=True)
class AttackSurfaceDefinition:
    surface_id: str
    version: str
    target_id: str
    target_version: str
    kind: SurfaceKind
    protocol: str
    method: str
    relative_path: str
    trust_boundary: str
    authentication_required: bool
    risk: RiskLevel
    owasp_mappings: tuple[OwaspMapping, ...]
    oracle_refs: tuple[str, ...]
    enabled: bool
    surface_policy: SurfacePolicy | None = None
    surface_policy_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "surface_id", _require_identifier(self.surface_id, "surface_id"))
        object.__setattr__(self, "version", _require_version(self.version))
        object.__setattr__(self, "target_id", _require_identifier(self.target_id, "target_id"))
        object.__setattr__(
            self, "target_version", _require_version(self.target_version, "target_version")
        )
        object.__setattr__(self, "kind", _coerce_enum(self.kind, SurfaceKind, "surface kind"))
        object.__setattr__(self, "protocol", _require_identifier(self.protocol, "protocol"))
        if not isinstance(self.method, str) or _METHOD_RE.fullmatch(self.method) is None:
            raise DefinitionError("method must be an uppercase protocol method")
        object.__setattr__(self, "relative_path", validate_relative_path(self.relative_path))
        object.__setattr__(
            self,
            "trust_boundary",
            _require_identifier(self.trust_boundary, "trust_boundary"),
        )
        if not isinstance(self.authentication_required, bool):
            raise DefinitionError("authentication_required must be a boolean")
        object.__setattr__(self, "risk", _coerce_enum(self.risk, RiskLevel, "risk"))
        if not isinstance(self.owasp_mappings, (tuple, list)) or not self.owasp_mappings:
            raise DefinitionError("owasp_mappings must contain structured mappings")
        mappings = tuple(self.owasp_mappings)
        if any(not isinstance(mapping, OwaspMapping) for mapping in mappings):
            raise DefinitionError("owasp_mappings must contain OwaspMapping values")
        mapping_keys = {
            (mapping.framework, mapping.version, mapping.identifier) for mapping in mappings
        }
        if len(mapping_keys) != len(mappings):
            raise DefinitionError("owasp_mappings must not contain duplicates")
        object.__setattr__(self, "owasp_mappings", mappings)
        oracle_refs = _normalize_references(self.oracle_refs, "surface oracle references")
        if not oracle_refs:
            raise DefinitionError("surface requires at least one oracle reference")
        object.__setattr__(self, "oracle_refs", oracle_refs)
        if not isinstance(self.enabled, bool):
            raise DefinitionError("enabled must be a boolean")
        if self.surface_policy is None:
            if _requires_surface_policy(self.target_version):
                raise DefinitionError("schema-v2 attack surfaces require canonical surface_policy")
            if self.surface_policy_sha256 is not None:
                raise DefinitionError("surface_policy_sha256 cannot exist without a surface policy")
            return
        if not isinstance(self.surface_policy, SurfacePolicy):
            raise DefinitionError("surface_policy must be a validated SurfacePolicy")
        if self.surface_policy_sha256 is None:
            raise DefinitionError("surface policy requires its canonical SHA-256")
        supplied_hash = _require_sha256(
            self.surface_policy_sha256,
            "surface_policy_sha256",
        )
        if supplied_hash != self.surface_policy.policy_hash():
            raise DefinitionError(
                "surface_policy_sha256 does not match canonical surface policy bytes"
            )
        first_operation = self.surface_policy.operation_templates[0]
        if self.method != first_operation.method:
            raise DefinitionError("surface method must match its first operation template")
        if self.relative_path != first_operation.relative_path:
            raise DefinitionError("surface relative_path must match its first operation template")
        expected_authentication = self.surface_policy.auth_mode is not AuthMode.NONE
        if self.authentication_required is not expected_authentication:
            raise DefinitionError("surface authentication_required must match its surface policy")


@dataclass(frozen=True, slots=True)
class AuthorizationScope:
    """Canonical authorization identity for one bounded target-surface run."""

    target_id: str
    target_version: str
    surface_id: str
    surface_version: str
    adapter_kind: str
    environment: TargetEnvironment
    exact_host: str
    auth_mode: AuthMode
    credential_ref: str | None
    explicit_no_auth: bool
    protocol: str
    method: str
    relative_path: str
    corpus_hash: str
    caps: SafetyCaps
    run_nonce: str
    corpus_id: str = "m11-seed-corpus-v1"
    execution_profile: ExecutionProfile = ExecutionProfile.LIVE
    hosted_run: HostedRunBinding | None = None
    surface_policy: SurfacePolicy | None = None
    surface_policy_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_id", _require_identifier(self.target_id, "target_id"))
        object.__setattr__(self, "target_version", _require_version(self.target_version))
        object.__setattr__(self, "surface_id", _require_identifier(self.surface_id, "surface_id"))
        object.__setattr__(self, "surface_version", _require_version(self.surface_version))
        object.__setattr__(
            self, "adapter_kind", _require_identifier(self.adapter_kind, "adapter_kind")
        )
        object.__setattr__(
            self,
            "environment",
            _coerce_enum(self.environment, TargetEnvironment, "environment"),
        )
        object.__setattr__(self, "exact_host", _require_host(self.exact_host))
        auth_mode = _coerce_enum(self.auth_mode, AuthMode, "auth_mode")
        object.__setattr__(self, "auth_mode", auth_mode)
        if not isinstance(self.explicit_no_auth, bool):
            raise DefinitionError("explicit_no_auth must be a boolean")
        if auth_mode is AuthMode.NONE:
            if not self.explicit_no_auth or self.credential_ref is not None:
                raise DefinitionError("no-auth scope must be explicit and credential-free")
        else:
            if self.explicit_no_auth or self.credential_ref is None:
                raise DefinitionError("authenticated scope requires its credential reference")
            object.__setattr__(
                self, "credential_ref", _require_credential_reference(self.credential_ref)
            )
        object.__setattr__(self, "protocol", _require_identifier(self.protocol, "protocol"))
        if not isinstance(self.method, str) or _METHOD_RE.fullmatch(self.method) is None:
            raise DefinitionError("method must be an uppercase protocol method")
        object.__setattr__(self, "relative_path", validate_relative_path(self.relative_path))
        if (
            not isinstance(self.corpus_hash, str)
            or _CORPUS_HASH_RE.fullmatch(self.corpus_hash) is None
        ):
            raise DefinitionError("corpus_hash must be a lowercase SHA-256 digest")
        if not isinstance(self.caps, SafetyCaps):
            raise DefinitionError("caps must be a validated SafetyCaps value")
        if not isinstance(self.run_nonce, str) or _RUN_NONCE_RE.fullmatch(self.run_nonce) is None:
            raise DefinitionError("run_nonce must be a stable bounded nonce")
        object.__setattr__(self, "corpus_id", _require_identifier(self.corpus_id, "corpus_id"))
        object.__setattr__(
            self,
            "execution_profile",
            _coerce_enum(self.execution_profile, ExecutionProfile, "execution_profile"),
        )
        if self.hosted_run is not None and not isinstance(self.hosted_run, HostedRunBinding):
            raise DefinitionError("hosted_run must be a validated HostedRunBinding")
        if self.surface_policy is None:
            if _requires_surface_policy(self.target_version):
                raise DefinitionError(
                    "schema-v2 authorization scopes require canonical surface_policy"
                )
            if self.surface_policy_sha256 is not None:
                raise DefinitionError("surface_policy_sha256 cannot exist without a surface policy")
            return
        if not isinstance(self.surface_policy, SurfacePolicy):
            raise DefinitionError("surface_policy must be a validated SurfacePolicy")
        if self.surface_policy_sha256 is None:
            raise DefinitionError("surface policy scope requires its canonical SHA-256")
        supplied_hash = _require_sha256(
            self.surface_policy_sha256,
            "surface_policy_sha256",
        )
        if supplied_hash != self.surface_policy.policy_hash():
            raise DefinitionError(
                "scope surface_policy_sha256 does not match canonical policy bytes"
            )
        expected_auth = (
            self.surface_policy.auth_mode,
            self.surface_policy.credential_ref,
            self.surface_policy.explicit_no_auth,
        )
        supplied_auth = (self.auth_mode, self.credential_ref, self.explicit_no_auth)
        if supplied_auth != expected_auth:
            raise DefinitionError("scope authentication facts must come from its surface policy")
        first_operation = self.surface_policy.operation_templates[0]
        if (
            self.method != first_operation.method
            or self.relative_path != first_operation.relative_path
        ):
            raise DefinitionError(
                "scope method and path must match its first surface-policy operation"
            )

    @classmethod
    def for_definitions(
        cls,
        *,
        target: TargetDefinition,
        surface: AttackSurfaceDefinition,
        corpus_hash: str,
        caps: SafetyCaps,
        run_nonce: str,
        corpus_id: str = "m11-seed-corpus-v1",
        execution_profile: ExecutionProfile = ExecutionProfile.LIVE,
        hosted_run: HostedRunBinding | None = None,
    ) -> AuthorizationScope:
        if surface.target_id != target.target_id or surface.target_version != target.version:
            raise DefinitionError("surface reference does not match the target definition")
        if _requires_surface_policy(surface.target_version) and surface.surface_policy is None:
            raise DefinitionError(
                "schema-v2 definitions require canonical surface policy before authorization"
            )
        if surface.surface_policy is None:
            auth_mode = target.auth_mode
            credential_ref = target.credential_ref
            explicit_no_auth = target.explicit_no_auth
        else:
            auth_mode = surface.surface_policy.auth_mode
            credential_ref = surface.surface_policy.credential_ref
            explicit_no_auth = surface.surface_policy.explicit_no_auth
        return cls(
            target_id=target.target_id,
            target_version=target.version,
            surface_id=surface.surface_id,
            surface_version=surface.version,
            adapter_kind=target.adapter_kind,
            environment=target.environment,
            exact_host=target.exact_host,
            auth_mode=auth_mode,
            credential_ref=credential_ref,
            explicit_no_auth=explicit_no_auth,
            protocol=surface.protocol,
            method=surface.method,
            relative_path=surface.relative_path,
            corpus_hash=corpus_hash,
            caps=caps,
            run_nonce=run_nonce,
            corpus_id=corpus_id,
            execution_profile=execution_profile,
            hosted_run=hosted_run,
            surface_policy=surface.surface_policy,
            surface_policy_sha256=surface.surface_policy_sha256,
        )

    def canonical_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "target_id": self.target_id,
            "target_version": self.target_version,
            "surface_id": self.surface_id,
            "surface_version": self.surface_version,
            "adapter_kind": self.adapter_kind,
            "environment": self.environment.value,
            "exact_host": self.exact_host,
            "auth_mode": self.auth_mode.value,
            "credential_ref": self.credential_ref,
            "explicit_no_auth": self.explicit_no_auth,
            "protocol": self.protocol,
            "method": self.method,
            "relative_path": self.relative_path,
            "corpus_id": self.corpus_id,
            "corpus_hash": self.corpus_hash,
            "caps": self.caps.canonical_payload(),
            "run_nonce": self.run_nonce,
            "execution_profile": self.execution_profile.value,
        }
        if self.hosted_run is not None:
            payload["hosted_run"] = self.hosted_run.canonical_payload()
        if self.surface_policy is not None:
            payload["surface_policy"] = self.surface_policy.canonical_payload()
            payload["surface_policy_sha256"] = self.surface_policy_sha256
        return payload

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_payload(),
            allow_nan=False,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    def scope_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


__all__ = [
    "AttackSurfaceDefinition",
    "AuthMode",
    "AuthorizationScope",
    "DefinitionError",
    "ExecutionProfile",
    "FixtureDescriptor",
    "HostedRunBinding",
    "OwaspMapping",
    "RiskLevel",
    "SafetyCaps",
    "SurfaceOperationTemplate",
    "SurfacePolicy",
    "SurfaceKind",
    "TargetDefinition",
    "TargetEnvironment",
    "TargetLifecycle",
    "relative_path_parameters",
    "validate_relative_path",
]
