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
from enum import StrEnum
from urllib.parse import urlsplit

_IDENTIFIER_RE = re.compile(r"\A[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_VERSION_RE = re.compile(r"\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_REFERENCE_RE = re.compile(r"\A[a-z][a-z0-9+.-]*://[^\s\x00-\x1f\x7f]+\Z")
_HOST_LABEL_RE = re.compile(r"\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_METHOD_RE = re.compile(r"\A[A-Z][A-Z0-9_-]{0,31}\Z")
_CORPUS_HASH_RE = re.compile(r"\A[a-f0-9]{64}\Z")
_RUN_NONCE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{15,127}\Z")
_RELATIVE_SEGMENT_RE = re.compile(r"\A[A-Za-z0-9._~-]+\Z")
_FORWARD_TRANSITIONS: dict[TargetLifecycle, TargetLifecycle] = {}


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
    if any(
        not segment or segment in {".", ".."} or _RELATIVE_SEGMENT_RE.fullmatch(segment) is None
        for segment in segments
    ):
        raise DefinitionError("relative path contains empty, traversal, or invalid segments")
    return path


def _finite_positive(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DefinitionError(f"{field} must be a finite positive number")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0:
        raise DefinitionError(f"{field} must be a finite positive number")
    return numeric


@dataclass(frozen=True, slots=True)
class SafetyCaps:
    """Target-specific maxima that an authorized run scope may only narrow."""

    budget_usd: float
    max_attempts_per_run: int
    target_requests_per_second: float
    run_timeout_seconds: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "budget_usd", _finite_positive(self.budget_usd, "budget_usd"))
        attempts = self.max_attempts_per_run
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
            raise DefinitionError("max_attempts_per_run must be a positive integer")
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
        return {
            "budget_usd": self.budget_usd,
            "max_attempts_per_run": self.max_attempts_per_run,
            "target_requests_per_second": self.target_requests_per_second,
            "run_timeout_seconds": self.run_timeout_seconds,
        }

    def is_within(self, maximum: SafetyCaps) -> bool:
        return (
            self.budget_usd <= maximum.budget_usd
            and self.max_attempts_per_run <= maximum.max_attempts_per_run
            and self.target_requests_per_second <= maximum.target_requests_per_second
            and self.run_timeout_seconds <= maximum.run_timeout_seconds
        )


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
    ) -> AuthorizationScope:
        if surface.target_id != target.target_id or surface.target_version != target.version:
            raise DefinitionError("surface reference does not match the target definition")
        return cls(
            target_id=target.target_id,
            target_version=target.version,
            surface_id=surface.surface_id,
            surface_version=surface.version,
            adapter_kind=target.adapter_kind,
            environment=target.environment,
            exact_host=target.exact_host,
            auth_mode=target.auth_mode,
            credential_ref=target.credential_ref,
            explicit_no_auth=target.explicit_no_auth,
            protocol=surface.protocol,
            method=surface.method,
            relative_path=surface.relative_path,
            corpus_hash=corpus_hash,
            caps=caps,
            run_nonce=run_nonce,
            corpus_id=corpus_id,
            execution_profile=execution_profile,
        )

    def canonical_payload(self) -> dict[str, object]:
        return {
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

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_payload(),
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
    "OwaspMapping",
    "RiskLevel",
    "SafetyCaps",
    "SurfaceKind",
    "TargetDefinition",
    "TargetEnvironment",
    "TargetLifecycle",
    "validate_relative_path",
]
