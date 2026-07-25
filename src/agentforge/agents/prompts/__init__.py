"""Immutable, package-owned system-prompt authority for the four hosted roles."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

_ROLES = ("orchestrator", "red_team", "judge", "documentation")
_VERSION = "1"
_MANIFEST_RESOURCE = "registry.v1.json"
_RESOURCE_BY_ROLE = {role: f"v1/{role}.txt" for role in _ROLES}
_MAX_MANIFEST_BYTES = 65_536
_MAX_PROMPT_BYTES = 1_048_576
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_SHAPES = (
    re.compile(
        r"(?<![A-Za-z0-9])sk-(?:(?:ant|or|proj)-)?[A-Za-z0-9_-]{16,}",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", re.IGNORECASE),
    re.compile(r"\bsk_(?:test|live)_[A-Za-z0-9_-]{16,}\b", re.IGNORECASE),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE),
    re.compile(
        r"(?<![A-Za-z0-9_])[\"']?"
        r"(?:[A-Za-z0-9]{1,32}[_-]){0,4}"
        r"(?:api[_-]?key|secret|token|password|credential|authorization|session)"
        r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+_.=-]{16,}",
        re.IGNORECASE,
    ),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(
        r"\bpostgres(?:ql)?(?:\+[A-Za-z0-9]+)?://"
        r"[^/\s:@]+:[^@\s/]+@[^/\s]+",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
)
_GENERIC_ERROR = "prompt registry validation failed"


class PromptRegistryError(RuntimeError):
    """The package-owned prompt authority is absent, altered, or ambiguous."""


@dataclass(frozen=True, slots=True)
class PromptRecord:
    """One immutable prompt identity whose content is deliberately omitted from ``repr``."""

    role: str
    version: str
    sha256: str
    content: str = field(repr=False)


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _validated_records(
    manifest_bytes: bytes,
    resources: Mapping[str, bytes],
) -> tuple[PromptRecord, ...]:
    if (
        type(manifest_bytes) is not bytes
        or not manifest_bytes
        or len(manifest_bytes) > _MAX_MANIFEST_BYTES
    ):
        raise ValueError("invalid manifest bytes")
    manifest = json.loads(
        manifest_bytes.decode("utf-8"),
        object_pairs_hook=_object_without_duplicate_keys,
    )
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "prompts"}:
        raise ValueError("invalid manifest shape")
    if manifest["schema_version"] != _VERSION:
        raise ValueError("invalid manifest version")
    entries = manifest["prompts"]
    if not isinstance(entries, list) or len(entries) != len(_ROLES):
        raise ValueError("invalid manifest role count")
    if not isinstance(resources, Mapping) or set(resources) != set(_RESOURCE_BY_ROLE.values()):
        raise ValueError("invalid resource set")

    records: list[PromptRecord] = []
    for role, entry in zip(_ROLES, entries, strict=True):
        if not isinstance(entry, dict) or set(entry) != {
            "role",
            "version",
            "resource",
            "sha256",
        }:
            raise ValueError("invalid manifest entry")
        resource_name = _RESOURCE_BY_ROLE[role]
        if (
            entry["role"] != role
            or entry["version"] != _VERSION
            or entry["resource"] != resource_name
            or not isinstance(entry["sha256"], str)
            or _SHA256.fullmatch(entry["sha256"]) is None
        ):
            raise ValueError("invalid prompt identity")
        raw = resources[resource_name]
        if type(raw) is not bytes or not raw or len(raw) > _MAX_PROMPT_BYTES:
            raise ValueError("invalid prompt bytes")
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("prompt digest mismatch")
        content = raw.decode("utf-8")
        if (
            not content.startswith(f"AgentForge system role: {role}\n")
            or not content.endswith("\n")
            or "\x00" in content
            or any(pattern.search(content) is not None for pattern in _SECRET_SHAPES)
        ):
            raise ValueError("invalid prompt content")
        records.append(
            PromptRecord(
                role=role,
                version=_VERSION,
                sha256=entry["sha256"],
                content=content,
            )
        )
    return tuple(records)


def validate_prompt_bundle(
    manifest_bytes: bytes,
    resources: Mapping[str, bytes],
) -> tuple[PromptRecord, ...]:
    """Validate supplied bytes against the closed v1 role/resource identity contract."""

    try:
        return _validated_records(manifest_bytes, resources)
    except (KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise PromptRegistryError(_GENERIC_ERROR) from None


def load_prompt_registry() -> tuple[PromptRecord, ...]:
    """Load all authority bytes through the package-resource traversable and validate them."""

    try:
        root = importlib.resources.files(__package__)
        manifest_bytes = root.joinpath(_MANIFEST_RESOURCE).read_bytes()
        resources = {
            resource_name: root.joinpath(resource_name).read_bytes()
            for resource_name in _RESOURCE_BY_ROLE.values()
        }
    except (AttributeError, FileNotFoundError, IsADirectoryError, OSError, TypeError):
        raise PromptRegistryError(_GENERIC_ERROR) from None
    return validate_prompt_bundle(manifest_bytes, resources)


def prompt_for_identity(role: str, version: str, sha256: str) -> PromptRecord:
    """Resolve only an exact role/version/hash identity; no role-only fallback exists."""

    matches = tuple(
        record
        for record in load_prompt_registry()
        if (record.role, record.sha256) == (role, sha256)
    )
    # A digest is part of the complete versioned identity, not a role-level alias. Fail closed if a
    # future registry ever reuses one role/hash pair across versions (or contains duplicate
    # records), even when one of those records exactly matches the caller's requested version.
    if len(matches) == 1 and matches[0].version == version:
        return matches[0]
    raise PromptRegistryError(_GENERIC_ERROR)


__all__ = [
    "PromptRecord",
    "PromptRegistryError",
    "load_prompt_registry",
    "prompt_for_identity",
    "validate_prompt_bundle",
]
