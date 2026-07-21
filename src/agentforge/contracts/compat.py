"""Deterministic schema-compatibility check shared by ``contract-steward`` and CI.

A change is BREAKING if a consumer that accepted the old schema could reject a valid new-producer
payload (or vice versa): a removed property, a newly-required property, a removed enum value, or a
narrowed/changed type. The contract-steward rule (DECISIONS.md D10) is that a breaking change
requires a version bump + migration note + updated tests — so a breaking change whose ``version`` is
unchanged is a failed run.
"""

from __future__ import annotations

from typing import Any


class ContractCompatError(Exception):
    """Raised when a breaking schema change is not accompanied by a version bump."""


def _props(schema: dict[str, Any]) -> dict[str, Any]:
    return schema.get("properties", {})


def _required(schema: dict[str, Any]) -> set[str]:
    return set(schema.get("required", []))


def breaking_changes(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Return a list of human-readable breaking changes (empty if backward-compatible)."""
    reasons: list[str] = []
    old_props, new_props = _props(old), _props(new)

    for name in old_props:
        if name not in new_props:
            reasons.append(f"property '{name}' removed")

    for name in sorted(_required(new) - _required(old)):
        reasons.append(f"property '{name}' became required")

    for name, old_p in old_props.items():
        new_p = new_props.get(name)
        if not isinstance(new_p, dict) or not isinstance(old_p, dict):
            continue
        if "enum" in old_p and "enum" in new_p:
            removed = set(old_p["enum"]) - set(new_p["enum"])
            if removed:
                reasons.append(f"enum values removed from '{name}': {sorted(removed)}")
        if "type" in old_p and "type" in new_p and old_p["type"] != new_p["type"]:
            reasons.append(f"type of '{name}' changed {old_p['type']} -> {new_p['type']}")

    return reasons


def is_breaking(old: dict[str, Any], new: dict[str, Any]) -> bool:
    return bool(breaking_changes(old, new))


def check_change(old: dict[str, Any], new: dict[str, Any]) -> None:
    """Raise :class:`ContractCompatError` if a breaking change lacks a version bump."""
    if is_breaking(old, new) and str(old.get("version")) == str(new.get("version")):
        raise ContractCompatError(
            "breaking change without a version bump: " + "; ".join(breaking_changes(old, new))
        )
