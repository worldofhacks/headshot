"""P10 compatibility: a breaking change without a version bump must fail (contract-steward rule)."""

import copy

import pytest

from agentforge.contracts import (
    ContractCompatError,
    breaking_changes,
    check_change,
    is_breaking,
    load_schema,
)


def test_additive_change_is_not_breaking() -> None:
    old = load_schema("verdict")
    new = copy.deepcopy(old)
    new["properties"]["new_optional_field"] = {"type": "string"}
    assert not is_breaking(old, new)
    check_change(old, new)  # must not raise


def test_removed_property_is_breaking_and_needs_a_bump() -> None:
    old = load_schema("verdict")
    new = copy.deepcopy(old)
    del new["properties"]["confidence"]
    assert is_breaking(old, new)
    with pytest.raises(ContractCompatError):
        check_change(old, new)  # same version + breaking -> fail


def test_breaking_change_ok_when_version_bumped() -> None:
    old = load_schema("verdict")
    new = copy.deepcopy(old)
    del new["properties"]["confidence"]
    new["version"] = "2"
    check_change(old, new)  # version bumped -> allowed


def test_new_required_field_is_breaking() -> None:
    old = load_schema("attack_attempt")
    new = copy.deepcopy(old)
    new["required"] = [*new["required"], "category"]
    assert "property 'category' became required" in breaking_changes(old, new)


def test_removed_enum_value_is_breaking() -> None:
    old = load_schema("verdict")
    new = copy.deepcopy(old)
    new["properties"]["state"]["enum"] = [
        s for s in old["properties"]["state"]["enum"] if s != "EXPLOIT_LIKELY"
    ]
    reasons = breaking_changes(old, new)
    assert any("enum values removed from 'state'" in r for r in reasons)
