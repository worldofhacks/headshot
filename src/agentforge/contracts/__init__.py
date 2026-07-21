"""Versioned inter-agent contract tooling (P10).

The JSON Schemas ship INSIDE this package at ``agentforge/contracts/v1/`` and are resolved via
``importlib.resources`` (so a wheel installed outside a repo checkout still finds them). They stay
language- and framework-neutral JSON (DECISIONS.md D10); an ``AGENTFORGE_CONTRACTS_DIR`` override
lets tooling point the loader at an on-disk copy. This package is the deterministic loader +
compatibility checker shared by the ``contract-steward`` skill and CI, so guidance and enforcement
cannot drift.

Importing ``agentforge`` does not import this module (it pulls in ``jsonschema``), keeping the
top-level package dependency-free.
"""

from agentforge.contracts.compat import (
    ContractCompatError,
    breaking_changes,
    check_change,
    is_breaking,
)
from agentforge.contracts.registry import (
    SUCCESS_SCHEMAS,
    contracts_dir,
    is_valid,
    load_schema,
    validate,
    validator_for,
)

__all__ = [
    "SUCCESS_SCHEMAS",
    "contracts_dir",
    "load_schema",
    "validator_for",
    "validate",
    "is_valid",
    "breaking_changes",
    "is_breaking",
    "check_change",
    "ContractCompatError",
]
