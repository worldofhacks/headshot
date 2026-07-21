"""Versioned inter-agent contract tooling (P10).

The JSON Schemas themselves live at the repo-root ``contracts/v1/`` so they are language- and
framework-neutral (DECISIONS.md D10). This package is the deterministic loader + compatibility
checker shared by the ``contract-steward`` skill and CI, so guidance and enforcement cannot drift.

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
