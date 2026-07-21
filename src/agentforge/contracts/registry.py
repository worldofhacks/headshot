"""Load and validate the versioned contracts under ``contracts/v1/``.

Uses ``jsonschema`` (a validation library, not an orchestration framework) via the
Draft 2020-12 validator. The contracts directory is resolved relative to the repo root, with an
``AGENTFORGE_CONTRACTS_DIR`` override for tooling that relocates it.
"""

from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path
from typing import Any

# The six success-message boundaries (ARCHITECTURE.md §4). Errors live in errors.json.
SUCCESS_SCHEMAS: tuple[str, ...] = (
    "campaign_directive",
    "attack_attempt",
    "attempt_result",
    "evidence_envelope",
    "verdict",
    "regression_admission",
)


def contracts_dir() -> Path:
    override = os.environ.get("AGENTFORGE_CONTRACTS_DIR")
    if override:
        return Path(override)
    # src/agentforge/contracts/registry.py -> parents[3] is the repo root.
    return Path(__file__).resolve().parents[3] / "contracts" / "v1"


@cache
def load_schema(name: str) -> dict[str, Any]:
    path = contracts_dir() / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"contract schema not found: {path}")
    return json.loads(path.read_text())


@cache
def validator_for(name: str):
    from jsonschema import Draft202012Validator

    schema = load_schema(name)
    Draft202012Validator.check_schema(schema)  # the schema itself must be well-formed
    return Draft202012Validator(schema)


def validate(name: str, payload: dict[str, Any]) -> None:
    """Raise ``jsonschema.ValidationError`` if ``payload`` does not conform to schema ``name``."""
    validator_for(name).validate(payload)


def is_valid(name: str, payload: dict[str, Any]) -> bool:
    return validator_for(name).is_valid(payload)
