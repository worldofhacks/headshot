"""Load and validate the versioned contracts under ``agentforge/contracts/v1/``.

Uses ``jsonschema`` (a validation library, not an orchestration framework) via the
Draft 2020-12 validator. The schemas ship INSIDE the package (``agentforge.contracts``,
subdirectory ``v1``) and are resolved with :mod:`importlib.resources`, so a wheel installed
outside any repo checkout still finds them. An ``AGENTFORGE_CONTRACTS_DIR`` override lets
tooling point the loader at an on-disk directory instead (e.g. a proposed edit under review).
"""

from __future__ import annotations

import json
import os
import re
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any

# A schema name is a bare identifier — lowercase alnum plus ``_ . -`` — with NO path separator
# and NO ``..``. importlib.resources ``joinpath`` / an on-disk override do NOT sanitize a
# component, so a name like ``../../pyproject`` would escape the package; this allowlist makes
# the traversal impossible even if a future caller ever passes a dynamic (untrusted) name.
_SCHEMA_NAME_RE = re.compile(r"\A[a-z0-9][a-z0-9_.-]*\Z")


def safe_schema_name(name: str) -> str:
    """Return ``name`` if it is a safe bare schema identifier; else raise ``ValueError``.

    Rejects path separators, ``..`` traversal, absolute paths, and empty/odd names, so a schema
    lookup can never read a file outside its packaged schema directory (defense in depth — all
    current callers pass hardcoded names, but this pins the property so it cannot regress)."""
    if not isinstance(name, str) or ".." in name or not _SCHEMA_NAME_RE.match(name):
        raise ValueError(
            f"invalid schema name {name!r}: expected [a-z0-9][a-z0-9_.-]* with no path "
            "separator or '..'"
        )
    return name


# The six success-message boundaries (ARCHITECTURE.md §4). Errors live in errors.json.
SUCCESS_SCHEMAS: tuple[str, ...] = (
    "campaign_directive",
    "attack_attempt",
    "attempt_result",
    "evidence_envelope",
    "verdict",
    "regression_admission",
)


def contracts_dir() -> Path | None:
    """Return the ``AGENTFORGE_CONTRACTS_DIR`` override directory, or ``None``.

    Override-only: when set, schemas are read from ``<override>/<name>.json`` on disk. When
    unset (the default), schemas resolve from inside the package via ``importlib.resources``
    and there is no filesystem directory to return.
    """
    override = os.environ.get("AGENTFORGE_CONTRACTS_DIR")
    return Path(override) if override else None


def _schema_text(name: str) -> str:
    name = safe_schema_name(name)  # no path traversal into or out of the schema directory
    override = contracts_dir()
    if override is not None:
        try:
            return (override / f"{name}.json").read_text(encoding="utf-8")
        except OSError as exc:  # fail closed with a clear message on a misconfigured override
            raise RuntimeError(
                f"contract schema {name!r} not found under AGENTFORGE_CONTRACTS_DIR override"
            ) from exc
    # Packaged resolution: zip-safe, CWD-independent, no repo checkout required.
    return files("agentforge.contracts").joinpath("v1", f"{name}.json").read_text(encoding="utf-8")


@cache
def load_schema(name: str) -> dict[str, Any]:
    return json.loads(_schema_text(name))


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
