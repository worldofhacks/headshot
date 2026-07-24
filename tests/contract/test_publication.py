"""The root PRD publication must exactly mirror the runtime contract authority."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from agentforge.contracts import SUCCESS_SCHEMAS, validator_for

ROOT = Path(__file__).resolve().parents[2]
CANONICAL_DIR = ROOT / "src" / "agentforge" / "contracts" / "v1"
PUBLISHED_DIR = ROOT / "contracts" / "v1"
EXPECTED_FILENAMES = {f"{name}.json" for name in (*SUCCESS_SCHEMAS, "errors")}


def _schema_files(directory: Path) -> dict[str, Path]:
    return {path.name: path for path in directory.glob("*.json")}


def test_root_contract_publication_matches_registry_and_canonical_bytes() -> None:
    canonical = _schema_files(CANONICAL_DIR)
    published = _schema_files(PUBLISHED_DIR)

    assert set(canonical) == EXPECTED_FILENAMES
    assert set(published) == EXPECTED_FILENAMES

    for filename in sorted(EXPECTED_FILENAMES):
        canonical_bytes = canonical[filename].read_bytes()
        assert published[filename].read_bytes() == canonical_bytes

        schema = json.loads(canonical_bytes)
        Draft202012Validator.check_schema(schema)
        validator_for(filename.removesuffix(".json"))
