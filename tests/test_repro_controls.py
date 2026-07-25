"""CI enforcement for the reproduction control manifest.

Pins the anti-cheat invariants (AC1-AC4) and the canonical report-ID scheme so a later edit to the
manifest cannot silently drift from the honesty rules. Pure stdlib, no network, no DB.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "evals" / "repro-controls" / "headshot-repro-controls-v1.json"
VALIDATOR = REPO / "scripts" / "validate_repro_controls.py"

_CANONICAL_ID = re.compile(r"^AF-VULN-2026-\d{4}-\d{3}$")


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_repro_controls", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_is_valid_json_with_three_findings() -> None:
    manifest = _manifest()
    assert manifest["manifest_id"] == "headshot-repro-controls-v1"
    assert len(manifest["findings"]) == 3


def test_anti_cheat_invariants_hold() -> None:
    problems, _notes = _load_validator().validate(_manifest(), {})
    assert problems == [], f"anti-cheat violations: {problems}"


def test_each_finding_has_canonical_id_and_trusted_confirm_source() -> None:
    for finding in _manifest()["findings"]:
        pos = finding["positive_case"]
        assert _CANONICAL_ID.match(pos["canonical_finding_id"]), pos.get("canonical_finding_id")
        # Only the deterministic authorities may confirm — the load-bearing invariant.
        assert pos["expected_confirmed_source"] in {"oracle", "canary", "human"}


def test_canonical_ids_are_the_distinct_007_008_009_sequence() -> None:
    ids = sorted(f["positive_case"]["canonical_finding_id"] for f in _manifest()["findings"])
    assert ids == [
        "AF-VULN-2026-0725-007",
        "AF-VULN-2026-0725-008",
        "AF-VULN-2026-0725-009",
    ]
