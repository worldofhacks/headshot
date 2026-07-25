"""A bundle is a claim; the provider's usage export is what turns it into a measurement.

The replay path validates bundle shape only, so a hand-written bundle with a fabricated request id
produces a passing calibration.  These tests pin the reconciliation that closes it: every sample's
``provider_request_id`` must appear in the provider's own export, with matching model, cost and
tokens — and a bundle that cannot be reconciled must not be able to license runtime authority.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = ROOT / "scripts" / "verify_calibration_provenance.py"

_IDENTITY = {
    "judge_provider": "openrouter:google-vertex",
    "judge_model": "google/gemini-2.5-pro",
    "judge_model_version": "3" * 64,
    "criteria_version": "independent-judge-assessment-v2",
    "implementation_version": "hosted-role-runtime-v2",
    "red_team_provider": "openrouter:together",
    "red_team_model": "qwen/qwen3.5-397b-a17b",
}


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_calibration_provenance", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bundle(samples: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema_version": "1", "judge_identity": _IDENTITY, "samples": samples}


def _sample(label: str, request_id: str, cost: str = "0.0174575") -> dict[str, Any]:
    return {
        "label_id": label,
        "provider_request_id": request_id,
        "returned_model": "google/gemini-2.5-pro",
        "input_tokens": 1030,
        "output_tokens": 185,
        "reasoning_tokens": 1432,
        "measured_cost_usd": cost,
    }


def _row(request_id: str, cost: str = "0.0174575", **overrides: Any) -> dict[str, Any]:
    row = {
        "id": request_id,
        "model": "google/gemini-2.5-pro",
        "cost": cost,
        "tokens_prompt": 1030,
        "tokens_completion": 1617,
    }
    row.update(overrides)
    return row


def test_a_reconciled_bundle_yields_an_attestation() -> None:
    module = _module()
    bundle = _bundle([_sample("L-1", "gen-aaa"), _sample("L-2", "gen-bbb")])

    attestation = module.verify(
        bundle,
        [_row("gen-aaa"), _row("gen-bbb")],
        ledger_total_usd="0.034915",
        export_path="/tmp/usage.csv",
    )

    assert attestation["attestation_kind"] == "openrouter_usage_export_reconciled"
    assert attestation["matched_generation_count"] == 2
    assert attestation["measured_usd_total"] == "0.0349150"
    assert attestation["judge_identity"] == _IDENTITY


def test_a_fabricated_request_id_has_nothing_to_match() -> None:
    """The load-bearing check — this is the hole the whole tool exists to close."""

    module = _module()
    bundle = _bundle([_sample("L-1", "gen-0000000000-FABRICATED")])

    with pytest.raises(module.ProvenanceRefused, match="does not appear in the usage export"):
        module.verify(bundle, [_row("gen-aaa")])


def test_a_cost_the_provider_did_not_charge_is_refused() -> None:
    module = _module()
    bundle = _bundle([_sample("L-1", "gen-aaa", cost="0.00")])

    with pytest.raises(module.ProvenanceRefused, match="cost 0.0174575 in the export"):
        module.verify(bundle, [_row("gen-aaa")])


def test_a_model_the_provider_did_not_serve_is_refused() -> None:
    module = _module()
    bundle = _bundle([_sample("L-1", "gen-aaa")])

    with pytest.raises(module.ProvenanceRefused, match="was served by"):
        module.verify(bundle, [_row("gen-aaa", model="fictional/model-9000")])


def test_reasoning_tokens_may_be_reported_inside_completion_tokens() -> None:
    """OpenRouter folds reasoning into completion; the bundle splits them. Both forms pass."""

    module = _module()
    bundle = _bundle([_sample("L-1", "gen-aaa")])

    assert module.verify(bundle, [_row("gen-aaa", tokens_completion=1617)])
    assert module.verify(bundle, [_row("gen-aaa", tokens_completion=185)])
    with pytest.raises(module.ProvenanceRefused, match="matches"):
        module.verify(bundle, [_row("gen-aaa", tokens_completion=99)])


def test_calls_the_bundle_does_not_report_are_refused_unless_allowed() -> None:
    module = _module()
    bundle = _bundle([_sample("L-1", "gen-aaa")])
    export = [_row("gen-aaa"), _row("gen-unreported")]

    with pytest.raises(module.ProvenanceRefused, match="not claimed by the bundle"):
        module.verify(bundle, export)

    allowed = module.verify(bundle, export, allow_extra_generations=True)
    assert allowed["unclaimed_generation_count"] == 1


def test_a_ledger_total_that_does_not_reconcile_is_refused() -> None:
    module = _module()
    bundle = _bundle([_sample("L-1", "gen-aaa")])

    with pytest.raises(module.ProvenanceRefused, match="does not reconcile"):
        module.verify(bundle, [_row("gen-aaa")], ledger_total_usd="9.99")


def test_a_duplicated_export_row_is_refused() -> None:
    module = _module()
    bundle = _bundle([_sample("L-1", "gen-aaa")])

    with pytest.raises(module.ProvenanceRefused, match="more than once"):
        module.verify(bundle, [_row("gen-aaa"), _row("gen-aaa")])


# --- export parsing ----------------------------------------------------------------------


def test_csv_and_json_exports_both_load(tmp_path: Path) -> None:
    module = _module()
    csv_path = tmp_path / "usage.csv"
    csv_path.write_text(
        "generation_id,model,cost,tokens_prompt,tokens_completion\n"
        "gen-aaa,google/gemini-2.5-pro,0.0174575,1030,1617\n",
        encoding="utf-8",
    )
    json_path = tmp_path / "usage.json"
    json_path.write_text(json.dumps({"data": [_row("gen-aaa")]}), encoding="utf-8")

    from_csv = module._load_export(csv_path)
    from_json = module._load_export(json_path)

    assert from_csv[0]["id"] == from_json[0]["id"] == "gen-aaa"
    assert from_csv[0]["cost"] == "0.0174575"


def test_an_unmappable_export_refuses_and_names_the_columns_it_saw(tmp_path: Path) -> None:
    """Guessing a column wrong would 'verify' nothing, so it refuses instead."""

    module = _module()
    path = tmp_path / "usage.csv"
    path.write_text("when,how_much\n2026-07-25,0.01\n", encoding="utf-8")

    with pytest.raises(module.ProvenanceRefused, match="Columns seen"):
        module._load_export(path)


# --- the enablement gate consumes it -----------------------------------------------------
#
# The hard "no reconciliation, no enablement" gate was replaced by graded provenance: a
# reconciliation now EARNS the `usage_export_reconciled` tier, and a bundle without one falls to
# `lineage_consistent`, which an approver may accept explicitly. The tier logic and the refusal of
# anything weaker than the accepted floor live in tests/test_calibration_provenance_tiers.py.


def test_a_reconciliation_earns_the_top_provider_tier_for_enablement() -> None:
    """The link between this tool's output and what enablement will grant."""

    from agentforge.agents.judge.provenance import classify_provider_provenance

    module = _module()
    bundle = _bundle([_sample("L-1", "gen-aaa"), _sample("L-2", "gen-bbb")])
    attestation = module.verify(bundle, [_row("gen-aaa"), _row("gen-bbb")])

    tier, _ = classify_provider_provenance(bundle, attestation=attestation)

    assert tier == "usage_export_reconciled"


def test_without_a_reconciliation_the_same_bundle_only_reaches_lineage_consistent() -> None:
    from agentforge.agents.judge.provenance import classify_provider_provenance

    bundle = _bundle([_sample("L-1", "gen-1784934309-yDHN8gAVdjgNMKHfMHlT")])
    varied = _sample("L-2", "gen-1784934325-4gKt0ABOyvB7ZSuScxxr", cost="0.0181")
    varied["output_tokens"] = 212  # distinct token counts are part of what the tier requires
    bundle["samples"].append(varied)

    tier, _ = classify_provider_provenance(bundle)

    assert tier == "lineage_consistent"
