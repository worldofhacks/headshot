"""Enablement is a gate, and every branch of it is a refusal rather than a repair.

The model Judge may only be enabled for the identity the deployment is actually running, on the
stratum it actually decides, over labels two distinct humans attested blind to its output.  These
tests pin each refusal, and pin that enablement never widens confirmation authority.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from agentforge.agents.hosted import (
    HOSTED_MAX_PHYSICAL_CALLS,
    HOSTED_ROLE_MODELS,
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_runtime import hosted_judge_identity
from agentforge.agents.judge import ACCEPTED_MODEL_JUDGE_THRESHOLDS, CalibrationGate
from agentforge.agents.prompts import load_prompt_registry

ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = ROOT / "scripts" / "enable_model_judge.py"
_GROUND_TRUTH = ROOT / "evals" / "ground-truth"

_UPSTREAM = {
    "orchestrator": "anthropic",
    "red_team": "together",
    "judge": "google-vertex",
    "documentation": "openai",
}
_PRICES = {
    "orchestrator": TokenPrices(Decimal("15"), Decimal("75"), Decimal("75")),
    "red_team": TokenPrices(Decimal("1"), Decimal("5"), Decimal("5")),
    "judge": TokenPrices(Decimal("5"), Decimal("30"), Decimal("30")),
    "documentation": TokenPrices(Decimal("5"), Decimal("30"), Decimal("30")),
}
_ROLE_MAX_USD = {
    "orchestrator": Decimal("1.50"),
    "red_team": Decimal("1"),
    "judge": Decimal("4"),
    "documentation": Decimal("1"),
}


def _prompt_sha256(role: str) -> str:
    """Resolve a role's prompt digest from the package-owned prompt authority."""

    return next(record for record in load_prompt_registry() if record.role == role).sha256


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("enable_model_judge", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _staged_set(policy: str = "production") -> HostedConfigurationSet:
    roles = tuple(
        HostedRoleConfiguration(
            role=role,  # type: ignore[arg-type]
            provider="openrouter",
            model_id=model_id,
            upstream_provider=_UPSTREAM[role],
            credential_reference=f"secretref://railway/openrouter/{role}/{policy}",
            prompt_sha256=_prompt_sha256(role),
            policy_sha256=hashlib.sha256(f"{policy}:{role}:v1".encode()).hexdigest(),
            prices=_PRICES[role],
            limits=HostedLimits(
                max_calls=(HOSTED_MAX_PHYSICAL_CALLS if role == "judge" else 1),
                max_input_tokens=120_000 * HOSTED_MAX_PHYSICAL_CALLS,
                max_output_tokens=4_000 * HOSTED_MAX_PHYSICAL_CALLS,
                max_reasoning_tokens=8_000 * HOSTED_MAX_PHYSICAL_CALLS,
                max_usd=_ROLE_MAX_USD[role],
                max_retries=1,
                max_requests_per_second=Decimal("0.5"),
                max_concurrency=1,
            ),
        )
        for role, model_id in HOSTED_ROLE_MODELS.items()
    )
    return HostedConfigurationSet(
        roles=roles,
        global_limits=HostedLimits(
            max_calls=HOSTED_MAX_PHYSICAL_CALLS,
            max_input_tokens=120_000 * HOSTED_MAX_PHYSICAL_CALLS,
            max_output_tokens=4_000 * HOSTED_MAX_PHYSICAL_CALLS,
            max_reasoning_tokens=8_000 * HOSTED_MAX_PHYSICAL_CALLS,
            max_usd=Decimal("10"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


class _IdealEvaluator:
    """Answers each label the way a perfectly-calibrated model could — never CONFIRMED."""

    def evaluate(self, envelope: dict[str, Any], *, integrity_ok: bool = True) -> dict[str, Any]:
        label_id = envelope["trusted"]["ground_truth_ref"]
        expected = _EXPECTED[label_id]
        state = "EXPLOIT_LIKELY" if expected == "EXPLOIT_CONFIRMED" else expected
        reason = {
            "EXPLOIT_LIKELY": "calibrated_positive",
            "NO_EXPLOIT_OBSERVED": "calibrated_negative",
            "INDETERMINATE": "uncertainty_band",
        }[state]
        verdict = {
            "schema_version": "1",
            "campaign_run_id": envelope["campaign_run_id"],
            "attempt_id": envelope["attempt_id"],
            "state": state,
            "confidence": 0.9 if state != "INDETERMINATE" else 0.0,
            "reason_codes": [reason],
        }
        if state in {"EXPLOIT_LIKELY", "NO_EXPLOIT_OBSERVED"}:
            verdict["confirmation_source"] = "calibrated_model"
        return verdict


def _slices() -> list[dict[str, Any]]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(_GROUND_TRUTH.glob("*.json"))
    ]


_EXPECTED = {
    label["label_id"]: label["expected_verdict"]["state"]
    for item in _slices()
    for label in item["labels"]
}


def _passing_calibration(configuration: HostedConfigurationSet) -> dict[str, Any]:
    return CalibrationGate(evaluator=_IdealEvaluator()).evaluate(
        slices=_slices(),
        identity=hosted_judge_identity(configuration),
        thresholds=ACCEPTED_MODEL_JUDGE_THRESHOLDS,
    )


def _attestation(
    calibration: dict[str, Any],
    *,
    labeler: str = "headshot:alex",
    reviewer: str = "headshot:jordan",
    blind: bool = True,
) -> dict[str, Any]:
    return {
        "slice_set_sha256": calibration["slice_set_sha256"],
        "labeling_guide_sha256": "c" * 64,
        "blind_to_judge_output": blind,
        "human_labeler": {"id": labeler, "attested_at": "2026-07-25T12:00:00+00:00"},
        "distinct_reviewer": {"id": reviewer, "attested_at": "2026-07-25T13:00:00+00:00"},
    }


def _provenance(
    configuration: HostedConfigurationSet, calibration: dict[str, Any]
) -> dict[str, Any]:
    """A reconciliation covering every scored sample, as verify_calibration_provenance emits."""

    return {
        "schema_version": "1",
        "attestation_kind": "openrouter_usage_export_reconciled",
        "judge_identity": hosted_judge_identity(configuration).payload(),
        "sample_count": len(calibration["sample_results"]),
        "matched_generation_count": len(calibration["sample_results"]),
        "unclaimed_generation_count": 0,
        "measured_usd_total": "0.75823375",
        "usage_export_path": "/tmp/openrouter-usage.csv",
    }


def _args(tmp_path: Path, **overrides: Any) -> Any:
    configuration = overrides.pop("configuration", None) or _staged_set()
    calibration = overrides.pop("calibration", None) or _passing_calibration(configuration)
    attestation = overrides.pop("attestation", None) or _attestation(calibration)
    provenance = overrides.pop("provenance", None) or _provenance(configuration, calibration)

    paths = {}
    for name, payload in (
        ("calibration", calibration),
        ("hosted", configuration.canonical_payload()),
        ("attestation", attestation),
        ("provenance", provenance),
    ):
        target = tmp_path / f"{name}.json"
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        paths[name] = target

    import argparse

    return argparse.Namespace(
        calibration=paths["calibration"],
        hosted_configuration_set=paths["hosted"],
        expected_configuration_sha256=overrides.pop(
            "expected_sha", configuration.configuration_sha256
        ),
        ground_truth_attestation=overrides.pop("gt_attestation_path", paths["attestation"]),
        provenance_attestation=overrides.pop("prov_path", paths["provenance"]),
        captured_results=None,
        accept_ground_truth_tier=overrides.pop("accept_gt", "human_two_person"),
        accept_provider_tier=overrides.pop("accept_prov", "usage_export_reconciled"),
        approver_ref=overrides.pop("approver_ref", "headshot:approver-morgan"),
        slice_dir=_GROUND_TRUTH,
        output=tmp_path / "out.json",
        confirm=True,
    )


# --- the happy path ----------------------------------------------------------------------


def test_enablement_succeeds_for_the_deployed_identity_with_two_person_ground_truth(
    tmp_path: Path,
) -> None:
    module = _module()

    enabled = module._enable(_args(tmp_path))

    assert enabled["state"] == "passed"
    assert enabled["human_approved"] is True
    assert enabled["runtime_enabled"] is True
    assert (
        enabled["approver_ref"]
        == "gt=human_two_person;prov=usage_export_reconciled;by=headshot:approver-morgan"
    )
    # Identity is the deployment's, re-derived rather than copied from the artifact.
    assert enabled["judge_identity"] == hosted_judge_identity(_staged_set()).payload()


def test_enablement_does_not_widen_confirmation_authority() -> None:
    """An enabled model still cannot confirm — twice over, in schema and in contract.

    The hosted assessment schema has no ``EXPLOIT_CONFIRMED`` member, so the model cannot even
    utter it; and ``verdict.json`` restricts an ``EXPLOIT_CONFIRMED`` verdict's
    ``confirmation_source`` to oracle / canary / human, so ``calibrated_model`` could not carry
    a confirmation even if some other code path tried to build one.
    """

    from jsonschema.exceptions import ValidationError

    from agentforge.agents.judge.hosted import _assessment_schema
    from agentforge.contracts import validate

    states = set(_assessment_schema()["properties"]["state"]["enum"])
    assert "EXPLOIT_CONFIRMED" not in states
    assert {"EXPLOIT_LIKELY", "NO_EXPLOIT_OBSERVED", "INDETERMINATE"} <= states

    with pytest.raises(ValidationError):
        validate(
            "verdict",
            {
                "schema_version": "1",
                "campaign_run_id": "run-1",
                "attempt_id": "attempt-1",
                "state": "EXPLOIT_CONFIRMED",
                "confidence": 1.0,
                "reason_codes": ["calibrated_positive"],
                "confirmation_source": "calibrated_model",
            },
        )


def test_enablement_leaves_indeterminate_reachable_and_never_safe() -> None:
    from agentforge.agents.judge.judge import is_safe

    assert is_safe({"state": "INDETERMINATE"}) is False
    assert is_safe({"state": "ERROR"}) is False
    assert is_safe({"state": "EXPLOIT_LIKELY"}) is False
    assert is_safe({"state": "NO_EXPLOIT_OBSERVED"}) is True


# --- identity refusals -------------------------------------------------------------------


def test_enablement_refuses_a_calibration_measured_against_another_identity(
    tmp_path: Path,
) -> None:
    """The exact defect being repaired: a calibration bound to a config production never runs."""

    module = _module()
    deployed = _staged_set("production")
    other = _staged_set("capture-local")
    args = _args(tmp_path, configuration=deployed, calibration=_passing_calibration(other))

    with pytest.raises(module.EnablementRefused, match="different Judge identity"):
        module._enable(args)


def test_enablement_refuses_a_configuration_the_operator_did_not_attest(tmp_path: Path) -> None:
    module = _module()

    with pytest.raises(module.EnablementRefused, match="drifted from the attested identity"):
        module._enable(_args(tmp_path, expected_sha="0" * 64))


# --- ground-truth refusals ---------------------------------------------------------------


def test_enablement_refuses_a_baseline_weaker_than_the_accepted_floor(tmp_path: Path) -> None:
    """Rule-derived labels no longer fail closed — they fail the FLOOR the approver named."""

    module = _module()
    configuration = _staged_set()
    calibration = _passing_calibration(configuration)
    unattested = _attestation(calibration)
    unattested["human_labeler"] = None

    with pytest.raises(module.EnablementRefused, match="weaker than the accepted floor"):
        module._enable(
            _args(
                tmp_path,
                configuration=configuration,
                attestation=unattested,
                accept_gt="human_two_person",
            )
        )


def test_enablement_accepts_the_rule_derived_baseline_when_that_floor_is_named(
    tmp_path: Path,
) -> None:
    """The deadline path: a weaker baseline is allowed once a human names it explicitly."""

    module = _module()
    configuration = _staged_set()
    calibration = _passing_calibration(configuration)
    unattested = _attestation(calibration)
    unattested["human_labeler"] = None

    enabled = module._enable(
        _args(
            tmp_path,
            configuration=configuration,
            attestation=unattested,
            accept_gt="rule_derived",
        )
    )

    assert enabled["runtime_enabled"] is True
    # And the downgrade travels inside the artifact.
    assert enabled["approver_ref"].startswith("gt=rule_derived;")


def test_a_solo_or_unblinded_attestation_falls_through_rather_than_being_honoured(
    tmp_path: Path,
) -> None:
    module = _module()
    configuration = _staged_set()
    calibration = _passing_calibration(configuration)
    for broken in (
        _attestation(calibration, labeler="headshot:alex", reviewer="headshot:alex"),
        _attestation(calibration, blind=False),
    ):
        with pytest.raises(module.EnablementRefused, match="weaker than the accepted floor"):
            module._enable(
                _args(
                    tmp_path,
                    configuration=configuration,
                    attestation=broken,
                    accept_gt="human_two_person",
                )
            )


def test_enablement_refuses_an_attestation_bound_to_another_slice_set(tmp_path: Path) -> None:
    module = _module()
    configuration = _staged_set()
    calibration = _passing_calibration(configuration)
    wrong = _attestation(calibration)
    wrong["slice_set_sha256"] = "d" * 64

    with pytest.raises(module.EnablementRefused, match="different slice set"):
        module._enable(_args(tmp_path, configuration=configuration, attestation=wrong))


# --- governing-stratum refusal -----------------------------------------------------------


def test_enablement_gates_on_the_non_oracle_stratum_not_the_pooled_headline(
    tmp_path: Path,
) -> None:
    module = _module()
    slice_dir = tmp_path / "gt"
    slice_dir.mkdir()
    (slice_dir / "pi.json").write_text(
        json.dumps(
            {
                "category": "prompt_injection",
                "labels": [
                    {
                        "label_id": "MODEL-1",
                        "evidence_envelope": {"trusted": {"canary_hits": [], "oracle_results": []}},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    calibration = {
        "thresholds": ACCEPTED_MODEL_JUDGE_THRESHOLDS.payload(),
        "metrics": {"sample_count": 1},
        "calibration_id": "JC-" + "0" * 64,
        "identity_sha256": "1" * 64,
        "slice_set_sha256": "2" * 64,
        "judge_identity": {},
        "state": "passed",
        "sample_results": [
            {
                "label_id": "MODEL-1",
                "category": "prompt_injection",
                "expected_state": "EXPLOIT_LIKELY",
                "actual_state": "NO_EXPLOIT_OBSERVED",
                "confidence": 0.9,
                "agreement": False,
                "false_positive": False,
                "false_negative": True,
                "abstained": False,
            }
        ],
    }

    with pytest.raises(module.EnablementRefused, match="non-oracle stratum"):
        module._require_governing_stratum_passes(calibration, slice_dir=slice_dir)
