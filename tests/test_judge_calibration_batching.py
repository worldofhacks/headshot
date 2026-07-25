"""Batched calibration must attest ONE identity, and the merge must refuse a partial campaign.

A corpus larger than the 56-call platform ceiling is captured as several sub-runs against one
unchanged staged configuration.  Two things make that safe rather than convenient:

* ``limits`` sits inside ``judge_model_version``, so the batches must share a configuration — a
  wider cap would attest a different evaluator and the sub-runs could not be aggregated at all; and
* a merge that quietly dropped a batch would measure a smaller, easier corpus and report a better
  agreement rate, so coverage is checked against the ground-truth corpus itself.
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
from agentforge.agents.prompts import load_prompt_registry

ROOT = Path(__file__).resolve().parents[1]
_CAPTURE = ROOT / "scripts" / "capture_judge_calibration.py"
_MERGE = ROOT / "scripts" / "merge_calibration_batches.py"

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


def _module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _staged_set(*, judge_max_calls: int = HOSTED_MAX_PHYSICAL_CALLS) -> HostedConfigurationSet:
    roles = tuple(
        HostedRoleConfiguration(
            role=role,  # type: ignore[arg-type]
            provider="openrouter",
            model_id=model_id,
            upstream_provider=_UPSTREAM[role],
            credential_reference=f"secretref://railway/openrouter/{role}/production",
            prompt_sha256=_prompt_sha256(role),
            policy_sha256=hashlib.sha256(f"production:{role}:v1".encode()).hexdigest(),
            prices=_PRICES[role],
            limits=HostedLimits(
                max_calls=(judge_max_calls if role == "judge" else 1),
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


def _labels(count: int) -> list[tuple[str, dict[str, Any]]]:
    return [("prompt_injection", {"label_id": f"GT-{index:04d}"}) for index in range(count)]


# --- the batch plan ----------------------------------------------------------------------


def test_a_200_label_corpus_splits_into_batches_that_each_fit_the_staged_envelope() -> None:
    module = _module(_CAPTURE, "capture_judge_calibration")
    staged = _staged_set()
    judge = next(role for role in staged.roles if role.role == "judge")

    plan = module._batch_plan(_labels(200), configuration=staged, judge_role=judge, batch_size=None)

    assert plan["batch_size"] == HOSTED_MAX_PHYSICAL_CALLS
    assert plan["batch_count"] == 4
    assert [len(b["labels"]) for b in plan["batches"]] == [56, 56, 56, 32]
    assert sum(len(b["labels"]) for b in plan["batches"]) == 200
    # Disjoint and complete.
    seen = [lid for b in plan["batches"] for lid in b["label_ids"]]
    assert len(seen) == len(set(seen)) == 200


def test_every_batch_of_one_campaign_attests_the_identical_identity() -> None:
    """The whole point of batching instead of raising the cap."""

    module = _module(_CAPTURE, "capture_judge_calibration")
    staged = _staged_set()
    judge = next(role for role in staged.roles if role.role == "judge")
    plan = module._batch_plan(_labels(200), configuration=staged, judge_role=judge, batch_size=None)

    # Identity is a function of the staged configuration alone — not of any batch.
    identity = hosted_judge_identity(staged).payload()
    assert identity["judge_model_version"] == judge.configuration_sha256
    assert plan["batch_count"] == 4

    # And the generation policy is bound to the campaign, so it is constant across sub-runs too.
    policies = {
        module._generation_policy_sha256(
            staged,
            total_sample_count=plan["total_sample_count"],
            batch_size=plan["batch_size"],
        )
        for _ in plan["batches"]
    }
    assert len(policies) == 1


def test_batch_size_may_not_exceed_the_staged_envelope() -> None:
    module = _module(_CAPTURE, "capture_judge_calibration")
    staged = _staged_set(judge_max_calls=20)
    judge = next(role for role in staged.roles if role.role == "judge")

    with pytest.raises(SystemExit, match="do NOT raise the staged limits"):
        module._batch_plan(_labels(200), configuration=staged, judge_role=judge, batch_size=56)


def test_batch_size_defaults_down_to_a_smaller_staged_cap() -> None:
    module = _module(_CAPTURE, "capture_judge_calibration")
    staged = _staged_set(judge_max_calls=20)
    judge = next(role for role in staged.roles if role.role == "judge")

    plan = module._batch_plan(_labels(50), configuration=staged, judge_role=judge, batch_size=None)

    assert plan["batch_size"] == 20
    assert [len(b["labels"]) for b in plan["batches"]] == [20, 20, 10]


# --- the merge ---------------------------------------------------------------------------


def _identity() -> dict[str, str]:
    return hosted_judge_identity(_staged_set()).payload()


def _write_batch(
    root: Path,
    *,
    index: int,
    label_ids: list[str],
    identity: dict[str, str] | None = None,
    role_config: str | None = None,
) -> Path:
    identity = identity or _identity()
    directory = root / f"batch-{index}"
    directory.mkdir(parents=True, exist_ok=True)
    bundle = {
        "schema_version": "1",
        "judge_identity": identity,
        "provenance": {
            "capture_kind": "openrouter_hosted_evaluator",
            "configuration_sha256": "a" * 64,
            "role_configuration_sha256": role_config or identity["judge_model_version"],
            "generation_policy_sha256": "b" * 64,
            "requested_model": identity["judge_model"],
            "returned_model": identity["judge_model"],
            "captured_at": f"2026-07-25T0{index}:00:00+00:00",
        },
        "samples": [
            {
                "label_id": label_id,
                "assessment": {
                    "state": "NO_EXPLOIT_OBSERVED",
                    "confidence": 0.9,
                    "rationale": "ok",
                    "criteria_hits": [],
                    "error_code": None,
                },
                "provider_request_id": f"gen-{label_id}",
                "trace_id": "0" * 32,
                "returned_model": identity["judge_model"],
                "input_tokens": 10,
                "output_tokens": 5,
                "reasoning_tokens": 1,
                "measured_cost_usd": "0.01",
            }
            for label_id in label_ids
        ],
    }
    (directory / "captured-results.json").write_text(json.dumps(bundle), encoding="utf-8")
    (directory / "capture-manifest.json").write_text(
        json.dumps(
            {
                "capture_run_id": f"run-{index}",
                "batch": {"batch_index": index, "batch_count": 2},
                "ledger": {"measured_usd": format(Decimal("0.01") * len(label_ids), "f")},
            }
        ),
        encoding="utf-8",
    )
    return directory


def _slice_dir(root: Path, label_ids: list[str]) -> Path:
    directory = root / "gt"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pi.json").write_text(
        json.dumps(
            {"category": "prompt_injection", "labels": [{"label_id": i} for i in label_ids]}
        ),
        encoding="utf-8",
    )
    return directory


def test_merge_joins_disjoint_batches_that_exactly_cover_the_corpus(tmp_path: Path) -> None:
    module = _module(_MERGE, "merge_calibration_batches")
    corpus = ["L-1", "L-2", "L-3", "L-4"]
    first = _write_batch(tmp_path, index=0, label_ids=["L-1", "L-2"])
    second = _write_batch(tmp_path, index=1, label_ids=["L-3", "L-4"])

    bundle, manifest = module.merge([first, second], slice_dir=_slice_dir(tmp_path, corpus))

    assert [s["label_id"] for s in bundle["samples"]] == corpus
    assert bundle["judge_identity"] == _identity()
    # Latest sub-run stamps the campaign.
    assert bundle["provenance"]["captured_at"] == "2026-07-25T01:00:00+00:00"
    assert manifest["batch_count"] == 2
    assert manifest["measured_usd_total"] == "0.04"
    assert manifest["label_to_batch"]["L-3"] == str(second)


def test_merge_refuses_when_a_batch_is_missing(tmp_path: Path) -> None:
    """The failure a silent merge would turn into a better-looking agreement rate."""

    module = _module(_MERGE, "merge_calibration_batches")
    corpus = ["L-1", "L-2", "L-3", "L-4"]
    only = _write_batch(tmp_path, index=0, label_ids=["L-1", "L-2"])

    with pytest.raises(module.MergeRefused, match="covered by no batch"):
        module.merge([only], slice_dir=_slice_dir(tmp_path, corpus))


def test_merge_refuses_batches_that_attest_different_identities(tmp_path: Path) -> None:
    module = _module(_MERGE, "merge_calibration_batches")
    corpus = ["L-1", "L-2"]
    first = _write_batch(tmp_path, index=0, label_ids=["L-1"])
    drifted = dict(_identity())
    drifted["judge_model_version"] = "f" * 64
    second = _write_batch(
        tmp_path, index=1, label_ids=["L-2"], identity=drifted, role_config="f" * 64
    )

    with pytest.raises(module.MergeRefused, match="different Judge identity"):
        module.merge([first, second], slice_dir=_slice_dir(tmp_path, corpus))


def test_merge_refuses_overlapping_batches(tmp_path: Path) -> None:
    module = _module(_MERGE, "merge_calibration_batches")
    corpus = ["L-1", "L-2"]
    first = _write_batch(tmp_path, index=0, label_ids=["L-1", "L-2"])
    second = _write_batch(tmp_path, index=1, label_ids=["L-2"])

    with pytest.raises(module.MergeRefused, match="appears in both"):
        module.merge([first, second], slice_dir=_slice_dir(tmp_path, corpus))


def test_merge_refuses_a_capture_with_no_batch_record(tmp_path: Path) -> None:
    module = _module(_MERGE, "merge_calibration_batches")
    directory = _write_batch(tmp_path, index=0, label_ids=["L-1"])
    manifest = json.loads((directory / "capture-manifest.json").read_text())
    manifest.pop("batch")
    (directory / "capture-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(module.MergeRefused, match="carries no batch record"):
        module.merge([directory], slice_dir=_slice_dir(tmp_path, ["L-1"]))
