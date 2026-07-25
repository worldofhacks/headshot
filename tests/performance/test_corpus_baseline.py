from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agentforge.agents.hosted import HOSTED_MAX_PHYSICAL_CALLS
from agentforge.campaign.corpus import AuthoredCase, AuthoredCorpus
from agentforge.performance.corpus_baseline import (
    BoundCapArtifact,
    CorpusBaselineError,
    build_run_authorization_envelope,
    capture_local_corpus_admission,
    verify_bound_caps,
    write_corpus_baseline_artifacts,
)

_RELEASE_SHA = "a" * 40


def _case(index: int, *, turns: int) -> AuthoredCase:
    payload = {
        "case_id": f"case-{index:03d}",
        "input_sequence": [f"synthetic fixture turn {turn}" for turn in range(turns)],
    }
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return AuthoredCase(
        payload=payload,
        content_hash=hashlib.sha256(canonical).hexdigest(),
        instance_id=f"INSTANCE-{index:03d}",
    )


def _live_100_fixture() -> AuthoredCorpus:
    cases = tuple(_case(index, turns=2 if index < 21 else 1) for index in range(100))
    return AuthoredCorpus(
        corpus_id="headshot-live-100-v1",
        content_hash="b" * 64,
        cases=cases,
        categories=frozenset({"synthetic-test-only"}),
        root=Path("/not-evidence"),
    )


def _bound_caps() -> tuple[BoundCapArtifact, ...]:
    return tuple(
        BoundCapArtifact(
            path=path,
            sha256=character * 64,
        )
        for path, character in (
            ("config/live-target-catalog.production.json", "c"),
            ("config/live-target-catalog.staging.json", "d"),
            ("config/targets/clinical-copilot-20260724.json", "e"),
            ("docs/evidence/authorization-requests/caps.json", "f"),
        )
    )


def test_run_envelope_derives_exact_counts_and_cumulative_four_role_batches() -> None:
    envelope = build_run_authorization_envelope(
        corpus=_live_100_fixture(),
        release_sha=_RELEASE_SHA,
        run_id="test-only-not-a-run",
        bound_caps=_bound_caps(),
    )

    assert envelope["authorization_status"] == "not_a_grant"
    assert envelope["caps"] == {
        "logical_case_limit": 100,
        "physical_request_limit": 121,
        "target_retries_per_turn": 0,
        "budget_usd_hard_cap": 50,
        "expected_spend_usd": {"minimum": 10, "maximum": 25},
    }
    batching = envelope["batching"]
    assert batching["hosted_max_physical_calls"] == HOSTED_MAX_PHYSICAL_CALLS == 56
    assert batching["hosted_calls_per_case"] == 4
    assert batching["batch_size"] == 14
    assert batching["batch_count"] == 8
    assert [batch["logical_case_count"] for batch in batching["batches"]] == [
        14,
        14,
        14,
        14,
        14,
        14,
        14,
        2,
    ]
    assert [batch["target_physical_request_count"] for batch in batching["batches"]] == [
        28,
        21,
        14,
        14,
        14,
        14,
        14,
        2,
    ]
    assert all(
        batch["hosted_global_call_count"] <= HOSTED_MAX_PHYSICAL_CALLS
        for batch in batching["batches"]
    )
    assert batching["batches"][0]["hosted_role_call_counts"] == {
        "documentation": 14,
        "judge": 14,
        "orchestrator": 14,
        "red_team": 14,
    }


def test_run_envelope_rejects_over_cap_batching_and_wrong_corpus_shape() -> None:
    with pytest.raises(CorpusBaselineError, match="HOSTED_MAX_PHYSICAL_CALLS"):
        build_run_authorization_envelope(
            corpus=_live_100_fixture(),
            release_sha=_RELEASE_SHA,
            run_id="test-only",
            bound_caps=_bound_caps(),
            batch_size=50,
        )

    wrong = AuthoredCorpus(
        corpus_id="headshot-live-100-v1",
        content_hash="d" * 64,
        cases=tuple(_case(index, turns=1) for index in range(100)),
        categories=frozenset({"synthetic-test-only"}),
        root=Path("/not-evidence"),
    )
    with pytest.raises(CorpusBaselineError, match="100/121/0"):
        build_run_authorization_envelope(
            corpus=wrong,
            release_sha=_RELEASE_SHA,
            run_id="test-only",
            bound_caps=_bound_caps(),
        )


def test_local_admission_metrics_are_observed_and_scope_is_explicit() -> None:
    corpus = AuthoredCorpus(
        corpus_id="fixture-v1",
        content_hash="e" * 64,
        cases=(
            _case(0, turns=2),
            _case(1, turns=1),
            _case(2, turns=1),
            _case(3, turns=1),
        ),
        categories=frozenset({"synthetic-test-only"}),
        root=Path("/not-evidence"),
    )
    monotonic_values = iter(
        (
            0,
            100,
            1_000_100,
            1_000_200,
            3_000_200,
            3_000_300,
            6_000_300,
            6_000_400,
            10_000_400,
            12_000_000,
        )
    )
    cpu_values = iter((0, 6_000_000))

    baseline = capture_local_corpus_admission(
        corpus=corpus,
        release_sha=_RELEASE_SHA,
        run_id="fixture-observation",
        monotonic_ns=lambda: next(monotonic_values),
        process_time_ns=lambda: next(cpu_values),
        peak_rss_bytes=lambda: 64_000_000,
        runtime_identity={"system": "test", "python": "test"},
    )

    assert baseline["scope"]["network_calls"] == 0
    assert "Railway service performance" in baseline["scope"]["not_measured"]
    assert baseline["corpus"]["logical_case_count"] == 4
    assert baseline["corpus"]["physical_request_count"] == 5
    metrics = baseline["metrics"]
    assert metrics["case_admission_latency_ms"] == {
        "sample_count": 4,
        "p50": 2.0,
        "p95": 4.0,
    }
    assert metrics["elapsed_ms"] == 12.0
    assert metrics["cpu_time_ms"] == 6.0
    assert metrics["cpu_utilization_ratio"] == 0.5
    assert metrics["throughput_cases_per_second"] == pytest.approx(333.3333333333333)
    assert metrics["peak_rss_bytes"] == 64_000_000
    assert metrics["canonical_case_payload_bytes"] > 0


def test_artifacts_are_content_addressed_and_never_overwritten(tmp_path: Path) -> None:
    output = tmp_path / "performance"
    envelope = build_run_authorization_envelope(
        corpus=_live_100_fixture(),
        release_sha=_RELEASE_SHA,
        run_id="test-only",
        bound_caps=_bound_caps(),
    )
    baseline = {
        "schema_version": "1",
        "artifact": "local-offline-corpus-admission-baseline",
    }

    result = write_corpus_baseline_artifacts(
        output_directory=output,
        envelope=envelope,
        local_baseline=baseline,
    )

    sums = (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert {path.name for path in output.iterdir()} == {
        "SHA256SUMS",
        "artifact-manifest.json",
        "local-admission-baseline.json",
        "run-authorization-envelope.json",
    }
    assert len(sums) == 3
    for line in sums:
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    assert dict(result.artifact_sha256s)["run-authorization-envelope.json"]

    with pytest.raises(CorpusBaselineError, match="never overwritten"):
        write_corpus_baseline_artifacts(
            output_directory=output,
            envelope=envelope,
            local_baseline=baseline,
        )


def test_repository_bound_caps_are_exact_and_content_addressed() -> None:
    root = Path(__file__).resolve().parents[2]

    artifacts = verify_bound_caps(root)

    assert [artifact.path for artifact in artifacts] == [
        "config/live-target-catalog.production.json",
        "config/live-target-catalog.staging.json",
        "config/targets/clinical-copilot-20260724.json",
        "docs/evidence/authorization-requests/caps.json",
    ]
    assert all(len(artifact.sha256) == 64 for artifact in artifacts)
