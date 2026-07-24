from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, localcontext

import pytest

from agentforge.performance import (
    NEAREST_RANK_RULE,
    ArtifactDigest,
    EvidenceArtifact,
    LogicalCaseSample,
    Measurement,
    PerformanceEvidenceError,
    PerformanceReportBuilder,
    PhysicalRequestSample,
    ProviderSample,
    RunResourceSample,
    UsdMeasurement,
    build_sha256sums,
    canonical_sha256,
    nearest_rank,
)


def _observed(value: int | float) -> Measurement:
    return Measurement.observed(value)


def _case(ordinal: int, *, turns: int) -> LogicalCaseSample:
    return LogicalCaseSample(
        case_id=f"case-{ordinal:03d}",
        case_sha256=hashlib.sha256(f"case-{ordinal}".encode()).hexdigest(),
        ordinal=ordinal,
        planned_physical_request_count=turns,
        duration_ms=_observed(100 + ordinal),
        queue_wait_ms=_observed(ordinal / 10),
        orchestration_latency_ms=_observed(ordinal),
    )


def _provider(ordinal: int) -> ProviderSample:
    return ProviderSample(
        call_id=f"provider-{ordinal:03d}",
        case_id=f"case-{ordinal:03d}",
        role="judge",
        ordinal=ordinal,
        status="failed" if ordinal == 100 else "succeeded",
        latency_ms=_observed(ordinal * 2),
        input_tokens=_observed(ordinal),
        output_tokens=_observed(ordinal * 2),
        reasoning_tokens=_observed(0),
        cost_usd=UsdMeasurement.observed(Decimal("0.01")),
        error_code="provider_error" if ordinal == 100 else None,
    )


def _resources(*, elapsed: Measurement | None = None) -> RunResourceSample:
    return RunResourceSample(
        elapsed_ms=elapsed or _observed(10_000),
        cpu_time_ms=_observed(5_000),
        peak_rss_bytes=_observed(64_000_000),
        postgres_bytes_before=_observed(1_000_000),
        postgres_bytes_after=_observed(1_001_000),
        artifact_bytes_before=_observed(10_000),
        artifact_bytes_after=_observed(10_500),
    )


def _exact_samples() -> tuple[
    tuple[LogicalCaseSample, ...],
    tuple[PhysicalRequestSample, ...],
    tuple[ProviderSample, ...],
]:
    cases = tuple(_case(ordinal, turns=2 if ordinal <= 21 else 1) for ordinal in range(1, 101))
    requests: list[PhysicalRequestSample] = []
    request_ordinal = 0
    for case in cases:
        for turn_index in range(1, case.planned_physical_request_count + 1):
            request_ordinal += 1
            requests.append(
                PhysicalRequestSample(
                    request_id=f"request-{request_ordinal:03d}",
                    case_id=case.case_id,
                    ordinal=request_ordinal,
                    turn_index=turn_index,
                    retry_index=0,
                    status="failed" if request_ordinal == 121 else "succeeded",
                    latency_ms=_observed(request_ordinal),
                    request_bytes=_observed(10),
                    response_bytes=_observed(20),
                    error_code="target_error" if request_ordinal == 121 else None,
                )
            )
    providers = tuple(_provider(ordinal) for ordinal in range(1, 101))
    return cases, tuple(requests), providers


def test_exact_100_121_zero_retry_report_reconciles_and_aggregates() -> None:
    cases, requests, providers = _exact_samples()

    report = PerformanceReportBuilder().build(
        run_id="run-exact",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=providers,
        resources=_resources(),
    )

    summary = report.summary
    assert summary.percentile_rule == NEAREST_RANK_RULE
    assert summary.reconciliation.passed is True
    assert summary.reconciliation.observed_logical_case_count == 100
    assert summary.reconciliation.observed_physical_request_count == 121
    assert summary.reconciliation.observed_retry_count == 0
    assert summary.reconciliation.expected_turn_distribution == ((1, 79), (2, 21))
    assert summary.reconciliation.observed_turn_distribution == ((1, 79), (2, 21))
    assert summary.reconciliation.expected_provider_role_counts == (("judge", 100),)
    assert summary.reconciliation.observed_provider_role_counts == (("judge", 100),)
    assert summary.reconciliation.violations == ()
    assert summary.evidence_complete is True
    assert summary.unavailable_metrics == ()

    assert summary.latency.orchestration.p95_ms.value == 95
    assert summary.latency.target.p95_ms.value == 115
    assert summary.latency.provider.p95_ms.value == 190
    assert summary.bottleneck.component == "provider"
    assert summary.bottleneck.p95_ms.value == 190

    assert summary.throughput.logical_cases_per_second.value == 10
    assert summary.throughput.physical_requests_per_second.value == pytest.approx(12.1)
    assert summary.errors.target_error_count == 1
    assert summary.errors.target_error_rate.value == pytest.approx(1 / 121)
    assert summary.errors.provider_error_count == 1
    assert summary.errors.provider_error_rate.value == pytest.approx(0.01)

    assert summary.resources.cpu_time_ms.value == 5_000
    assert summary.resources.cpu_utilization_ratio.value == 0.5
    assert summary.resources.peak_rss_bytes.value == 64_000_000
    assert summary.resources.postgres_growth_bytes.value == 1_000
    assert summary.resources.artifact_growth_bytes.value == 500
    assert summary.resources.total_storage_growth_bytes.value == 1_500
    assert summary.resources.storage_throughput_bytes_per_second.value == 150

    assert summary.accounting.request_bytes.value == 1_210
    assert summary.accounting.response_bytes.value == 2_420
    assert summary.accounting.provider_input_tokens.value == 5_050
    assert summary.accounting.provider_output_tokens.value == 10_100
    assert summary.accounting.provider_reasoning_tokens.value == 0
    assert summary.accounting.provider_cost_usd.value == Decimal("1.00")


def test_unavailable_values_remain_explicit_and_never_become_zero() -> None:
    cases, requests, providers = _exact_samples()
    providers = (
        replace(
            providers[0],
            reasoning_tokens=Measurement.unavailable("provider omitted usage"),
        ),
        *providers[1:],
    )
    resources = _resources(elapsed=Measurement.unavailable("monotonic clock sample missing"))

    report = PerformanceReportBuilder().build(
        run_id="run-partial",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=providers,
        resources=resources,
    )

    summary = report.summary
    assert summary.reconciliation.passed is True
    assert summary.evidence_complete is False
    assert summary.accounting.provider_reasoning_tokens.available is False
    assert summary.accounting.provider_reasoning_tokens.value is None
    assert "1 of 100 samples unavailable" in (
        summary.accounting.provider_reasoning_tokens.unavailable_reason or ""
    )
    assert summary.throughput.logical_cases_per_second.available is False
    assert summary.throughput.logical_cases_per_second.value is None
    assert summary.resources.storage_throughput_bytes_per_second.available is False
    assert any("provider omitted usage" in item for item in summary.unavailable_metrics)
    assert any("monotonic clock sample missing" in item for item in summary.unavailable_metrics)

    summary_document = json.loads(
        next(artifact.content for artifact in report.artifacts if artifact.path == "summary.json")
    )
    reasoning = summary_document["accounting"]["provider_reasoning_tokens"]
    assert reasoning == {
        "available": False,
        "unavailable_reason": "provider reasoning tokens: 1 of 100 samples unavailable",
        "value": None,
    }


def test_reconciliation_reports_extra_send_and_retry_without_discarding_evidence() -> None:
    cases = (_case(1, turns=2), _case(2, turns=1))
    requests = (
        PhysicalRequestSample(
            request_id="r1",
            case_id=cases[0].case_id,
            ordinal=1,
            turn_index=1,
            retry_index=0,
            status="succeeded",
            latency_ms=_observed(1),
            request_bytes=_observed(1),
            response_bytes=_observed(1),
        ),
        PhysicalRequestSample(
            request_id="r2",
            case_id=cases[0].case_id,
            ordinal=2,
            turn_index=2,
            retry_index=0,
            status="succeeded",
            latency_ms=_observed(2),
            request_bytes=_observed(1),
            response_bytes=_observed(1),
        ),
        PhysicalRequestSample(
            request_id="r3",
            case_id=cases[1].case_id,
            ordinal=3,
            turn_index=1,
            retry_index=0,
            status="succeeded",
            latency_ms=_observed(3),
            request_bytes=_observed(1),
            response_bytes=_observed(1),
        ),
        PhysicalRequestSample(
            request_id="r4",
            case_id=cases[0].case_id,
            ordinal=4,
            turn_index=1,
            retry_index=1,
            status="failed",
            latency_ms=_observed(4),
            request_bytes=_observed(1),
            response_bytes=_observed(1),
            error_code="retry_failed",
        ),
    )
    providers = (
        replace(_provider(1), case_id=cases[0].case_id),
        replace(_provider(2), case_id=cases[1].case_id),
    )

    report = PerformanceReportBuilder(
        expected_logical_case_count=2,
        expected_physical_request_count=3,
        expected_retry_count=0,
        expected_turn_distribution={1: 1, 2: 1},
        expected_provider_role_counts={"judge": 2},
    ).build(
        run_id="run-over-cap",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=providers,
        resources=_resources(),
    )

    reconciliation = report.summary.reconciliation
    assert reconciliation.passed is False
    assert reconciliation.observed_physical_request_count == 4
    assert reconciliation.observed_retry_count == 1
    assert reconciliation.violations == (
        f"case_request_count_mismatch:{cases[0].case_id}",
        "physical_request_count_mismatch",
        "retry_count_mismatch",
    )
    assert report.summary.evidence_complete is False
    assert len(report.artifacts) == 4


def test_provider_role_counts_are_exact_required_inputs_and_configurable() -> None:
    cases, requests, providers = _exact_samples()

    missing_judge = PerformanceReportBuilder().build(
        run_id="run-missing-judge",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=providers[:-1],
        resources=_resources(),
    )
    assert missing_judge.summary.reconciliation.passed is False
    assert missing_judge.summary.evidence_complete is False
    assert missing_judge.summary.reconciliation.observed_provider_role_counts == (("judge", 99),)
    assert (
        "provider_role_count_mismatch:judge:expected=100:observed=99"
        in missing_judge.summary.reconciliation.violations
    )

    documentation = replace(
        providers[0],
        call_id="provider-documentation-001",
        case_id=None,
        role="documentation",
        ordinal=101,
    )
    unexpected = PerformanceReportBuilder().build(
        run_id="run-unexpected-role",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=(*providers, documentation),
        resources=_resources(),
    )
    assert unexpected.summary.reconciliation.passed is False
    assert "provider_role_distribution_mismatch" in (unexpected.summary.reconciliation.violations)

    complete = PerformanceReportBuilder(
        expected_provider_role_counts={"judge": 100, "documentation": 1}
    ).build(
        run_id="run-role-counts",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=(*providers, documentation),
        resources=_resources(),
    )
    assert complete.summary.reconciliation.passed is True
    assert complete.summary.reconciliation.observed_provider_role_counts == (
        ("documentation", 1),
        ("judge", 100),
    )


def test_every_default_judge_call_is_bound_one_to_one_to_a_known_case() -> None:
    cases, requests, providers = _exact_samples()
    duplicated_case_coverage = (
        replace(providers[0], case_id=cases[1].case_id),
        *providers[1:],
    )

    report = PerformanceReportBuilder().build(
        run_id="run-judge-coverage",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=duplicated_case_coverage,
        resources=_resources(),
    )

    assert report.summary.reconciliation.passed is False
    assert f"judge_case_call_count_mismatch:{cases[0].case_id}:0" in (
        report.summary.reconciliation.violations
    )
    assert f"judge_case_call_count_mismatch:{cases[1].case_id}:2" in (
        report.summary.reconciliation.violations
    )


def test_default_turn_distribution_rejects_any_non_one_or_two_turn_case() -> None:
    cases, requests, providers = _exact_samples()
    altered_cases = (
        replace(cases[0], planned_physical_request_count=3),
        replace(cases[1], planned_physical_request_count=1),
        *cases[2:],
    )

    report = PerformanceReportBuilder().build(
        run_id="run-invalid-turn-shape",
        logical_cases=altered_cases,
        physical_requests=requests,
        provider_calls=providers,
        resources=_resources(),
    )

    reconciliation = report.summary.reconciliation
    assert reconciliation.passed is False
    assert report.summary.evidence_complete is False
    assert reconciliation.observed_turn_distribution == ((1, 80), (2, 19), (3, 1))
    assert "turn_count_not_allowed:case-001:3" in reconciliation.violations
    assert "turn_distribution_mismatch" in reconciliation.violations


def test_provider_usd_is_exact_decimal_and_canonical_without_float_rounding() -> None:
    cases, requests, providers = _exact_samples()

    report = PerformanceReportBuilder().build(
        run_id="run-decimal-cost",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=providers,
        resources=_resources(),
    )
    total = report.summary.accounting.provider_cost_usd
    assert total.available is True
    assert total.value == Decimal("1.00")
    assert isinstance(total.value, Decimal)

    summary_document = json.loads(
        next(artifact.content for artifact in report.artifacts if artifact.path == "summary.json")
    )
    assert summary_document["accounting"]["provider_cost_usd"]["value"] == "1"

    first = UsdMeasurement.observed(Decimal("0.1000000000000000000000000001"))
    second = UsdMeasurement.observed(Decimal("0.1000000000000000000000000002"))
    assert canonical_sha256(first) != canonical_sha256(second)
    with pytest.raises(PerformanceEvidenceError, match="Decimal"):
        UsdMeasurement.observed(0.01)  # type: ignore[arg-type]
    with pytest.raises(PerformanceEvidenceError, match="UsdMeasurement"):
        replace(providers[0], cost_usd=_observed(1))  # type: ignore[arg-type]
    with pytest.raises(PerformanceEvidenceError, match="numeric"):
        Measurement.observed(Decimal("1"))  # type: ignore[arg-type]


def test_provider_usd_sum_is_independent_of_ambient_decimal_precision() -> None:
    cases, requests, providers = _exact_samples()
    precise_providers = (
        replace(
            providers[0],
            cost_usd=UsdMeasurement.observed(Decimal("0.123")),
        ),
        replace(
            providers[1],
            cost_usd=UsdMeasurement.observed(Decimal("0.456")),
        ),
        *(
            replace(
                provider,
                cost_usd=UsdMeasurement.observed(Decimal("0")),
            )
            for provider in providers[2:]
        ),
    )

    with localcontext() as context:
        context.prec = 2
        report = PerformanceReportBuilder().build(
            run_id="run-decimal-context",
            logical_cases=cases,
            physical_requests=requests,
            provider_calls=precise_providers,
            resources=_resources(),
        )

    assert report.summary.accounting.provider_cost_usd.value == Decimal("0.579")


def test_artifacts_and_sha256sums_are_canonical_and_input_order_independent() -> None:
    cases, requests, providers = _exact_samples()
    builder = PerformanceReportBuilder()

    first = builder.build(
        run_id="run-stable",
        logical_cases=cases,
        physical_requests=requests,
        provider_calls=providers,
        resources=_resources(),
    )
    second = builder.build(
        run_id="run-stable",
        logical_cases=tuple(reversed(cases)),
        physical_requests=tuple(reversed(requests)),
        provider_calls=tuple(reversed(providers)),
        resources=_resources(),
    )

    assert first.artifacts == second.artifacts
    assert first.sha256sums_text == second.sha256sums_text
    lines = first.sha256sums_text.splitlines()
    assert lines == sorted(lines, key=lambda line: line.split("  ", 1)[1])
    assert [line.split("  ", 1)[1] for line in lines] == [
        "samples/logical-cases.json",
        "samples/physical-requests.json",
        "samples/provider-calls.json",
        "summary.json",
    ]
    for artifact in first.artifacts:
        assert artifact.sha256 == hashlib.sha256(artifact.content).hexdigest()

    tampered = EvidenceArtifact(
        path="summary.json",
        content=b"tampered",
        sha256="0" * 64,
    )
    with pytest.raises(PerformanceEvidenceError, match="digest mismatch"):
        build_sha256sums((tampered,))


@pytest.mark.parametrize(
    "unsafe_path",
    (
        "/absolute.json",
        "../escape.json",
        "samples/../escape.json",
        "samples/./summary.json",
        r"samples\summary.json",
        "samples//summary.json",
        "samples/\nsummary.json",
        "C:summary.json",
        "samples/\u2215summary.json",
    ),
)
def test_artifact_paths_are_strict_safe_relative_paths(unsafe_path: str) -> None:
    with pytest.raises(PerformanceEvidenceError, match="safe relative artifact path"):
        EvidenceArtifact(
            path=unsafe_path,
            content=b"evidence",
            sha256=hashlib.sha256(b"evidence").hexdigest(),
        )
    with pytest.raises(PerformanceEvidenceError, match="safe relative artifact path"):
        ArtifactDigest(path=unsafe_path, sha256="0" * 64)


def test_sha256sums_revalidates_paths_immediately_before_rendering() -> None:
    artifact = EvidenceArtifact(
        path="samples/evidence.json",
        content=b"evidence",
        sha256=hashlib.sha256(b"evidence").hexdigest(),
    )
    object.__setattr__(artifact, "path", "../line-injection\nfake")

    with pytest.raises(PerformanceEvidenceError, match="safe relative artifact path"):
        build_sha256sums((artifact,))


def test_nearest_rank_rule_and_models_are_strict_and_immutable() -> None:
    assert "ceil(percentile * sample_count)" in NEAREST_RANK_RULE
    assert nearest_rank([40, 10, 30, 20], 0.50) == 20
    assert nearest_rank([40, 10, 30, 20], 0.95) == 40
    with pytest.raises(PerformanceEvidenceError, match="at least one"):
        nearest_rank([], 0.95)
    with pytest.raises(PerformanceEvidenceError, match=r"\(0, 1\]"):
        nearest_rank([1], 0)
    with pytest.raises(PerformanceEvidenceError, match="requires a non-empty reason"):
        Measurement(value=None)

    measurement = Measurement.observed(0)
    assert measurement.available is True
    assert measurement.value == 0
    with pytest.raises(FrozenInstanceError):
        measurement.value = 1  # type: ignore[misc]
