"""Pure deterministic aggregation and hashing for performance evidence."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from decimal import Decimal
from typing import Any

from agentforge.performance.models import (
    AccountingSummary,
    ArtifactDigest,
    BottleneckCandidate,
    BottleneckSummary,
    DistributionSummary,
    ErrorSummary,
    EvidenceArtifact,
    LatencySummary,
    LogicalCaseSample,
    Measurement,
    PerformanceEvidenceError,
    PerformanceReport,
    PerformanceSummary,
    PhysicalRequestSample,
    ProviderSample,
    ReconciliationSummary,
    ResourceSummary,
    RunResourceSample,
    ThroughputSummary,
    UsdMeasurement,
    validate_artifact_path,
)

NEAREST_RANK_RULE = (
    "Sort all values ascending and select the 1-indexed value at "
    "rank ceil(percentile * sample_count); percentiles require every sample to be observed."
)
_DEFAULT_TURN_DISTRIBUTION = {1: 79, 2: 21}
_DEFAULT_PROVIDER_ROLE_COUNTS = {"judge": 100}


def nearest_rank(values: Sequence[int | float], percentile: float) -> int | float:
    """Return the nearest-rank percentile.

    The rule is intentionally singular and reproducible: sort ascending and choose the
    1-indexed rank ``ceil(percentile * n)``.  Empty input and percentiles outside ``(0, 1]``
    are rejected rather than represented as zero.
    """

    if not values:
        raise PerformanceEvidenceError("nearest-rank percentile requires at least one value")
    if (
        isinstance(percentile, bool)
        or not isinstance(percentile, (int, float))
        or not math.isfinite(float(percentile))
        or not 0 < percentile <= 1
    ):
        raise PerformanceEvidenceError("percentile must be a finite number in (0, 1]")
    normalized: list[int | float] = []
    for value in values:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise PerformanceEvidenceError(
                "nearest-rank values must be finite numeric observations"
            )
        normalized.append(value)
    ordered = sorted(normalized)
    rank = math.ceil(percentile * len(ordered))
    return ordered[rank - 1]


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize supported immutable evidence into canonical UTF-8 JSON bytes."""

    return json.dumps(
        _canonical_data(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return a deterministic SHA-256 over :func:`canonical_json_bytes`."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _decimal_text(value: Decimal) -> str:
    """Encode one finite Decimal exactly without consulting the ambient Decimal context."""

    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if rendered in {"", "-0"}:
        return "0"
    return rendered


def build_sha256sums(artifacts: Iterable[EvidenceArtifact]) -> str:
    """Return standard two-space ``SHA256SUMS`` lines sorted by artifact path."""

    entries = tuple(artifacts)
    paths = [artifact.path for artifact in entries]
    if len(paths) != len(set(paths)):
        raise PerformanceEvidenceError("SHA256SUMS cannot contain duplicate artifact paths")
    for artifact in entries:
        validate_artifact_path(artifact.path)
        actual = hashlib.sha256(artifact.content).hexdigest()
        if actual != artifact.sha256:
            raise PerformanceEvidenceError(f"artifact digest mismatch for {artifact.path}")
    return "".join(
        f"{artifact.sha256}  {artifact.path}\n"
        for artifact in sorted(entries, key=lambda item: item.path)
    )


class PerformanceReportBuilder:
    """Build one deterministic report without database, network, or filesystem access."""

    def __init__(
        self,
        *,
        expected_logical_case_count: int = 100,
        expected_physical_request_count: int = 121,
        expected_retry_count: int = 0,
        expected_turn_distribution: Mapping[int, int] | None = None,
        expected_provider_role_counts: Mapping[str, int] | None = None,
    ) -> None:
        for label, value in (
            ("expected_logical_case_count", expected_logical_case_count),
            ("expected_physical_request_count", expected_physical_request_count),
            ("expected_retry_count", expected_retry_count),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < (0 if label == "expected_retry_count" else 1)
            ):
                raise PerformanceEvidenceError(f"{label} is invalid")
        self.expected_logical_case_count = expected_logical_case_count
        self.expected_physical_request_count = expected_physical_request_count
        self.expected_retry_count = expected_retry_count
        self.expected_turn_distribution = self._expected_count_pairs(
            (
                _DEFAULT_TURN_DISTRIBUTION
                if expected_turn_distribution is None
                else expected_turn_distribution
            ),
            key_kind="turn",
        )
        self.expected_provider_role_counts = self._expected_count_pairs(
            (
                _DEFAULT_PROVIDER_ROLE_COUNTS
                if expected_provider_role_counts is None
                else expected_provider_role_counts
            ),
            key_kind="role",
        )
        if (
            sum(count for _turns, count in self.expected_turn_distribution)
            != self.expected_logical_case_count
        ):
            raise PerformanceEvidenceError(
                "expected turn distribution must equal expected logical case count"
            )
        if (
            sum(turns * count for turns, count in self.expected_turn_distribution)
            != self.expected_physical_request_count
        ):
            raise PerformanceEvidenceError(
                "expected turn distribution must equal expected physical request count"
            )

    def build(
        self,
        *,
        run_id: str,
        logical_cases: Sequence[LogicalCaseSample],
        physical_requests: Sequence[PhysicalRequestSample],
        provider_calls: Sequence[ProviderSample],
        resources: RunResourceSample,
    ) -> PerformanceReport:
        """Reconcile, aggregate, content-address, and package immutable evidence."""

        if not isinstance(run_id, str) or not run_id.strip():
            raise PerformanceEvidenceError("run_id must be a non-empty string")
        if not isinstance(resources, RunResourceSample):
            raise PerformanceEvidenceError("resources must be a RunResourceSample")

        cases = self._ordered(
            logical_cases,
            model=LogicalCaseSample,
            id_attribute="case_id",
            label="logical case",
        )
        requests = self._ordered(
            physical_requests,
            model=PhysicalRequestSample,
            id_attribute="request_id",
            label="physical request",
        )
        calls = self._ordered(
            provider_calls,
            model=ProviderSample,
            id_attribute="call_id",
            label="provider call",
        )

        logical_artifact = self._sample_artifact(
            "samples/logical-cases.json", "logical_case", cases
        )
        request_artifact = self._sample_artifact(
            "samples/physical-requests.json", "physical_request", requests
        )
        provider_artifact = self._sample_artifact(
            "samples/provider-calls.json", "provider_call", calls
        )
        source_artifacts = tuple(
            ArtifactDigest(path=item.path, sha256=item.sha256)
            for item in sorted(
                (logical_artifact, request_artifact, provider_artifact),
                key=lambda artifact: artifact.path,
            )
        )

        reconciliation = self._reconcile(cases, requests, calls)
        latency = LatencySummary(
            logical_case=_distribution(
                tuple(sample.duration_ms for sample in cases), "logical_case.duration_ms"
            ),
            queue_wait=_distribution(
                tuple(sample.queue_wait_ms for sample in cases),
                "logical_case.queue_wait_ms",
            ),
            orchestration=_distribution(
                tuple(sample.orchestration_latency_ms for sample in cases),
                "logical_case.orchestration_latency_ms",
            ),
            target=_distribution(
                tuple(sample.latency_ms for sample in requests),
                "physical_request.latency_ms",
            ),
            provider=_distribution(
                tuple(sample.latency_ms for sample in calls),
                "provider_call.latency_ms",
            ),
        )
        throughput = ThroughputSummary(
            logical_cases_per_second=_per_second(
                len(cases), resources.elapsed_ms, "logical throughput"
            ),
            physical_requests_per_second=_per_second(
                len(requests), resources.elapsed_ms, "physical-request throughput"
            ),
        )
        errors = ErrorSummary(
            target_error_count=sum(sample.status == "failed" for sample in requests),
            target_error_rate=_error_rate(requests, "target error rate"),
            provider_error_count=sum(sample.status == "failed" for sample in calls),
            provider_error_rate=_error_rate(calls, "provider error rate"),
        )
        resource_summary = _resources(resources)
        accounting = AccountingSummary(
            request_bytes=_sum_complete(
                tuple(sample.request_bytes for sample in requests), "request bytes"
            ),
            response_bytes=_sum_complete(
                tuple(sample.response_bytes for sample in requests), "response bytes"
            ),
            provider_input_tokens=_sum_complete(
                tuple(sample.input_tokens for sample in calls), "provider input tokens"
            ),
            provider_output_tokens=_sum_complete(
                tuple(sample.output_tokens for sample in calls), "provider output tokens"
            ),
            provider_reasoning_tokens=_sum_complete(
                tuple(sample.reasoning_tokens for sample in calls),
                "provider reasoning tokens",
            ),
            provider_cost_usd=_sum_usd_complete(
                tuple(sample.cost_usd for sample in calls), "provider cost"
            ),
        )
        bottleneck = _bottleneck(latency)
        unavailable = _unavailable_metric_paths(cases, requests, calls, resources)
        summary = PerformanceSummary(
            schema_version="1",
            run_id=run_id,
            percentile_rule=NEAREST_RANK_RULE,
            reconciliation=reconciliation,
            evidence_complete=reconciliation.passed and not unavailable,
            unavailable_metrics=unavailable,
            latency=latency,
            throughput=throughput,
            errors=errors,
            resources=resource_summary,
            accounting=accounting,
            bottleneck=bottleneck,
            source_artifacts=source_artifacts,
        )
        summary_artifact = self._artifact("summary.json", canonical_json_bytes(summary))
        artifacts = tuple(
            sorted(
                (
                    logical_artifact,
                    request_artifact,
                    provider_artifact,
                    summary_artifact,
                ),
                key=lambda artifact: artifact.path,
            )
        )
        return PerformanceReport(
            summary=summary,
            artifacts=artifacts,
            sha256sums_text=build_sha256sums(artifacts),
        )

    def _reconcile(
        self,
        cases: tuple[LogicalCaseSample, ...],
        requests: tuple[PhysicalRequestSample, ...],
        calls: tuple[ProviderSample, ...],
    ) -> ReconciliationSummary:
        violations: list[str] = []
        if len(cases) != self.expected_logical_case_count:
            violations.append("logical_case_count_mismatch")
        if len(requests) != self.expected_physical_request_count:
            violations.append("physical_request_count_mismatch")

        retry_count = sum(sample.retry_index > 0 for sample in requests)
        if retry_count != self.expected_retry_count:
            violations.append("retry_count_mismatch")

        observed_turn_counts = Counter(case.planned_physical_request_count for case in cases)
        observed_turn_distribution = tuple(sorted(observed_turn_counts.items()))
        if observed_turn_distribution != self.expected_turn_distribution:
            violations.append("turn_distribution_mismatch")
        permitted_turn_counts = {turns for turns, _count in self.expected_turn_distribution}
        for case in cases:
            if case.planned_physical_request_count not in permitted_turn_counts:
                violations.append(
                    f"turn_count_not_allowed:{case.case_id}:{case.planned_physical_request_count}"
                )

        observed_provider_counts = Counter(call.role for call in calls)
        observed_provider_role_counts = tuple(sorted(observed_provider_counts.items()))
        if observed_provider_role_counts != self.expected_provider_role_counts:
            violations.append("provider_role_distribution_mismatch")
        for role, expected_count in self.expected_provider_role_counts:
            observed_count = observed_provider_counts[role]
            if observed_count != expected_count:
                violations.append(
                    f"provider_role_count_mismatch:{role}:"
                    f"expected={expected_count}:observed={observed_count}"
                )

        case_ids = {sample.case_id for sample in cases}
        judge_calls_by_case = Counter(
            call.case_id for call in calls if call.role == "judge" and call.case_id in case_ids
        )
        for case_id in sorted(case_ids):
            if judge_calls_by_case[case_id] != 1:
                violations.append(
                    f"judge_case_call_count_mismatch:{case_id}:{judge_calls_by_case[case_id]}"
                )
        for call in calls:
            if call.role == "judge" and call.case_id not in case_ids:
                violations.append(f"judge_call_unknown_case:{call.call_id}")

        unknown_case_ids = sorted(
            {sample.case_id for sample in requests if sample.case_id not in case_ids}
        )
        violations.extend(f"unknown_request_case:{case_id}" for case_id in unknown_case_ids)

        observed_by_case = Counter(sample.case_id for sample in requests)
        first_send_turns: dict[str, set[int]] = {}
        for request in requests:
            if request.retry_index == 0:
                first_send_turns.setdefault(request.case_id, set()).add(request.turn_index)
        for case in cases:
            if observed_by_case[case.case_id] != case.planned_physical_request_count:
                violations.append(f"case_request_count_mismatch:{case.case_id}")
            expected_turns = set(range(1, case.planned_physical_request_count + 1))
            if first_send_turns.get(case.case_id, set()) != expected_turns:
                violations.append(f"case_turn_sequence_mismatch:{case.case_id}")

        if (
            sum(case.planned_physical_request_count for case in cases)
            != self.expected_physical_request_count
        ):
            violations.append("planned_physical_request_count_mismatch")

        normalized_violations = tuple(sorted(set(violations)))
        return ReconciliationSummary(
            expected_logical_case_count=self.expected_logical_case_count,
            observed_logical_case_count=len(cases),
            expected_physical_request_count=self.expected_physical_request_count,
            observed_physical_request_count=len(requests),
            expected_retry_count=self.expected_retry_count,
            observed_retry_count=retry_count,
            expected_turn_distribution=self.expected_turn_distribution,
            observed_turn_distribution=observed_turn_distribution,
            expected_provider_role_counts=self.expected_provider_role_counts,
            observed_provider_role_counts=observed_provider_role_counts,
            passed=not normalized_violations,
            violations=normalized_violations,
        )

    @staticmethod
    def _expected_count_pairs(
        values: Mapping[Any, int],
        *,
        key_kind: str,
    ) -> tuple[tuple[Any, int], ...]:
        if not isinstance(values, Mapping) or not values:
            raise PerformanceEvidenceError(
                f"expected {key_kind} counts must be a non-empty mapping"
            )
        normalized: list[tuple[Any, int]] = []
        for key, count in values.items():
            if key_kind == "turn":
                if isinstance(key, bool) or not isinstance(key, int) or key < 1:
                    raise PerformanceEvidenceError(
                        "expected turn-count keys must be positive integers"
                    )
            elif not isinstance(key, str) or not key.strip():
                raise PerformanceEvidenceError(
                    "expected provider-role keys must be non-empty strings"
                )
            if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                raise PerformanceEvidenceError(
                    f"expected {key_kind} counts must be positive integers"
                )
            normalized.append((key, count))
        return tuple(sorted(normalized))

    @staticmethod
    def _ordered(
        values: Sequence[Any],
        *,
        model: type,
        id_attribute: str,
        label: str,
    ) -> tuple[Any, ...]:
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise PerformanceEvidenceError(f"{label} samples must be a sequence")
        items = tuple(values)
        if any(not isinstance(item, model) for item in items):
            raise PerformanceEvidenceError(f"every {label} sample must use {model.__name__}")
        identifiers = [getattr(item, id_attribute) for item in items]
        ordinals = [item.ordinal for item in items]
        if len(identifiers) != len(set(identifiers)):
            raise PerformanceEvidenceError(f"{label} identifiers must be unique")
        if len(ordinals) != len(set(ordinals)):
            raise PerformanceEvidenceError(f"{label} ordinals must be unique")
        if sorted(ordinals) != list(range(1, len(items) + 1)):
            raise PerformanceEvidenceError(f"{label} ordinals must be contiguous and start at one")
        return tuple(sorted(items, key=lambda item: (item.ordinal, getattr(item, id_attribute))))

    @classmethod
    def _sample_artifact(
        cls, path: str, sample_type: str, samples: Sequence[Any]
    ) -> EvidenceArtifact:
        records = []
        for sample in samples:
            payload = _canonical_data(sample)
            records.append(
                {
                    "content_sha256": canonical_sha256(payload),
                    **payload,
                }
            )
        document = {
            "schema_version": "1",
            "sample_type": sample_type,
            "samples": records,
        }
        return cls._artifact(path, canonical_json_bytes(document))

    @staticmethod
    def _artifact(path: str, content: bytes) -> EvidenceArtifact:
        return EvidenceArtifact(
            path=path,
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
        )


def _distribution(measurements: tuple[Measurement, ...], label: str) -> DistributionSummary:
    observed = tuple(measurement.value for measurement in measurements if measurement.available)
    if not measurements:
        reason = f"{label}: no samples"
        p50 = Measurement.unavailable(reason)
        p95 = Measurement.unavailable(reason)
    elif len(observed) != len(measurements):
        reason = (
            f"{label}: {len(measurements) - len(observed)} of "
            f"{len(measurements)} samples unavailable"
        )
        p50 = Measurement.unavailable(reason)
        p95 = Measurement.unavailable(reason)
    else:
        p50 = Measurement.observed(nearest_rank(observed, 0.50))
        p95 = Measurement.observed(nearest_rank(observed, 0.95))
    return DistributionSummary(
        sample_count=len(measurements),
        observed_count=len(observed),
        p50_ms=p50,
        p95_ms=p95,
    )


def _sum_complete(measurements: tuple[Measurement, ...], label: str) -> Measurement:
    if not measurements:
        return Measurement.unavailable(f"{label}: no samples")
    unavailable = sum(not measurement.available for measurement in measurements)
    if unavailable:
        return Measurement.unavailable(
            f"{label}: {unavailable} of {len(measurements)} samples unavailable"
        )
    return Measurement.observed(
        sum(measurement.value for measurement in measurements if measurement.value is not None)
    )


def _sum_usd_complete(measurements: tuple[UsdMeasurement, ...], label: str) -> UsdMeasurement:
    if not measurements:
        return UsdMeasurement.unavailable(f"{label}: no samples")
    unavailable = sum(not measurement.available for measurement in measurements)
    if unavailable:
        return UsdMeasurement.unavailable(
            f"{label}: {unavailable} of {len(measurements)} samples unavailable"
        )
    values: list[Decimal] = []
    for measurement in measurements:
        assert measurement.value is not None
        values.append(measurement.value)
    return UsdMeasurement.observed(_sum_decimals_exact(values))


def _sum_decimals_exact(values: Sequence[Decimal]) -> Decimal:
    """Sum finite Decimals by aligned integer coefficients, independent of context precision."""

    minimum_exponent = min(value.as_tuple().exponent for value in values)
    total_coefficient = 0
    for value in values:
        sign, digits, exponent = value.as_tuple()
        coefficient = int("".join(str(digit) for digit in digits) or "0")
        if sign:
            coefficient = -coefficient
        total_coefficient += coefficient * (10 ** (exponent - minimum_exponent))
    if total_coefficient == 0:
        return Decimal("0")
    sign = int(total_coefficient < 0)
    result_digits = tuple(int(character) for character in str(abs(total_coefficient)))
    return Decimal((sign, result_digits, minimum_exponent))


def _per_second(count: int, elapsed_ms: Measurement, label: str) -> Measurement:
    if not elapsed_ms.available or elapsed_ms.value is None:
        return Measurement.unavailable(
            f"{label}: elapsed time unavailable ({elapsed_ms.unavailable_reason})"
        )
    return Measurement.observed(count / (float(elapsed_ms.value) / 1000.0))


def _error_rate(samples: Sequence[Any], label: str) -> Measurement:
    if not samples:
        return Measurement.unavailable(f"{label}: no samples")
    return Measurement.observed(sum(sample.status == "failed" for sample in samples) / len(samples))


def _delta(before: Measurement, after: Measurement, label: str) -> Measurement:
    if not before.available or not after.available:
        return Measurement.unavailable(f"{label}: before/after value unavailable")
    assert before.value is not None
    assert after.value is not None
    return Measurement.observed(after.value - before.value)


def _add_complete(measurements: tuple[Measurement, ...], label: str) -> Measurement:
    if any(not measurement.available for measurement in measurements):
        return Measurement.unavailable(f"{label}: component unavailable")
    return Measurement.observed(
        sum(measurement.value for measurement in measurements if measurement.value is not None)
    )


def _ratio(
    numerator: Measurement,
    denominator: Measurement,
    label: str,
    *,
    denominator_scale: float = 1.0,
) -> Measurement:
    if not numerator.available or not denominator.available:
        return Measurement.unavailable(f"{label}: input unavailable")
    assert numerator.value is not None
    assert denominator.value is not None
    if denominator.value <= 0:
        return Measurement.unavailable(f"{label}: denominator is not positive")
    return Measurement.observed(
        float(numerator.value) / (float(denominator.value) / denominator_scale)
    )


def _resources(resources: RunResourceSample) -> ResourceSummary:
    postgres_growth = _delta(
        resources.postgres_bytes_before,
        resources.postgres_bytes_after,
        "PostgreSQL growth",
    )
    artifact_growth = _delta(
        resources.artifact_bytes_before,
        resources.artifact_bytes_after,
        "artifact growth",
    )
    total_growth = _add_complete((postgres_growth, artifact_growth), "total storage growth")
    return ResourceSummary(
        elapsed_ms=resources.elapsed_ms,
        cpu_time_ms=resources.cpu_time_ms,
        cpu_utilization_ratio=_ratio(
            resources.cpu_time_ms, resources.elapsed_ms, "CPU utilization"
        ),
        peak_rss_bytes=resources.peak_rss_bytes,
        postgres_growth_bytes=postgres_growth,
        artifact_growth_bytes=artifact_growth,
        total_storage_growth_bytes=total_growth,
        storage_throughput_bytes_per_second=_ratio(
            total_growth,
            resources.elapsed_ms,
            "storage throughput",
            denominator_scale=1000.0,
        ),
    )


def _bottleneck(latency: LatencySummary) -> BottleneckSummary:
    candidates = (
        BottleneckCandidate(component="orchestration", p95_ms=latency.orchestration.p95_ms),
        BottleneckCandidate(component="provider", p95_ms=latency.provider.p95_ms),
        BottleneckCandidate(component="target", p95_ms=latency.target.p95_ms),
    )
    unavailable = tuple(
        candidate.component for candidate in candidates if not candidate.p95_ms.available
    )
    if unavailable:
        return BottleneckSummary(
            component=None,
            p95_ms=Measurement.unavailable(
                "bottleneck unavailable; missing p95 for " + ", ".join(unavailable)
            ),
            candidates=candidates,
        )
    for candidate in candidates:
        assert candidate.p95_ms.value is not None
    selected = sorted(
        candidates,
        key=lambda candidate: (
            -float(candidate.p95_ms.value),
            candidate.component,
        ),
    )[0]
    return BottleneckSummary(
        component=selected.component,
        p95_ms=selected.p95_ms,
        candidates=candidates,
    )


def _unavailable_metric_paths(
    cases: tuple[LogicalCaseSample, ...],
    requests: tuple[PhysicalRequestSample, ...],
    calls: tuple[ProviderSample, ...],
    resources: RunResourceSample,
) -> tuple[str, ...]:
    unavailable: list[str] = []
    groups = (
        ("logical_case", cases, "case_id"),
        ("physical_request", requests, "request_id"),
        ("provider_call", calls, "call_id"),
    )
    for prefix, samples, identifier_name in groups:
        if not samples:
            unavailable.append(f"{prefix}:no_samples")
            continue
        for sample in samples:
            identifier = getattr(sample, identifier_name)
            for field in dataclasses.fields(sample):
                measurement = getattr(sample, field.name)
                if (
                    isinstance(measurement, (Measurement, UsdMeasurement))
                    and not measurement.available
                ):
                    unavailable.append(
                        f"{prefix}[{identifier}].{field.name}:{measurement.unavailable_reason}"
                    )
    for field in dataclasses.fields(resources):
        measurement = getattr(resources, field.name)
        if isinstance(measurement, Measurement) and not measurement.available:
            unavailable.append(f"resources.{field.name}:{measurement.unavailable_reason}")
    return tuple(sorted(unavailable))


def _canonical_data(value: Any) -> Any:
    if isinstance(value, UsdMeasurement):
        return {
            "available": value.available,
            "unavailable_reason": value.unavailable_reason,
            "value": _decimal_text(value.value) if value.value is not None else None,
        }
    if isinstance(value, Measurement):
        return {
            "available": value.available,
            "unavailable_reason": value.unavailable_reason,
            "value": value.value,
        }
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _canonical_data(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_data(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_canonical_data(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise PerformanceEvidenceError(f"value of type {type(value).__name__} is not canonicalizable")
