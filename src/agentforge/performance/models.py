"""Immutable, network-free models for deterministic performance evidence.

Every measured value is either observed or explicitly unavailable.  ``None`` is never
silently interpreted as zero: callers must retain a reason whenever collection was not
possible.  The models are deliberately independent of the Runner and database so the same
report logic can be used by deterministic benchmarks and authorized live evidence collection.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from decimal import Decimal

Number = int | float

_SAMPLE_STATUSES = frozenset({"succeeded", "failed"})
_SHA256_LENGTH = 64
_ARTIFACT_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_MAX_ARTIFACT_PATH_LENGTH = 512


class PerformanceEvidenceError(ValueError):
    """Raised when performance evidence is malformed or internally ambiguous."""


def _nonempty(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise PerformanceEvidenceError(f"{label} must be a non-empty string")


def _positive_integer(label: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PerformanceEvidenceError(f"{label} must be a positive integer")


def _nonnegative_integer(label: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PerformanceEvidenceError(f"{label} must be a non-negative integer")


def _sha256(label: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PerformanceEvidenceError(f"{label} must be a lowercase SHA-256 hex digest")


def validate_artifact_path(value: object) -> str:
    """Require one unambiguous, portable, relative evidence-artifact path."""

    message = "path must be a safe relative artifact path"
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_ARTIFACT_PATH_LENGTH
        or value != value.strip()
        or value.startswith("/")
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PerformanceEvidenceError(message)
    segments = value.split("/")
    if any(
        segment in {"", ".", ".."} or _ARTIFACT_SEGMENT.fullmatch(segment) is None
        for segment in segments
    ):
        raise PerformanceEvidenceError(message)
    return value


def _nonnegative_measurement(label: str, measurement: Measurement) -> None:
    if not isinstance(measurement, Measurement):
        raise PerformanceEvidenceError(f"{label} must be a Measurement")
    if measurement.available and measurement.value is not None and measurement.value < 0:
        raise PerformanceEvidenceError(f"{label} cannot be negative")


def _positive_measurement(label: str, measurement: Measurement) -> None:
    _nonnegative_measurement(label, measurement)
    if measurement.available and measurement.value is not None and measurement.value <= 0:
        raise PerformanceEvidenceError(f"{label} must be greater than zero when observed")


def _token_measurement(label: str, measurement: Measurement) -> None:
    _nonnegative_measurement(label, measurement)
    if (
        measurement.available
        and measurement.value is not None
        and (isinstance(measurement.value, bool) or not isinstance(measurement.value, int))
    ):
        raise PerformanceEvidenceError(f"{label} must be an integer when observed")


@dataclass(frozen=True, slots=True)
class Measurement:
    """One numeric observation or an explicit explanation of why it is unavailable."""

    value: Number | None
    unavailable_reason: str | None = None

    def __post_init__(self) -> None:
        if self.value is None:
            if not isinstance(self.unavailable_reason, str) or not self.unavailable_reason.strip():
                raise PerformanceEvidenceError(
                    "an unavailable measurement requires a non-empty reason"
                )
            return
        if isinstance(self.value, bool) or not isinstance(self.value, (int, float)):
            raise PerformanceEvidenceError("an observed measurement must be numeric")
        if not math.isfinite(float(self.value)):
            raise PerformanceEvidenceError("an observed measurement must be finite")
        if self.unavailable_reason is not None:
            raise PerformanceEvidenceError(
                "an observed measurement cannot have an unavailable reason"
            )

    @classmethod
    def observed(cls, value: Number) -> Measurement:
        """Construct an observed numeric measurement, including a legitimate zero."""

        return cls(value=value)

    @classmethod
    def unavailable(cls, reason: str) -> Measurement:
        """Construct a missing measurement without fabricating a numeric value."""

        return cls(value=None, unavailable_reason=reason)

    @property
    def available(self) -> bool:
        return self.value is not None


@dataclass(frozen=True, slots=True)
class UsdMeasurement:
    """One exact Decimal USD observation or an explicit unavailable reason."""

    value: Decimal | None
    unavailable_reason: str | None = None

    def __post_init__(self) -> None:
        if self.value is None:
            if not isinstance(self.unavailable_reason, str) or not self.unavailable_reason.strip():
                raise PerformanceEvidenceError(
                    "an unavailable USD measurement requires a non-empty reason"
                )
            return
        if not isinstance(self.value, Decimal):
            raise PerformanceEvidenceError("an observed USD measurement must use Decimal")
        if not self.value.is_finite():
            raise PerformanceEvidenceError("an observed USD measurement must be finite")
        if self.value < 0:
            raise PerformanceEvidenceError("an observed USD measurement cannot be negative")
        if self.unavailable_reason is not None:
            raise PerformanceEvidenceError(
                "an observed USD measurement cannot have an unavailable reason"
            )

    @classmethod
    def observed(cls, value: Decimal) -> UsdMeasurement:
        return cls(value=value)

    @classmethod
    def unavailable(cls, reason: str) -> UsdMeasurement:
        return cls(value=None, unavailable_reason=reason)

    @property
    def available(self) -> bool:
        return self.value is not None


@dataclass(frozen=True, slots=True)
class LogicalCaseSample:
    """Raw timing and request-plan evidence for one logical attack case."""

    case_id: str
    case_sha256: str
    ordinal: int
    planned_physical_request_count: int
    duration_ms: Measurement
    queue_wait_ms: Measurement
    orchestration_latency_ms: Measurement

    def __post_init__(self) -> None:
        _nonempty("case_id", self.case_id)
        _sha256("case_sha256", self.case_sha256)
        _positive_integer("ordinal", self.ordinal)
        _positive_integer("planned_physical_request_count", self.planned_physical_request_count)
        _nonnegative_measurement("duration_ms", self.duration_ms)
        _nonnegative_measurement("queue_wait_ms", self.queue_wait_ms)
        _nonnegative_measurement("orchestration_latency_ms", self.orchestration_latency_ms)


@dataclass(frozen=True, slots=True)
class PhysicalRequestSample:
    """Raw target-request evidence; ``retry_index=0`` denotes the first and only send."""

    request_id: str
    case_id: str
    ordinal: int
    turn_index: int
    retry_index: int
    status: str
    latency_ms: Measurement
    request_bytes: Measurement
    response_bytes: Measurement
    error_code: str | None = None

    def __post_init__(self) -> None:
        _nonempty("request_id", self.request_id)
        _nonempty("case_id", self.case_id)
        _positive_integer("ordinal", self.ordinal)
        _positive_integer("turn_index", self.turn_index)
        _nonnegative_integer("retry_index", self.retry_index)
        if self.status not in _SAMPLE_STATUSES:
            raise PerformanceEvidenceError(
                "physical request status must be 'succeeded' or 'failed'"
            )
        if self.error_code is not None:
            _nonempty("error_code", self.error_code)
        _nonnegative_measurement("latency_ms", self.latency_ms)
        _nonnegative_measurement("request_bytes", self.request_bytes)
        _nonnegative_measurement("response_bytes", self.response_bytes)


@dataclass(frozen=True, slots=True)
class ProviderSample:
    """Raw hosted-agent call timing, usage, cost, and status evidence."""

    call_id: str
    role: str
    ordinal: int
    status: str
    latency_ms: Measurement
    input_tokens: Measurement
    output_tokens: Measurement
    reasoning_tokens: Measurement
    cost_usd: UsdMeasurement
    case_id: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        _nonempty("call_id", self.call_id)
        _nonempty("role", self.role)
        _positive_integer("ordinal", self.ordinal)
        if self.status not in _SAMPLE_STATUSES:
            raise PerformanceEvidenceError("provider status must be 'succeeded' or 'failed'")
        if self.case_id is not None:
            _nonempty("case_id", self.case_id)
        if self.error_code is not None:
            _nonempty("error_code", self.error_code)
        _nonnegative_measurement("latency_ms", self.latency_ms)
        _token_measurement("input_tokens", self.input_tokens)
        _token_measurement("output_tokens", self.output_tokens)
        _token_measurement("reasoning_tokens", self.reasoning_tokens)
        if not isinstance(self.cost_usd, UsdMeasurement):
            raise PerformanceEvidenceError("cost_usd must be a UsdMeasurement")


@dataclass(frozen=True, slots=True)
class RunResourceSample:
    """Before/after resource observations for one bounded run."""

    elapsed_ms: Measurement
    cpu_time_ms: Measurement
    peak_rss_bytes: Measurement
    postgres_bytes_before: Measurement
    postgres_bytes_after: Measurement
    artifact_bytes_before: Measurement
    artifact_bytes_after: Measurement

    def __post_init__(self) -> None:
        _positive_measurement("elapsed_ms", self.elapsed_ms)
        _nonnegative_measurement("cpu_time_ms", self.cpu_time_ms)
        _nonnegative_measurement("peak_rss_bytes", self.peak_rss_bytes)
        _nonnegative_measurement("postgres_bytes_before", self.postgres_bytes_before)
        _nonnegative_measurement("postgres_bytes_after", self.postgres_bytes_after)
        _nonnegative_measurement("artifact_bytes_before", self.artifact_bytes_before)
        _nonnegative_measurement("artifact_bytes_after", self.artifact_bytes_after)


@dataclass(frozen=True, slots=True)
class DistributionSummary:
    """A complete nearest-rank latency distribution or explicit unavailability."""

    sample_count: int
    observed_count: int
    p50_ms: Measurement
    p95_ms: Measurement


@dataclass(frozen=True, slots=True)
class ReconciliationSummary:
    expected_logical_case_count: int
    observed_logical_case_count: int
    expected_physical_request_count: int
    observed_physical_request_count: int
    expected_retry_count: int
    observed_retry_count: int
    expected_turn_distribution: tuple[tuple[int, int], ...]
    observed_turn_distribution: tuple[tuple[int, int], ...]
    expected_provider_role_counts: tuple[tuple[str, int], ...]
    observed_provider_role_counts: tuple[tuple[str, int], ...]
    passed: bool
    violations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LatencySummary:
    logical_case: DistributionSummary
    queue_wait: DistributionSummary
    orchestration: DistributionSummary
    target: DistributionSummary
    provider: DistributionSummary


@dataclass(frozen=True, slots=True)
class ThroughputSummary:
    logical_cases_per_second: Measurement
    physical_requests_per_second: Measurement


@dataclass(frozen=True, slots=True)
class ErrorSummary:
    target_error_count: int
    target_error_rate: Measurement
    provider_error_count: int
    provider_error_rate: Measurement


@dataclass(frozen=True, slots=True)
class ResourceSummary:
    elapsed_ms: Measurement
    cpu_time_ms: Measurement
    cpu_utilization_ratio: Measurement
    peak_rss_bytes: Measurement
    postgres_growth_bytes: Measurement
    artifact_growth_bytes: Measurement
    total_storage_growth_bytes: Measurement
    storage_throughput_bytes_per_second: Measurement


@dataclass(frozen=True, slots=True)
class AccountingSummary:
    request_bytes: Measurement
    response_bytes: Measurement
    provider_input_tokens: Measurement
    provider_output_tokens: Measurement
    provider_reasoning_tokens: Measurement
    provider_cost_usd: UsdMeasurement


@dataclass(frozen=True, slots=True)
class BottleneckCandidate:
    component: str
    p95_ms: Measurement


@dataclass(frozen=True, slots=True)
class BottleneckSummary:
    component: str | None
    p95_ms: Measurement
    candidates: tuple[BottleneckCandidate, ...]


@dataclass(frozen=True, slots=True)
class ArtifactDigest:
    path: str
    sha256: str

    def __post_init__(self) -> None:
        validate_artifact_path(self.path)
        _sha256("artifact sha256", self.sha256)


@dataclass(frozen=True, slots=True)
class PerformanceSummary:
    schema_version: str
    run_id: str
    percentile_rule: str
    reconciliation: ReconciliationSummary
    evidence_complete: bool
    unavailable_metrics: tuple[str, ...]
    latency: LatencySummary
    throughput: ThroughputSummary
    errors: ErrorSummary
    resources: ResourceSummary
    accounting: AccountingSummary
    bottleneck: BottleneckSummary
    source_artifacts: tuple[ArtifactDigest, ...]


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    path: str
    content: bytes
    sha256: str

    def __post_init__(self) -> None:
        validate_artifact_path(self.path)
        if not isinstance(self.content, bytes):
            raise PerformanceEvidenceError("artifact content must be immutable bytes")
        _sha256("artifact sha256", self.sha256)


@dataclass(frozen=True, slots=True)
class PerformanceReport:
    summary: PerformanceSummary
    artifacts: tuple[EvidenceArtifact, ...]
    sha256sums_text: str
