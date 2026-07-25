"""Offline, content-addressed performance evidence for one reviewed corpus.

This module deliberately measures only local corpus admission work: immutable case
verification, canonical serialization, batching, and artifact production.  It never
labels those observations as target, provider, Railway, or end-to-end campaign
performance.  Live-run latency and cost remain separate evidence inputs.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import resource
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentforge.agents.hosted import HOSTED_MAX_PHYSICAL_CALLS
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.campaign.corpus import AuthoredCorpus, verified_case_payload
from agentforge.performance.report import NEAREST_RANK_RULE, canonical_json_bytes, nearest_rank

_RELEASE_SHA = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_EXPECTED_CAP_FIELDS: dict[str, int | float] = {
    "budget_usd": 50.0,
    "max_attempts_per_run": 130,
    "target_requests_per_second": 0.5,
    "run_timeout_seconds": 3600.0,
    "logical_case_limit": 100,
    "physical_request_limit": 121,
    "target_retries_per_turn": 0,
}
_BOUND_CAP_FILES = (
    "config/live-target-catalog.production.json",
    "config/live-target-catalog.staging.json",
    "config/targets/clinical-copilot-20260724.json",
    "docs/evidence/authorization-requests/caps.json",
)


class CorpusBaselineError(ValueError):
    """Raised when corpus performance evidence cannot be produced unambiguously."""


@dataclass(frozen=True, slots=True)
class BoundCapArtifact:
    """One repository file whose run caps are exact and content-addressed."""

    path: str
    sha256: str

    def __post_init__(self) -> None:
        if self.path not in _BOUND_CAP_FILES:
            raise CorpusBaselineError("bound cap artifact path is not in the closed file set")
        if not isinstance(self.sha256, str) or _SHA256.fullmatch(self.sha256) is None:
            raise CorpusBaselineError("bound cap artifact digest must be one lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class ArtifactWriteResult:
    """Paths and digests produced by :func:`write_corpus_baseline_artifacts`."""

    output_directory: Path
    artifact_sha256s: tuple[tuple[str, str], ...]


def _case_identity(case: Any, ordinal: int) -> str:
    instance_id = getattr(case, "instance_id", None)
    if isinstance(instance_id, str) and instance_id.strip():
        return instance_id
    payload = verified_case_payload(case)
    case_id = payload.get("case_id")
    if isinstance(case_id, str) and case_id.strip():
        return case_id
    return f"case-{ordinal:03d}"


def _turn_count(payload: Mapping[str, Any]) -> int:
    turns = payload.get("input_sequence")
    if not isinstance(turns, list) or not turns:
        raise CorpusBaselineError("every admitted case must declare a non-empty input_sequence")
    return len(turns)


def _validate_release_sha(release_sha: str) -> None:
    if not isinstance(release_sha, str) or _RELEASE_SHA.fullmatch(release_sha) is None:
        raise CorpusBaselineError("release_sha must be one lowercase 40- or 64-character hex SHA")


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or not run_id.strip():
        raise CorpusBaselineError("run_id must be a non-empty string")


def _normalized_cap_payload(payload: Mapping[str, Any]) -> dict[str, int | float]:
    return {field: payload.get(field) for field in _EXPECTED_CAP_FIELDS}


def verify_bound_caps(repo_root: Path) -> tuple[BoundCapArtifact, ...]:
    """Verify the reviewed 100/121/0, $50 envelope across its four bound files."""

    root = repo_root.resolve()
    artifacts: list[BoundCapArtifact] = []
    for relative in _BOUND_CAP_FILES:
        path = root / relative
        try:
            raw = path.read_bytes()
            value = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise CorpusBaselineError(
                f"bound cap file is unavailable or invalid: {relative}"
            ) from exc

        cap_payloads: Sequence[Mapping[str, Any]]
        if relative.endswith("/caps.json"):
            if not isinstance(value, dict):
                raise CorpusBaselineError(f"bound cap file must contain an object: {relative}")
            cap_payloads = (value,)
        else:
            if not isinstance(value, list) or not value:
                raise CorpusBaselineError(
                    f"bound target catalog must contain at least one entry: {relative}"
                )
            extracted: list[Mapping[str, Any]] = []
            for entry in value:
                if not isinstance(entry, dict):
                    raise CorpusBaselineError(f"bound target catalog entry is invalid: {relative}")
                target = entry.get("target")
                caps = target.get("safety_caps") if isinstance(target, dict) else None
                if not isinstance(caps, dict):
                    raise CorpusBaselineError(
                        f"bound target catalog entry has no safety_caps: {relative}"
                    )
                extracted.append(caps)
            cap_payloads = tuple(extracted)

        for caps in cap_payloads:
            if _normalized_cap_payload(caps) != _EXPECTED_CAP_FIELDS:
                raise CorpusBaselineError(
                    f"run caps differ from the reviewed 100/121/0, $50 envelope: {relative}"
                )
        artifacts.append(
            BoundCapArtifact(
                path=relative,
                sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
    return tuple(artifacts)


def build_run_authorization_envelope(
    *,
    corpus: AuthoredCorpus,
    release_sha: str,
    run_id: str,
    bound_caps: Sequence[BoundCapArtifact],
    batch_size: int | None = None,
) -> dict[str, Any]:
    """Build a non-authorizing, deterministic envelope for a reviewed corpus.

    The returned document binds the exact case/turn counts and a deterministic batch
    plan.  It is preparation evidence only; it cannot mint or replace a two-person run
    authorization.
    """

    if not isinstance(corpus, AuthoredCorpus):
        raise CorpusBaselineError("corpus must be one resolved AuthoredCorpus")
    _validate_release_sha(release_sha)
    _validate_run_id(run_id)
    expected_paths = set(_BOUND_CAP_FILES)
    supplied_paths = {
        artifact.path for artifact in bound_caps if isinstance(artifact, BoundCapArtifact)
    }
    if len(bound_caps) != len(_BOUND_CAP_FILES) or supplied_paths != expected_paths:
        raise CorpusBaselineError("the envelope requires the exact four bound cap artifacts")

    per_case_calls = sum(
        DEFAULT_HOSTED_GENERATION_POLICY.required_logical_calls(case_count=1).values()
    )
    safe_batch_size = HOSTED_MAX_PHYSICAL_CALLS // per_case_calls
    selected_batch_size = safe_batch_size if batch_size is None else batch_size
    if (
        isinstance(selected_batch_size, bool)
        or not isinstance(selected_batch_size, int)
        or selected_batch_size < 1
    ):
        raise CorpusBaselineError("batch_size must be a positive integer")
    required_for_selected_batch = sum(
        DEFAULT_HOSTED_GENERATION_POLICY.required_logical_calls(
            case_count=selected_batch_size
        ).values()
    )
    if required_for_selected_batch > HOSTED_MAX_PHYSICAL_CALLS:
        raise CorpusBaselineError(
            "batch_size exceeds the cumulative four-role "
            f"HOSTED_MAX_PHYSICAL_CALLS={HOSTED_MAX_PHYSICAL_CALLS} authority"
        )

    cases: list[dict[str, Any]] = []
    for ordinal, case in enumerate(corpus.cases, start=1):
        payload = verified_case_payload(case)
        cases.append(
            {
                "case_id": _case_identity(case, ordinal),
                "case_sha256": case.content_hash,
                "turn_count": _turn_count(payload),
            }
        )
    if not cases:
        raise CorpusBaselineError("the reviewed corpus contains no cases")

    batches: list[dict[str, Any]] = []
    for batch_index, offset in enumerate(range(0, len(cases), selected_batch_size), start=1):
        batch_cases = cases[offset : offset + selected_batch_size]
        role_calls = DEFAULT_HOSTED_GENERATION_POLICY.required_logical_calls(
            case_count=len(batch_cases)
        )
        batches.append(
            {
                "batch_id": f"batch-{batch_index:02d}",
                "logical_case_count": len(batch_cases),
                "target_physical_request_count": sum(
                    int(case["turn_count"]) for case in batch_cases
                ),
                "target_retries_per_turn": 0,
                "hosted_role_call_counts": dict(sorted(role_calls.items())),
                "hosted_global_call_count": sum(role_calls.values()),
                "case_refs": [
                    {
                        "case_id": case["case_id"],
                        "case_sha256": case["case_sha256"],
                    }
                    for case in batch_cases
                ],
            }
        )

    logical_count = len(cases)
    physical_count = sum(int(case["turn_count"]) for case in cases)
    expected_triple = {
        "logical_case_limit": logical_count,
        "physical_request_limit": physical_count,
        "target_retries_per_turn": 0,
    }
    configured_triple = {
        field: _EXPECTED_CAP_FIELDS[field]
        for field in (
            "logical_case_limit",
            "physical_request_limit",
            "target_retries_per_turn",
        )
    }
    if expected_triple != configured_triple:
        raise CorpusBaselineError(
            "reviewed corpus counts do not match the bound 100/121/0 authorization envelope"
        )
    if any(batch["hosted_global_call_count"] > HOSTED_MAX_PHYSICAL_CALLS for batch in batches):
        raise CorpusBaselineError("a batch exceeds HOSTED_MAX_PHYSICAL_CALLS")

    return {
        "schema_version": "1",
        "artifact": "run-authorization-envelope-preparation",
        "authorization_status": "not_a_grant",
        "notice": (
            "This content-hashed preparation artifact does not authorize dispatch. "
            "The application must still enforce its distinct operator/approver grant."
        ),
        "run_id": run_id,
        "release_sha": release_sha,
        "corpus": {
            "corpus_id": corpus.corpus_id,
            "corpus_sha256": corpus.content_hash,
        },
        "caps": {
            **expected_triple,
            "budget_usd_hard_cap": 50,
            "expected_spend_usd": {"minimum": 10, "maximum": 25},
        },
        "batching": {
            "reason": (
                "The corpus exceeds the cumulative four-role hosted authority; execute bounded "
                "batches and aggregate their immutable result manifests. The batch size is "
                "derived from the landed generation policy, not from a per-role-only estimate."
            ),
            "hosted_max_physical_calls": HOSTED_MAX_PHYSICAL_CALLS,
            "hosted_calls_per_case": per_case_calls,
            "batch_size": selected_batch_size,
            "batch_count": len(batches),
            "batches": batches,
        },
        "bound_cap_artifacts": [
            {"path": artifact.path, "sha256": artifact.sha256}
            for artifact in sorted(bound_caps, key=lambda item: item.path)
        ],
    }


def _peak_rss_bytes() -> int:
    observed = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes; Linux and the other supported deployment environments
    # report KiB.  Keep the normalization explicit in the evidence scope.
    multiplier = 1 if sys.platform == "darwin" else 1024
    return int(observed * multiplier)


def capture_local_corpus_admission(
    *,
    corpus: AuthoredCorpus,
    release_sha: str,
    run_id: str,
    monotonic_ns: Callable[[], int] = time.perf_counter_ns,
    process_time_ns: Callable[[], int] = time.process_time_ns,
    peak_rss_bytes: Callable[[], int] = _peak_rss_bytes,
    runtime_identity: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Measure local immutable-corpus admission, with no network or provider calls."""

    if not isinstance(corpus, AuthoredCorpus):
        raise CorpusBaselineError("corpus must be one resolved AuthoredCorpus")
    _validate_release_sha(release_sha)
    _validate_run_id(run_id)
    if not corpus.cases:
        raise CorpusBaselineError("the reviewed corpus contains no cases")

    elapsed_start = monotonic_ns()
    cpu_start = process_time_ns()
    latencies_ms: list[float] = []
    payload_bytes = 0
    physical_requests = 0
    for case in corpus.cases:
        case_start = monotonic_ns()
        payload = verified_case_payload(case)
        canonical = canonical_json_bytes(payload)
        payload_bytes += len(canonical)
        physical_requests += _turn_count(payload)
        case_end = monotonic_ns()
        if case_end < case_start:
            raise CorpusBaselineError("monotonic clock moved backwards during case admission")
        latencies_ms.append((case_end - case_start) / 1_000_000)
    cpu_end = process_time_ns()
    elapsed_end = monotonic_ns()
    if cpu_end < cpu_start or elapsed_end <= elapsed_start:
        raise CorpusBaselineError("resource clocks did not produce a positive bounded observation")

    elapsed_ms = (elapsed_end - elapsed_start) / 1_000_000
    cpu_time_ms = (cpu_end - cpu_start) / 1_000_000
    identity = (
        dict(runtime_identity)
        if runtime_identity is not None
        else {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "machine": platform.machine(),
        }
    )
    if not identity or any(
        not isinstance(key, str)
        or not key.strip()
        or not isinstance(value, str)
        or not value.strip()
        for key, value in identity.items()
    ):
        raise CorpusBaselineError("runtime_identity must contain non-empty string pairs")

    return {
        "schema_version": "1",
        "artifact": "local-offline-corpus-admission-baseline",
        "scope": {
            "measured": (
                "local immutable case verification, canonical serialization, and turn counting"
            ),
            "not_measured": [
                "Railway service performance",
                "target latency",
                "provider latency",
                "database growth",
                "campaign cost",
            ],
            "network_calls": 0,
        },
        "run_id": run_id,
        "release_sha": release_sha,
        "corpus": {
            "corpus_id": corpus.corpus_id,
            "corpus_sha256": corpus.content_hash,
            "logical_case_count": len(corpus.cases),
            "physical_request_count": physical_requests,
            "target_retries": 0,
        },
        "runtime": dict(sorted(identity.items())),
        "method": {
            "case_order": "reviewed manifest order",
            "percentile_rule": NEAREST_RANK_RULE,
            "rss_definition": "process peak RSS at observation time",
        },
        "metrics": {
            "case_admission_latency_ms": {
                "sample_count": len(latencies_ms),
                "p50": nearest_rank(latencies_ms, 0.50),
                "p95": nearest_rank(latencies_ms, 0.95),
            },
            "elapsed_ms": elapsed_ms,
            "cpu_time_ms": cpu_time_ms,
            "cpu_utilization_ratio": cpu_time_ms / elapsed_ms,
            "throughput_cases_per_second": len(corpus.cases) / (elapsed_ms / 1_000),
            "peak_rss_bytes": peak_rss_bytes(),
            "canonical_case_payload_bytes": payload_bytes,
        },
    }


def _artifact_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(value)


def write_corpus_baseline_artifacts(
    *,
    output_directory: Path,
    envelope: Mapping[str, Any],
    local_baseline: Mapping[str, Any],
) -> ArtifactWriteResult:
    """Write new immutable evidence files; refuse to overwrite an existing directory."""

    destination = output_directory.resolve()
    if destination.exists():
        raise CorpusBaselineError("output directory already exists; evidence is never overwritten")
    destination.mkdir(parents=True)

    primary = {
        "local-admission-baseline.json": _artifact_bytes(local_baseline),
        "run-authorization-envelope.json": _artifact_bytes(envelope),
    }
    manifest_entries = [
        {
            "path": name,
            "byte_length": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for name, content in sorted(primary.items())
    ]
    manifest = {
        "schema_version": "1",
        "artifact": "corpus-performance-artifact-manifest",
        "artifacts": manifest_entries,
    }
    contents = {
        **primary,
        "artifact-manifest.json": _artifact_bytes(manifest),
    }
    for name, content in contents.items():
        (destination / name).write_bytes(content)

    digest_pairs = tuple(
        sorted((name, hashlib.sha256(content).hexdigest()) for name, content in contents.items())
    )
    sums = "".join(f"{digest}  {name}\n" for name, digest in digest_pairs)
    (destination / "SHA256SUMS").write_text(sums, encoding="utf-8")
    return ArtifactWriteResult(
        output_directory=destination,
        artifact_sha256s=digest_pairs,
    )


__all__ = [
    "ArtifactWriteResult",
    "BoundCapArtifact",
    "CorpusBaselineError",
    "build_run_authorization_envelope",
    "capture_local_corpus_admission",
    "verify_bound_caps",
    "write_corpus_baseline_artifacts",
]
