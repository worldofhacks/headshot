"""Offline, content-addressed performance evidence for one reviewed corpus.

This module deliberately measures only local corpus admission work: immutable case
verification, canonical serialization, batching, and artifact production.  It never
labels those observations as target, provider, Railway, or end-to-end campaign
performance.  Live-run latency and cost remain separate evidence inputs.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import resource
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.agents.hosted_policy import (
    HostedGenerationPolicy,
    HostedGenerationPolicyError,
    resolve_hosted_generation_policy,
)
from agentforge.campaign.corpus import AuthoredCorpus, verified_case_payload
from agentforge.performance.report import NEAREST_RANK_RULE, canonical_json_bytes, nearest_rank
from agentforge.target.spec import DefinitionError, SafetyCaps

_RELEASE_SHA = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")
_EXPECTED_CAP_FIELDS: dict[str, int | float] = {
    "budget_usd": 50.0,
    "max_attempts_per_run": 100,
    "target_requests_per_second": 0.5,
    "run_timeout_seconds": 3600.0,
    "logical_case_limit": 100,
    "physical_request_limit": 121,
    "target_retries_per_turn": 0,
}
_LEGACY_CAP_FIELDS: dict[str, int | float] = {
    "budget_usd": 1.0,
    "max_attempts_per_run": 40,
    "target_requests_per_second": 0.5,
    "run_timeout_seconds": 1800.0,
    "logical_case_limit": 40,
    "physical_request_limit": 60,
    "target_retries_per_turn": 1,
}
_BOUND_CAP_FILES = (
    "config/live-target-catalog.production.json",
    "config/live-target-catalog.staging.json",
    "config/targets/clinical-copilot-20260724.json",
    "docs/evidence/authorization-requests/caps.json",
)
_CATALOG_CAP_SCOPE: dict[str, dict[str, Mapping[str, int | float]]] = {
    "config/live-target-catalog.production.json": {
        "copilot-week1": _LEGACY_CAP_FIELDS,
        "copilot-week2": _EXPECTED_CAP_FIELDS,
        "clinical-copilot-week1": _LEGACY_CAP_FIELDS,
        "clinical-copilot-week2": _EXPECTED_CAP_FIELDS,
    },
    "config/live-target-catalog.staging.json": {
        "copilot-week1": _LEGACY_CAP_FIELDS,
        "copilot-week2": _EXPECTED_CAP_FIELDS,
        "clinical-copilot-week1": _LEGACY_CAP_FIELDS,
        "clinical-copilot-week2": _EXPECTED_CAP_FIELDS,
    },
    "config/targets/clinical-copilot-20260724.json": {
        "clinical-copilot-week1": _LEGACY_CAP_FIELDS,
        "clinical-copilot-week2": _EXPECTED_CAP_FIELDS,
    },
}
_INTENDED_TARGET_ID = "copilot-week2"
_INTENDED_SURFACE_ID = "copilot-week2-chat"
_ARTIFACT_ROOT = Path("docs/performance/artifacts")
_USD_HARD_CAP = Decimal("50")
_MILLION = Decimal(1_000_000)


class CorpusBaselineError(ValueError):
    """Raised when corpus performance evidence cannot be produced unambiguously."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_nonfinite_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _strict_json_bytes(raw: bytes, *, label: str) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CorpusBaselineError(f"{label} is invalid JSON") from exc


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


@dataclass(frozen=True, slots=True)
class StagedConfigurationReceipt:
    """One exact configuration payload paired with the resource identity returned at staging."""

    configuration: HostedConfigurationSet
    resource_id: str
    raw_bytes: bytes = field(repr=False)
    receipt_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.configuration, HostedConfigurationSet):
            raise CorpusBaselineError("staged receipt configuration is invalid")
        if not isinstance(self.resource_id, str):
            raise CorpusBaselineError("staged configuration resource_id is invalid")
        if self.resource_id != self.configuration.configuration_sha256:
            raise CorpusBaselineError(
                "staged configuration resource_id differs from its canonical hash"
            )
        if not isinstance(self.raw_bytes, bytes):
            raise CorpusBaselineError("staged configuration receipt bytes are invalid")
        try:
            value = _strict_json_bytes(
                self.raw_bytes,
                label="staged configuration receipt",
            )
            parsed_configuration = HostedConfigurationSet.from_payload(value["configuration"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CorpusBaselineError("staged configuration receipt bytes are invalid") from exc
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "resource_id", "configuration"}
            or value.get("schema_version") != "1"
            or value.get("resource_id") != self.resource_id
            or parsed_configuration != self.configuration
        ):
            raise CorpusBaselineError(
                "staged configuration receipt fields differ from its retained bytes"
            )
        object.__setattr__(
            self,
            "receipt_sha256",
            hashlib.sha256(self.raw_bytes).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class BatchBudgetPlan:
    """Exact per-batch run budgets whose aggregate cannot exceed the campaign hard cap."""

    allocations_usd: tuple[Decimal, ...]
    aggregate_budget_usd: Decimal
    target_id: str
    surface_id: str
    raw_bytes: bytes = field(repr=False)
    plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if self.target_id != _INTENDED_TARGET_ID or self.surface_id != _INTENDED_SURFACE_ID:
            raise CorpusBaselineError("batch budget plan is bound to the wrong target surface")
        if not self.allocations_usd:
            raise CorpusBaselineError("batch budget plan must contain at least one allocation")
        if any(
            not isinstance(value, Decimal)
            or not value.is_finite()
            or value <= 0
            or value.as_tuple().exponent < -2
            for value in self.allocations_usd
        ):
            raise CorpusBaselineError(
                "batch budget allocations must be positive finite USD values "
                "with at most two decimals"
            )
        if (
            not isinstance(self.aggregate_budget_usd, Decimal)
            or not self.aggregate_budget_usd.is_finite()
            or self.aggregate_budget_usd <= 0
            or self.aggregate_budget_usd > _USD_HARD_CAP
            or self.aggregate_budget_usd != sum(self.allocations_usd, Decimal(0))
        ):
            raise CorpusBaselineError(
                "batch budget allocations must sum exactly to an aggregate no greater than $50"
            )
        if not isinstance(self.raw_bytes, bytes):
            raise CorpusBaselineError("batch budget plan bytes are invalid")
        try:
            value = _strict_json_bytes(self.raw_bytes, label="batch budget plan")
            retained_aggregate = Decimal(value["aggregate_budget_usd"])
            retained_allocations = tuple(Decimal(item) for item in value["batch_budget_usd"])
        except (
            InvalidOperation,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise CorpusBaselineError("batch budget plan bytes are invalid") from exc
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "target_id",
                "surface_id",
                "aggregate_budget_usd",
                "batch_budget_usd",
            }
            or value.get("schema_version") != "1"
            or value.get("target_id") != self.target_id
            or value.get("surface_id") != self.surface_id
            or not isinstance(value.get("aggregate_budget_usd"), str)
            or not isinstance(value.get("batch_budget_usd"), list)
            or any(not isinstance(item, str) for item in value["batch_budget_usd"])
            or retained_aggregate != self.aggregate_budget_usd
            or retained_allocations != self.allocations_usd
        ):
            raise CorpusBaselineError("batch budget plan fields differ from its retained bytes")
        object.__setattr__(
            self,
            "plan_sha256",
            hashlib.sha256(self.raw_bytes).hexdigest(),
        )


def _decimal_text(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered or "0"


def _absolute_path_without_symlinks(path: Path, *, label: str) -> Path:
    """Return an absolute lexical path after rejecting every existing symlink component."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if os.path.lexists(current) and current.is_symlink():
            raise CorpusBaselineError(f"{label} contains a symlink component")
    return absolute


def _regular_file_bytes(path: Path, *, label: str) -> bytes:
    absolute = _absolute_path_without_symlinks(path, label=label)
    try:
        metadata = absolute.lstat()
    except OSError as exc:
        raise CorpusBaselineError(f"{label} is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise CorpusBaselineError(f"{label} must be a regular non-symlink file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
        with os.fdopen(descriptor, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise CorpusBaselineError(f"{label} could not be read safely") from exc


def _safe_repo_root(repo_root: Path) -> Path:
    root = _absolute_path_without_symlinks(repo_root, label="repository root")
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise CorpusBaselineError("repository root is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CorpusBaselineError("repository root must be a real directory")
    return root


def _repo_file_bytes(root: Path, relative: str) -> bytes:
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise CorpusBaselineError("bound repository path is unsafe")
    path = root / relative_path
    absolute = _absolute_path_without_symlinks(path, label=f"bound cap file {relative}")
    if not absolute.is_relative_to(root):
        raise CorpusBaselineError(f"bound cap file escapes the repository: {relative}")
    return _regular_file_bytes(absolute, label=f"bound cap file {relative}")


def _git_output(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ("git", "-C", os.fspath(root), *arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CorpusBaselineError("release source identity could not be checked") from exc
    if completed.returncode != 0:
        raise CorpusBaselineError("release source identity could not be checked")
    return completed.stdout.strip()


def verify_release_head(repo_root: Path, release_sha: str) -> str:
    """Require a clean checkout whose exact Git HEAD is the claimed release SHA."""

    root = _safe_repo_root(repo_root)
    _validate_release_sha(release_sha)
    top_level = _absolute_path_without_symlinks(
        Path(_git_output(root, "rev-parse", "--show-toplevel")),
        label="Git top-level path",
    )
    if top_level != root:
        raise CorpusBaselineError("repo_root is not the exact checked Git worktree root")
    checked_head = _git_output(root, "rev-parse", "--verify", "HEAD^{commit}")
    if checked_head != release_sha:
        raise CorpusBaselineError("release_sha differs from the exact checked Git HEAD")
    if _git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise CorpusBaselineError("release worktree is not clean; evidence would not match HEAD")
    return checked_head


def load_staged_configuration_receipt(path: Path) -> StagedConfigurationReceipt:
    """Parse a byte-addressed stage receipt and require resource_id == canonical config hash."""

    raw = _regular_file_bytes(path, label="staged configuration receipt")
    value = _strict_json_bytes(raw, label="staged configuration receipt")
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "resource_id", "configuration"}
        or value.get("schema_version") != "1"
        or not isinstance(value.get("resource_id"), str)
    ):
        raise CorpusBaselineError("staged configuration receipt has an invalid shape")
    try:
        configuration = HostedConfigurationSet.from_payload(value["configuration"])
    except (TypeError, ValueError) as exc:
        raise CorpusBaselineError("staged hosted configuration is invalid") from exc
    return StagedConfigurationReceipt(
        configuration=configuration,
        resource_id=value["resource_id"],
        raw_bytes=raw,
    )


def load_batch_budget_plan(path: Path) -> BatchBudgetPlan:
    """Load exact per-batch allocations from one immutable, non-symlink JSON artifact."""

    raw = _regular_file_bytes(path, label="batch budget plan")
    value = _strict_json_bytes(raw, label="batch budget plan")
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "target_id",
            "surface_id",
            "aggregate_budget_usd",
            "batch_budget_usd",
        }
        or value.get("schema_version") != "1"
        or not isinstance(value.get("target_id"), str)
        or not isinstance(value.get("surface_id"), str)
        or not isinstance(value.get("aggregate_budget_usd"), str)
        or not isinstance(value.get("batch_budget_usd"), list)
        or any(not isinstance(item, str) for item in value["batch_budget_usd"])
    ):
        raise CorpusBaselineError("batch budget plan has an invalid shape")
    try:
        aggregate = Decimal(value["aggregate_budget_usd"])
        allocations = tuple(Decimal(item) for item in value["batch_budget_usd"])
    except InvalidOperation as exc:
        raise CorpusBaselineError("batch budget plan contains an invalid USD value") from exc
    return BatchBudgetPlan(
        allocations_usd=allocations,
        aggregate_budget_usd=aggregate,
        target_id=value["target_id"],
        surface_id=value["surface_id"],
        raw_bytes=raw,
    )


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
    if set(release_sha) == {"0"}:
        raise CorpusBaselineError("release_sha cannot be the all-zero sentinel")


def _validate_run_id(run_id: str) -> None:
    if not isinstance(run_id, str) or not run_id.strip():
        raise CorpusBaselineError("run_id must be a non-empty string")


def _validated_cap_payload(
    payload: object,
    *,
    expected: Mapping[str, int | float],
    source: str,
) -> dict[str, int | float]:
    if not isinstance(payload, dict) or set(payload) != set(_EXPECTED_CAP_FIELDS):
        raise CorpusBaselineError(f"run caps have an invalid exact shape: {source}")
    for cap_name in ("max_attempts_per_run", "logical_case_limit", "physical_request_limit"):
        if type(payload[cap_name]) is not int:
            raise CorpusBaselineError(f"run cap {cap_name} must be an exact integer: {source}")
    if type(payload["target_retries_per_turn"]) is not int:
        raise CorpusBaselineError(
            f"run cap target_retries_per_turn must be an exact integer: {source}"
        )
    for cap_name in ("budget_usd", "target_requests_per_second", "run_timeout_seconds"):
        if isinstance(payload[cap_name], bool) or not isinstance(payload[cap_name], (int, float)):
            raise CorpusBaselineError(f"run cap {cap_name} must be numeric: {source}")
    try:
        parsed = SafetyCaps(
            budget_usd=payload["budget_usd"],
            max_attempts_per_run=payload["max_attempts_per_run"],
            target_requests_per_second=payload["target_requests_per_second"],
            run_timeout_seconds=payload["run_timeout_seconds"],
            logical_case_limit=payload["logical_case_limit"],
            physical_request_limit=payload["physical_request_limit"],
            target_retries_per_turn=payload["target_retries_per_turn"],
        )
    except (DefinitionError, TypeError, ValueError) as exc:
        raise CorpusBaselineError(f"run caps fail the runtime model: {source}") from exc
    canonical = parsed.canonical_payload()
    if canonical != dict(expected):
        raise CorpusBaselineError(f"run caps differ from their reviewed target scope: {source}")
    return canonical


def verify_bound_caps(repo_root: Path) -> tuple[BoundCapArtifact, ...]:
    """Verify exact runtime-typed caps and the narrow Week 2 scope across four bound files."""

    root = _safe_repo_root(repo_root)
    artifacts: list[BoundCapArtifact] = []
    for relative in _BOUND_CAP_FILES:
        raw = _repo_file_bytes(root, relative)
        value = _strict_json_bytes(raw, label=f"bound cap file {relative}")

        if relative.endswith("/caps.json"):
            _validated_cap_payload(value, expected=_EXPECTED_CAP_FIELDS, source=relative)
        else:
            if not isinstance(value, list) or not value:
                raise CorpusBaselineError(
                    f"bound target catalog must contain at least one entry: {relative}"
                )
            expected_by_target = _CATALOG_CAP_SCOPE[relative]
            observed_targets: set[str] = set()
            for entry in value:
                if not isinstance(entry, dict):
                    raise CorpusBaselineError(f"bound target catalog entry is invalid: {relative}")
                target = entry.get("target")
                target_id = target.get("target_id") if isinstance(target, dict) else None
                caps = target.get("safety_caps") if isinstance(target, dict) else None
                if (
                    not isinstance(target_id, str)
                    or target_id in observed_targets
                    or target_id not in expected_by_target
                ):
                    raise CorpusBaselineError(
                        f"bound target catalog identity is unexpected or duplicated: {relative}"
                    )
                if not isinstance(caps, dict):
                    raise CorpusBaselineError(
                        f"bound target catalog entry has no safety_caps: {relative}"
                    )
                observed_targets.add(target_id)
                _validated_cap_payload(
                    caps,
                    expected=expected_by_target[target_id],
                    source=f"{relative}:{target_id}",
                )
            if observed_targets != set(expected_by_target):
                raise CorpusBaselineError(
                    f"bound target catalog is missing a reviewed target identity: {relative}"
                )
        artifacts.append(
            BoundCapArtifact(
                path=relative,
                sha256=hashlib.sha256(raw).hexdigest(),
            )
        )
    return tuple(artifacts)


def _hosted_capacity_projection(
    *,
    configuration: HostedConfigurationSet,
    generation_policy: HostedGenerationPolicy,
    case_count: int,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Project worst-case retry, token, and spend reservations for one batch."""

    try:
        logical_by_role = generation_policy.required_logical_calls(case_count=case_count)
    except HostedGenerationPolicyError as exc:
        raise CorpusBaselineError("generation policy could not derive hosted role calls") from exc
    bounds_by_role = generation_policy.call_bounds
    role_rows: list[dict[str, Any]] = []
    failures: list[str] = []
    global_calls = 0
    global_input = 0
    global_output = 0
    global_reasoning = 0
    global_usd = Decimal(0)

    for role_configuration in configuration.roles:
        role = role_configuration.role
        role_limits = role_configuration.limits
        bounds = bounds_by_role[role]
        logical_calls = logical_by_role[role]
        attempts_per_logical_call = 1 + min(
            role_limits.max_retries,
            configuration.global_limits.max_retries,
        )
        physical_calls = logical_calls * attempts_per_logical_call
        input_tokens = bounds.input_tokens * physical_calls
        output_tokens = bounds.output_tokens * physical_calls
        reasoning_tokens = bounds.reasoning_tokens * physical_calls
        prices = role_configuration.prices
        reasoning_price = max(
            prices.output_usd_per_million_tokens,
            prices.reasoning_usd_per_million_tokens,
        )
        maximum_usd = (
            prices.input_usd_per_million_tokens * input_tokens
            + prices.output_usd_per_million_tokens * output_tokens
            + reasoning_price * reasoning_tokens
        ) / _MILLION

        for limit_name, required, limit in (
            ("calls", physical_calls, role_limits.max_calls),
            ("input tokens", input_tokens, role_limits.max_input_tokens),
            ("output tokens", output_tokens, role_limits.max_output_tokens),
            ("reasoning tokens", reasoning_tokens, role_limits.max_reasoning_tokens),
        ):
            if required > limit:
                failures.append(f"{role} {limit_name} reservation exceeds its staged role cap")
        if maximum_usd > role_limits.max_usd:
            failures.append(f"{role} spend reservation exceeds its staged role cap")

        role_rows.append(
            {
                "role": role,
                "model_id": role_configuration.model_id,
                "logical_calls": logical_calls,
                "attempts_per_logical_call": attempts_per_logical_call,
                "physical_calls": physical_calls,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reasoning_tokens": reasoning_tokens,
                "maximum_usd": _decimal_text(maximum_usd),
                "staged_limits": role_limits.canonical_payload(),
            }
        )
        global_calls += physical_calls
        global_input += input_tokens
        global_output += output_tokens
        global_reasoning += reasoning_tokens
        global_usd += maximum_usd

    global_limits = configuration.global_limits
    for limit_name, required, limit in (
        ("calls", global_calls, global_limits.max_calls),
        ("input tokens", global_input, global_limits.max_input_tokens),
        ("output tokens", global_output, global_limits.max_output_tokens),
        ("reasoning tokens", global_reasoning, global_limits.max_reasoning_tokens),
    ):
        if required > limit:
            failures.append(f"global {limit_name} reservation exceeds the staged global cap")
    if global_usd > global_limits.max_usd:
        failures.append("global spend reservation exceeds the staged global cap")

    return (
        {
            "logical_case_count": case_count,
            "roles": role_rows,
            "global": {
                "physical_calls": global_calls,
                "input_tokens": global_input,
                "output_tokens": global_output,
                "reasoning_tokens": global_reasoning,
                "maximum_usd": _decimal_text(global_usd),
                "staged_limits": global_limits.canonical_payload(),
            },
        },
        tuple(failures),
    )


def _derive_hosted_batch_capacity(
    *,
    configuration: HostedConfigurationSet,
    generation_policy: HostedGenerationPolicy,
    maximum_case_count: int,
) -> tuple[int, dict[str, Any]]:
    capacity = 0
    capacity_projection: dict[str, Any] | None = None
    first_failure: tuple[str, ...] = ()
    for candidate in range(1, maximum_case_count + 1):
        projection, failures = _hosted_capacity_projection(
            configuration=configuration,
            generation_policy=generation_policy,
            case_count=candidate,
        )
        if failures:
            first_failure = failures
            break
        capacity = candidate
        capacity_projection = projection
    if capacity < 1 or capacity_projection is None:
        detail = first_failure[0] if first_failure else "no positive batch capacity"
        raise CorpusBaselineError(
            f"staged hosted configuration cannot reserve even one corpus case: {detail}"
        )
    return capacity, capacity_projection


def build_run_authorization_envelope(
    *,
    corpus: AuthoredCorpus,
    repo_root: Path,
    release_sha: str,
    run_id: str,
    staged_configuration: StagedConfigurationReceipt,
    generation_policy: HostedGenerationPolicy,
    budget_plan: BatchBudgetPlan,
) -> dict[str, Any]:
    """Build a non-authorizing, deterministic envelope for a reviewed corpus.

    The returned document binds the exact case/turn counts and a deterministic batch
    plan.  It is preparation evidence only; it cannot mint or replace a two-person run
    authorization.
    """

    if not isinstance(corpus, AuthoredCorpus):
        raise CorpusBaselineError("corpus must be one resolved AuthoredCorpus")
    verified_release_sha = verify_release_head(repo_root, release_sha)
    _validate_run_id(run_id)
    if not isinstance(staged_configuration, StagedConfigurationReceipt):
        raise CorpusBaselineError("one exact staged configuration receipt is required")
    if not isinstance(generation_policy, HostedGenerationPolicy):
        raise CorpusBaselineError("one registered hosted generation policy is required")
    try:
        registered_policy = resolve_hosted_generation_policy(generation_policy.policy_sha256)
    except HostedGenerationPolicyError as exc:
        raise CorpusBaselineError("generation policy is not registered by this release") from exc
    if registered_policy != generation_policy:
        raise CorpusBaselineError("generation policy differs from its registered identity")
    if not isinstance(budget_plan, BatchBudgetPlan):
        raise CorpusBaselineError("one exact per-batch budget plan is required")
    bound_caps = verify_bound_caps(repo_root)

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

    selected_batch_size, capacity_projection = _derive_hosted_batch_capacity(
        configuration=staged_configuration.configuration,
        generation_policy=generation_policy,
        maximum_case_count=len(cases),
    )
    batch_count = (len(cases) + selected_batch_size - 1) // selected_batch_size
    if len(budget_plan.allocations_usd) != batch_count:
        raise CorpusBaselineError(
            "batch budget allocation count differs from the staged-config-derived batch count"
        )

    batches: list[dict[str, Any]] = []
    for batch_index, offset in enumerate(range(0, len(cases), selected_batch_size), start=1):
        batch_cases = cases[offset : offset + selected_batch_size]
        projection, failures = _hosted_capacity_projection(
            configuration=staged_configuration.configuration,
            generation_policy=generation_policy,
            case_count=len(batch_cases),
        )
        if failures:
            raise CorpusBaselineError(
                "derived batch no longer fits the staged hosted configuration"
            )
        batch_budget = budget_plan.allocations_usd[batch_index - 1]
        maximum_hosted_reservation = Decimal(projection["global"]["maximum_usd"])
        if maximum_hosted_reservation > batch_budget:
            raise CorpusBaselineError(
                "a batch's hosted spend reservation exceeds its reviewed budget allocation"
            )
        batch_payload = {
            "batch_id": f"batch-{batch_index:02d}",
            "logical_case_count": len(batch_cases),
            "target_physical_request_count": sum(int(case["turn_count"]) for case in batch_cases),
            "target_retries_per_turn": 0,
            "batch_budget_usd": _decimal_text(batch_budget),
            "hosted_reservation": projection,
            "case_refs": [
                {
                    "case_id": case["case_id"],
                    "case_sha256": case["case_sha256"],
                }
                for case in batch_cases
            ],
        }
        batch_payload["batch_sha256"] = hashlib.sha256(
            canonical_json_bytes(batch_payload)
        ).hexdigest()
        batches.append(batch_payload)

    logical_count = len(cases)
    physical_count = sum(int(case["turn_count"]) for case in cases)
    expected_triple = {
        "logical_case_limit": logical_count,
        "physical_request_limit": physical_count,
        "target_retries_per_turn": 0,
    }
    configured_triple = {
        cap_name: _EXPECTED_CAP_FIELDS[cap_name]
        for cap_name in (
            "logical_case_limit",
            "physical_request_limit",
            "target_retries_per_turn",
        )
    }
    if expected_triple != configured_triple:
        raise CorpusBaselineError(
            "reviewed corpus counts do not match the bound 100/121/0 authorization envelope"
        )

    return {
        "schema_version": "1",
        "artifact": "run-authorization-envelope-preparation",
        "authorization_status": "not_a_grant",
        "notice": (
            "This content-hashed preparation artifact does not authorize dispatch. "
            "The application must still enforce its distinct operator/approver grant."
        ),
        "run_id": run_id,
        "release_sha": verified_release_sha,
        "target": {
            "target_id": _INTENDED_TARGET_ID,
            "surface_id": _INTENDED_SURFACE_ID,
        },
        "corpus": {
            "corpus_id": corpus.corpus_id,
            "corpus_sha256": corpus.content_hash,
        },
        "caps": {
            "max_attempts_per_run": _EXPECTED_CAP_FIELDS["max_attempts_per_run"],
            **expected_triple,
            "budget_usd_hard_cap": _decimal_text(_USD_HARD_CAP),
            "authorized_batch_budget_usd": [
                _decimal_text(value) for value in budget_plan.allocations_usd
            ],
            "authorized_aggregate_budget_usd": _decimal_text(budget_plan.aggregate_budget_usd),
            "batch_budget_plan_sha256": budget_plan.plan_sha256,
            "expected_spend_usd": {"minimum": 10, "maximum": 25},
        },
        "hosted_configuration": {
            "resource_id": staged_configuration.resource_id,
            "configuration_sha256": (staged_configuration.configuration.configuration_sha256),
            "stage_receipt_sha256": staged_configuration.receipt_sha256,
            "generation_policy_sha256": generation_policy.policy_sha256,
            "roles": [
                {
                    "role": role.role,
                    "model_id": role.model_id,
                    "configuration_sha256": role.configuration_sha256,
                }
                for role in staged_configuration.configuration.roles
            ],
        },
        "batching": {
            "reason": (
                "Batch capacity is derived from the exact staged four-role configuration and "
                "registered generation policy, including retry, call, token, and spend limits."
            ),
            "batch_size": selected_batch_size,
            "batch_count": len(batches),
            "capacity_projection": capacity_projection,
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
    observed_peak_rss = peak_rss_bytes()
    if type(observed_peak_rss) is not int or observed_peak_rss < 0:
        raise CorpusBaselineError("peak RSS observation must be a non-negative integer byte count")

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
            "peak_rss_bytes": observed_peak_rss,
            "canonical_case_payload_bytes": payload_bytes,
        },
    }


def _artifact_bytes(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(value)


def _validate_artifact_pair(
    envelope: Mapping[str, Any],
    local_baseline: Mapping[str, Any],
) -> tuple[str, str, str, str]:
    if (
        not isinstance(envelope, Mapping)
        or envelope.get("schema_version") != "1"
        or envelope.get("artifact") != "run-authorization-envelope-preparation"
        or envelope.get("authorization_status") != "not_a_grant"
        or not isinstance(local_baseline, Mapping)
        or local_baseline.get("schema_version") != "1"
        or local_baseline.get("artifact") != "local-offline-corpus-admission-baseline"
    ):
        raise CorpusBaselineError("artifact pair has an invalid identity or schema")
    run_id = envelope.get("run_id")
    release_sha = envelope.get("release_sha")
    envelope_corpus = envelope.get("corpus")
    baseline_corpus = local_baseline.get("corpus")
    if (
        not isinstance(run_id, str)
        or local_baseline.get("run_id") != run_id
        or not isinstance(release_sha, str)
        or local_baseline.get("release_sha") != release_sha
        or not isinstance(envelope_corpus, Mapping)
        or not isinstance(baseline_corpus, Mapping)
    ):
        raise CorpusBaselineError("artifact pair is not bound to one run and release")
    _validate_run_id(run_id)
    _validate_release_sha(release_sha)
    corpus_id = envelope_corpus.get("corpus_id")
    corpus_sha256 = envelope_corpus.get("corpus_sha256")
    if (
        not isinstance(corpus_id, str)
        or not corpus_id
        or baseline_corpus.get("corpus_id") != corpus_id
        or not isinstance(corpus_sha256, str)
        or _SHA256.fullmatch(corpus_sha256) is None
        or baseline_corpus.get("corpus_sha256") != corpus_sha256
    ):
        raise CorpusBaselineError("artifact pair is not bound to one immutable corpus")
    caps = envelope.get("caps")
    if (
        not isinstance(caps, Mapping)
        or baseline_corpus.get("logical_case_count") != caps.get("logical_case_limit")
        or baseline_corpus.get("physical_request_count") != caps.get("physical_request_limit")
        or baseline_corpus.get("target_retries") != caps.get("target_retries_per_turn")
    ):
        raise CorpusBaselineError("local baseline counts differ from the authorization envelope")
    return run_id, release_sha, corpus_id, corpus_sha256


def _write_exclusive_at(directory_fd: int, name: str, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o640, dir_fd=directory_fd)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise CorpusBaselineError("immutable artifact file could not be created safely") from exc


def write_corpus_baseline_artifacts(
    *,
    repo_root: Path,
    output_directory: Path,
    envelope: Mapping[str, Any],
    local_baseline: Mapping[str, Any],
) -> ArtifactWriteResult:
    """Write a new direct child of the repository artifact root without following symlinks."""

    root = _safe_repo_root(repo_root)
    _, release_sha, _, _ = _validate_artifact_pair(envelope, local_baseline)
    verify_release_head(root, release_sha)
    artifact_root = _absolute_path_without_symlinks(
        root / _ARTIFACT_ROOT,
        label="performance artifact root",
    )
    destination = _absolute_path_without_symlinks(
        output_directory,
        label="performance artifact output",
    )
    if (
        destination.parent != artifact_root
        or destination.name in {"", ".", ".."}
        or not destination.name.strip()
    ):
        raise CorpusBaselineError(
            "output directory must be one direct child of docs/performance/artifacts"
        )

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
    digest_pairs = tuple(
        sorted((name, hashlib.sha256(content).hexdigest()) for name, content in contents.items())
    )
    sums = "".join(f"{digest}  {name}\n" for name, digest in digest_pairs).encode()

    if not os.path.lexists(artifact_root):
        try:
            os.mkdir(artifact_root, 0o750)
        except OSError as exc:
            raise CorpusBaselineError("performance artifact root could not be created") from exc
    artifact_root = _absolute_path_without_symlinks(
        artifact_root,
        label="performance artifact root",
    )
    if not stat.S_ISDIR(artifact_root.lstat().st_mode):
        raise CorpusBaselineError("performance artifact root must be a real directory")
    if os.path.lexists(destination):
        raise CorpusBaselineError("output directory already exists; evidence is never overwritten")

    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        artifact_root_fd = os.open(artifact_root, directory_flags)
        try:
            os.mkdir(destination.name, 0o750, dir_fd=artifact_root_fd)
            destination_fd = os.open(
                destination.name,
                directory_flags,
                dir_fd=artifact_root_fd,
            )
        finally:
            os.close(artifact_root_fd)
    except OSError as exc:
        raise CorpusBaselineError(
            "output directory could not be created without following links"
        ) from exc
    try:
        for name, content in contents.items():
            _write_exclusive_at(destination_fd, name, content)
        _write_exclusive_at(destination_fd, "SHA256SUMS", sums)
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    return ArtifactWriteResult(
        output_directory=destination,
        artifact_sha256s=digest_pairs,
    )


__all__ = [
    "ArtifactWriteResult",
    "BatchBudgetPlan",
    "BoundCapArtifact",
    "CorpusBaselineError",
    "StagedConfigurationReceipt",
    "build_run_authorization_envelope",
    "capture_local_corpus_admission",
    "load_batch_budget_plan",
    "load_staged_configuration_receipt",
    "verify_bound_caps",
    "verify_release_head",
    "write_corpus_baseline_artifacts",
]
