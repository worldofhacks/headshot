from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from decimal import Decimal
from pathlib import Path

import pytest

from agentforge.agents.hosted import (
    HOSTED_ROLE_MAX_MEASURED_USD,
    HOSTED_ROLE_MODELS,
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.prompts import load_prompt_registry
from agentforge.agents.runtime import AGENT_ROLES
from agentforge.campaign.corpus import AuthoredCase, AuthoredCorpus
from agentforge.performance.corpus_baseline import (
    BatchBudgetPlan,
    CorpusBaselineError,
    StagedConfigurationReceipt,
    build_run_authorization_envelope,
    capture_local_corpus_admission,
    load_batch_budget_plan,
    load_staged_configuration_receipt,
    verify_bound_caps,
    verify_release_head,
    write_corpus_baseline_artifacts,
)

_SOURCE_ROOT = Path(__file__).resolve().parents[2]
_BOUND_CAP_PATHS = (
    "config/live-target-catalog.production.json",
    "config/live-target-catalog.staging.json",
    "config/targets/clinical-copilot-20260724.json",
    "docs/evidence/authorization-requests/caps.json",
)


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


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _clean_repo(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    for relative in _BOUND_CAP_PATHS:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_SOURCE_ROOT / relative, destination)
    performance_root = root / "docs/performance"
    performance_root.mkdir(parents=True, exist_ok=True)
    (performance_root / ".gitkeep").write_text("", encoding="utf-8")
    (root / ".gitignore").write_text("docs/performance/artifacts/\n", encoding="utf-8")
    _git(root, "init")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Corpus Baseline Test")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "test fixture")
    return root, _git(root, "rev-parse", "HEAD")


def _hosted_configuration(
    *,
    orchestrator_input_limit: int = 1_000_000,
    price: Decimal = Decimal("0.01"),
) -> HostedConfigurationSet:
    prompts = {record.role: record.sha256 for record in load_prompt_registry()}
    call_limits = {
        "orchestrator": 9,
        "red_team": 19,
        "judge": 19,
        "documentation": 9,
    }
    input_limits = {
        "orchestrator": orchestrator_input_limit,
        "red_team": 1_000_000,
        "judge": 1_000_000,
        "documentation": 1_000_000,
    }
    provider_slugs = {
        "orchestrator": "anthropic",
        "red_team": "qwen",
        "judge": "google",
        "documentation": "openai",
    }
    roles = tuple(
        HostedRoleConfiguration(
            role=role,
            provider="openrouter",
            model_id=HOSTED_ROLE_MODELS[role],
            upstream_provider=provider_slugs[role],
            credential_reference=f"secretref://test/{role}/generation-1",
            prompt_sha256=prompts[role],
            policy_sha256=hashlib.sha256(f"policy:{role}".encode()).hexdigest(),
            prices=TokenPrices(
                input_usd_per_million_tokens=price,
                output_usd_per_million_tokens=price,
                reasoning_usd_per_million_tokens=price,
            ),
            limits=HostedLimits(
                max_calls=call_limits[role],
                max_input_tokens=input_limits[role],
                max_output_tokens=100_000,
                max_reasoning_tokens=100_000,
                max_usd=HOSTED_ROLE_MAX_MEASURED_USD[role],
                max_retries=1,
                max_requests_per_second=Decimal("0.5"),
                max_concurrency=1,
            ),
        )
        for role in AGENT_ROLES
    )
    return HostedConfigurationSet(
        roles=roles,
        global_limits=HostedLimits(
            max_calls=56,
            max_input_tokens=2_000_000,
            max_output_tokens=200_000,
            max_reasoning_tokens=200_000,
            max_usd=Decimal("10"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _staged_receipt(
    configuration: HostedConfigurationSet | None = None,
) -> StagedConfigurationReceipt:
    selected = configuration or _hosted_configuration()
    raw = _json_bytes(
        {
            "schema_version": "1",
            "resource_id": selected.configuration_sha256,
            "configuration": selected.canonical_payload(),
        }
    )
    return StagedConfigurationReceipt(
        configuration=selected,
        resource_id=selected.configuration_sha256,
        raw_bytes=raw,
    )


def _budget_plan(
    *,
    batch_count: int = 25,
    allocation: Decimal = Decimal("2"),
) -> BatchBudgetPlan:
    aggregate = allocation * batch_count
    raw = _json_bytes(
        {
            "schema_version": "1",
            "target_id": "copilot-week2",
            "surface_id": "copilot-week2-chat",
            "aggregate_budget_usd": format(aggregate, "f"),
            "batch_budget_usd": [format(allocation, "f")] * batch_count,
        }
    )
    return BatchBudgetPlan(
        allocations_usd=(allocation,) * batch_count,
        aggregate_budget_usd=aggregate,
        target_id="copilot-week2",
        surface_id="copilot-week2-chat",
        raw_bytes=raw,
    )


def _envelope(root: Path, release_sha: str) -> dict[str, object]:
    return build_run_authorization_envelope(
        corpus=_live_100_fixture(),
        repo_root=root,
        release_sha=release_sha,
        run_id="test-only-not-a-run",
        staged_configuration=_staged_receipt(),
        generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
        budget_plan=_budget_plan(),
    )


def _baseline(release_sha: str) -> dict[str, object]:
    return capture_local_corpus_admission(
        corpus=_live_100_fixture(),
        release_sha=release_sha,
        run_id="test-only-not-a-run",
        peak_rss_bytes=lambda: 64_000_000,
        runtime_identity={"system": "test", "python": "test"},
    )


def test_run_envelope_derives_retry_call_token_and_spend_capacity(
    tmp_path: Path,
) -> None:
    root, release_sha = _clean_repo(tmp_path)

    envelope = _envelope(root, release_sha)

    assert envelope["authorization_status"] == "not_a_grant"
    assert envelope["target"] == {
        "target_id": "copilot-week2",
        "surface_id": "copilot-week2-chat",
    }
    assert envelope["caps"] == {
        "max_attempts_per_run": 100,
        "logical_case_limit": 100,
        "physical_request_limit": 121,
        "target_retries_per_turn": 0,
        "budget_usd_hard_cap": "50",
        "authorized_batch_budget_usd": ["2"] * 25,
        "authorized_aggregate_budget_usd": "50",
        "batch_budget_plan_sha256": _budget_plan().plan_sha256,
        "expected_spend_usd": {"minimum": 10, "maximum": 25},
    }
    batching = envelope["batching"]
    assert batching["batch_size"] == 4
    assert batching["batch_count"] == 25
    assert [batch["logical_case_count"] for batch in batching["batches"]] == [4] * 25
    assert [batch["target_physical_request_count"] for batch in batching["batches"][:6]] == [
        8,
        8,
        8,
        8,
        8,
        5,
    ]
    projection = batching["capacity_projection"]
    assert projection["global"]["physical_calls"] == 32
    assert projection["global"]["input_tokens"] == 1_488_128
    assert projection["global"]["output_tokens"] == 81_920
    assert projection["global"]["reasoning_tokens"] == 172_032
    assert all(row["attempts_per_logical_call"] == 2 for row in projection["roles"])
    assert all(row["physical_calls"] == 8 for row in projection["roles"])
    assert all(len(batch["batch_sha256"]) == 64 for batch in batching["batches"])


def test_run_envelope_rejects_wrong_corpus_and_budget_allocation_count(
    tmp_path: Path,
) -> None:
    root, release_sha = _clean_repo(tmp_path)
    wrong = AuthoredCorpus(
        corpus_id="headshot-live-100-v1",
        content_hash="e" * 64,
        cases=tuple(_case(index, turns=1) for index in range(100)),
        categories=frozenset({"synthetic-test-only"}),
        root=Path("/not-evidence"),
    )
    with pytest.raises(CorpusBaselineError, match="100/121/0"):
        build_run_authorization_envelope(
            corpus=wrong,
            repo_root=root,
            release_sha=release_sha,
            run_id="test-only",
            staged_configuration=_staged_receipt(),
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            budget_plan=_budget_plan(),
        )

    with pytest.raises(CorpusBaselineError, match="spend reservation"):
        build_run_authorization_envelope(
            corpus=_live_100_fixture(),
            repo_root=root,
            release_sha=release_sha,
            run_id="test-only",
            staged_configuration=_staged_receipt(),
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            budget_plan=_budget_plan(allocation=Decimal("0.01")),
        )

    with pytest.raises(CorpusBaselineError, match="allocation count"):
        build_run_authorization_envelope(
            corpus=_live_100_fixture(),
            repo_root=root,
            release_sha=release_sha,
            run_id="test-only",
            staged_configuration=_staged_receipt(),
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            budget_plan=BatchBudgetPlan(
                allocations_usd=(Decimal("50"),),
                aggregate_budget_usd=Decimal("50"),
                target_id="copilot-week2",
                surface_id="copilot-week2-chat",
                raw_bytes=_json_bytes(
                    {
                        "schema_version": "1",
                        "target_id": "copilot-week2",
                        "surface_id": "copilot-week2-chat",
                        "aggregate_budget_usd": "50",
                        "batch_budget_usd": ["50"],
                    }
                ),
            ),
        )


@pytest.mark.parametrize(
    ("configuration", "message"),
    (
        (
            _hosted_configuration(orchestrator_input_limit=65_535),
            "input tokens reservation",
        ),
        (
            _hosted_configuration(price=Decimal("100")),
            "spend reservation",
        ),
    ),
)
def test_run_envelope_fails_closed_when_one_case_exceeds_staged_limits(
    tmp_path: Path,
    configuration: HostedConfigurationSet,
    message: str,
) -> None:
    root, release_sha = _clean_repo(tmp_path)

    with pytest.raises(CorpusBaselineError, match=message):
        build_run_authorization_envelope(
            corpus=_live_100_fixture(),
            repo_root=root,
            release_sha=release_sha,
            run_id="test-only",
            staged_configuration=_staged_receipt(configuration),
            generation_policy=DEFAULT_HOSTED_GENERATION_POLICY,
            budget_plan=_budget_plan(),
        )


def test_stage_receipt_and_batch_budget_plan_are_byte_addressed(
    tmp_path: Path,
) -> None:
    configuration = _hosted_configuration()
    receipt_path = tmp_path / "stage-receipt.json"
    receipt_payload = {
        "schema_version": "1",
        "resource_id": configuration.configuration_sha256,
        "configuration": configuration.canonical_payload(),
    }
    receipt_path.write_text(json.dumps(receipt_payload), encoding="utf-8")
    receipt = load_staged_configuration_receipt(receipt_path)
    assert receipt.resource_id == configuration.configuration_sha256
    assert receipt.receipt_sha256 == hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    receipt_payload["resource_id"] = "f" * 64
    receipt_path.write_text(json.dumps(receipt_payload), encoding="utf-8")
    with pytest.raises(CorpusBaselineError, match="resource_id"):
        load_staged_configuration_receipt(receipt_path)

    budget_path = tmp_path / "budget.json"
    budget_payload = {
        "schema_version": "1",
        "target_id": "copilot-week2",
        "surface_id": "copilot-week2-chat",
        "aggregate_budget_usd": "50",
        "batch_budget_usd": ["2"] * 25,
    }
    budget_path.write_text(json.dumps(budget_payload), encoding="utf-8")
    plan = load_batch_budget_plan(budget_path)
    assert plan.aggregate_budget_usd == Decimal("50")
    assert plan.plan_sha256 == hashlib.sha256(budget_path.read_bytes()).hexdigest()

    budget_payload["batch_budget_usd"] = ["2"] * 26
    budget_path.write_text(json.dumps(budget_payload), encoding="utf-8")
    with pytest.raises(CorpusBaselineError, match="sum exactly"):
        load_batch_budget_plan(budget_path)


def test_safe_loaders_reject_symlink_inputs(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)

    with pytest.raises(CorpusBaselineError, match="symlink"):
        load_staged_configuration_receipt(link)
    with pytest.raises(CorpusBaselineError, match="symlink"):
        load_batch_budget_plan(link)


def test_release_identity_requires_exact_nonzero_clean_head(tmp_path: Path) -> None:
    root, release_sha = _clean_repo(tmp_path)
    assert verify_release_head(root, release_sha) == release_sha

    with pytest.raises(CorpusBaselineError, match="all-zero"):
        verify_release_head(root, "0" * 40)
    with pytest.raises(CorpusBaselineError, match="differs"):
        verify_release_head(root, "a" * 40)

    (root / "dirty.txt").write_text("not committed", encoding="utf-8")
    with pytest.raises(CorpusBaselineError, match="not clean"):
        verify_release_head(root, release_sha)


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
        release_sha="a" * 40,
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

    with pytest.raises(CorpusBaselineError, match="non-negative integer"):
        capture_local_corpus_admission(
            corpus=corpus,
            release_sha="a" * 40,
            run_id="fixture-observation",
            peak_rss_bytes=lambda: -1,
        )


def test_artifacts_are_content_addressed_scoped_and_never_overwritten(
    tmp_path: Path,
) -> None:
    root, release_sha = _clean_repo(tmp_path)
    envelope = _envelope(root, release_sha)
    baseline = _baseline(release_sha)
    output = root / "docs/performance/artifacts/test-run"

    result = write_corpus_baseline_artifacts(
        repo_root=root,
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
            repo_root=root,
            output_directory=output,
            envelope=envelope,
            local_baseline=baseline,
        )
    with pytest.raises(CorpusBaselineError, match="direct child"):
        write_corpus_baseline_artifacts(
            repo_root=root,
            output_directory=root / "escaped-output",
            envelope=envelope,
            local_baseline=baseline,
        )


def test_artifact_writer_rejects_broken_output_symlink(tmp_path: Path) -> None:
    root, _ = _clean_repo(tmp_path)
    output = root / "docs/performance/artifacts/test-run"
    output.parent.mkdir(parents=True)
    output.symlink_to(root / "missing-target", target_is_directory=True)
    _git(root, "add", "-f", "docs/performance/artifacts/test-run")
    _git(root, "commit", "-m", "tracked hostile output link")
    release_sha = _git(root, "rev-parse", "HEAD")
    envelope = _envelope(root, release_sha)

    with pytest.raises(CorpusBaselineError, match="symlink"):
        write_corpus_baseline_artifacts(
            repo_root=root,
            output_directory=output,
            envelope=envelope,
            local_baseline=_baseline(release_sha),
        )


def test_bound_caps_reject_wrong_types_and_symlinked_catalog(tmp_path: Path) -> None:
    root, _ = _clean_repo(tmp_path)
    caps_path = root / "docs/evidence/authorization-requests/caps.json"
    value = json.loads(caps_path.read_text(encoding="utf-8"))
    value["max_attempts_per_run"] = True
    caps_path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(CorpusBaselineError, match="exact integer"):
        verify_bound_caps(root)

    root, _ = _clean_repo(tmp_path / "second")
    catalog = root / "config/live-target-catalog.production.json"
    alternate = root / "catalog-copy.json"
    alternate.write_bytes(catalog.read_bytes())
    catalog.unlink()
    catalog.symlink_to(alternate)
    with pytest.raises(CorpusBaselineError, match="symlink"):
        verify_bound_caps(root)


def test_repository_bound_caps_are_exact_scoped_and_content_addressed() -> None:
    artifacts = verify_bound_caps(_SOURCE_ROOT)

    assert [artifact.path for artifact in artifacts] == list(_BOUND_CAP_PATHS)
    assert all(len(artifact.sha256) == 64 for artifact in artifacts)
    assert all(
        artifact.sha256 == hashlib.sha256((_SOURCE_ROOT / artifact.path).read_bytes()).hexdigest()
        for artifact in artifacts
    )
