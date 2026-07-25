"""The calibration capture must attest the DEPLOYED Judge identity, never one it invented.

An earlier revision of ``scripts/capture_judge_calibration.py`` built its own four-role
``HostedConfigurationSet``.  Because ``judge_model_version`` is the Judge role's
``configuration_sha256`` — which hashes credential reference, prices and limits along with model
and prompt — and because those synthesized limits were sized to the corpus, the attested identity
both drifted with the sample count and could never equal the deployed one.  The measurement was
real; the thing it attested was not in production.

These tests pin the replacement contract: the staged configuration set is supplied, hash-pinned,
and refused rather than repaired.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path
from types import ModuleType

import pytest

from agentforge.agents.hosted import (
    HOSTED_MAX_PHYSICAL_CALLS,
    HOSTED_ROLE_MODELS,
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_prompts import hosted_prompt
from agentforge.agents.hosted_runtime import hosted_judge_identity

ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = ROOT / "scripts" / "capture_judge_calibration.py"

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


def _capture_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("capture_judge_calibration", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _staged_set(*, judge_max_calls: int = HOSTED_MAX_PHYSICAL_CALLS) -> HostedConfigurationSet:
    """A stand-in for what a deployment stages: real prompts, real ceilings, prod-shaped refs."""

    roles = tuple(
        HostedRoleConfiguration(
            role=role,  # type: ignore[arg-type]
            provider="openrouter",
            model_id=model_id,
            upstream_provider=_UPSTREAM[role],
            credential_reference=f"secretref://railway/openrouter/{role}/production",
            prompt_sha256=hosted_prompt(role).prompt_sha256,
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


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _judge_role(configuration: HostedConfigurationSet) -> HostedRoleConfiguration:
    return next(role for role in configuration.roles if role.role == "judge")


# --- the defect this replaces ------------------------------------------------------------


def test_judge_identity_moves_with_the_limits_it_was_built_from() -> None:
    """The regression that motivated the change: identity is limits-sensitive.

    The old capture sized ``max_calls`` to the label count, so calibrating 54 labels and 100
    labels produced two different ``judge_model_version`` values — and neither was the deployed
    one. Pin the sensitivity so nobody reintroduces a corpus-scaled configuration.
    """

    fifty_four = hosted_judge_identity(_staged_set(judge_max_calls=54)).payload()
    fifty_six = hosted_judge_identity(_staged_set(judge_max_calls=56)).payload()

    assert fifty_four["judge_model"] == fifty_six["judge_model"]
    assert fifty_four["judge_model_version"] != fifty_six["judge_model_version"]


# --- staged configuration loading --------------------------------------------------------


def test_staged_configuration_round_trips_and_yields_the_deployed_identity(tmp_path: Path) -> None:
    module = _capture_module()
    staged = _staged_set()
    path = _write(tmp_path / "hosted.json", staged.canonical_payload())

    loaded = module._staged_configuration(path, expected_sha256=staged.configuration_sha256)

    assert loaded.configuration_sha256 == staged.configuration_sha256
    identity = hosted_judge_identity(loaded).payload()
    assert identity["judge_model_version"] == _judge_role(staged).configuration_sha256


def test_staged_configuration_refuses_a_hash_the_operator_did_not_attest(tmp_path: Path) -> None:
    module = _capture_module()
    staged = _staged_set()
    path = _write(tmp_path / "hosted.json", staged.canonical_payload())

    with pytest.raises(SystemExit, match="drifted from the attested identity"):
        module._staged_configuration(path, expected_sha256="0" * 64)


def test_staged_configuration_refuses_a_non_hex_attestation(tmp_path: Path) -> None:
    module = _capture_module()
    staged = _staged_set()
    path = _write(tmp_path / "hosted.json", staged.canonical_payload())

    with pytest.raises(SystemExit, match="64-character"):
        module._staged_configuration(path, expected_sha256="not-a-digest")


def test_staged_configuration_refuses_unreadable_and_malformed_input(tmp_path: Path) -> None:
    module = _capture_module()
    digest = "a" * 64

    with pytest.raises(SystemExit, match="unreadable"):
        module._staged_configuration(tmp_path / "absent.json", expected_sha256=digest)

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit, match="not valid JSON"):
        module._staged_configuration(broken, expected_sha256=digest)


def test_staged_configuration_refuses_a_prompt_identity_this_release_does_not_serve(
    tmp_path: Path,
) -> None:
    """Prompt drift is an identity refusal, not a warning — the deployed prompt IS the identity."""

    module = _capture_module()
    staged = _staged_set()
    payload = staged.canonical_payload()
    for role in payload["roles"]:
        if role["role"] == "judge":
            role["prompt_sha256"] = "b" * 64

    path = _write(tmp_path / "hosted.json", payload)
    with pytest.raises(SystemExit, match="invalid for this release"):
        module._staged_configuration(path, expected_sha256=staged.configuration_sha256)


# --- capacity ---------------------------------------------------------------------------
# A corpus larger than one staged batch is no longer a refusal — it is split into sub-runs against
# the SAME configuration, so judge_model_version stays constant. That behaviour, and the refusal to
# widen the staged limits instead, live in tests/test_judge_calibration_batching.py.


# --- the CLI contract --------------------------------------------------------------------


def test_capture_cli_requires_the_staged_configuration_and_its_attested_hash() -> None:
    """There is no unbound capture path left: both flags are mandatory."""

    completed = subprocess.run(
        [sys.executable, str(_SCRIPT), "--output-dir", "/tmp", "--capture-run-id", "x"],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "--hosted-configuration-set" in completed.stderr
    assert "--expected-configuration-sha256" in completed.stderr
