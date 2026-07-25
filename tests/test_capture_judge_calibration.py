"""The calibration capture harness must bind to the STAGED configuration, or refuse.

The Judge identity content-addresses the whole judge role configuration, so a capture taken under
any other configuration produces an identity the runtime rejects as `identity_drift`. These tests
pin that the harness cannot silently calibrate against something other than what was staged, and
that an envelope too small for the corpus is refused BEFORE the first billed provider call rather
than part-way through one.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from agentforge.agents.hosted import HOSTED_ROLE_MODELS
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.hosted_prompts import hosted_prompt
from agentforge.agents.hosted_runtime import hosted_judge_identity

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "capture_judge_calibration.py"

_UPSTREAM = {
    "orchestrator": "anthropic",
    "red_team": "together",
    "judge": "google-vertex",
    "documentation": "openai",
}
_PRICES = {
    "orchestrator": ("15", "75", "75"),
    "red_team": ("1", "5", "5"),
    "judge": ("5", "30", "30"),
    "documentation": ("5", "30", "30"),
}
_ROLE_USD = {
    "orchestrator": "1.50",
    "red_team": "1",
    "judge": "4",
    "documentation": "1",
}


def _harness():
    spec = importlib.util.spec_from_file_location("capture_judge_calibration", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _staged_payload(**role_limit_overrides: Any) -> dict[str, Any]:
    """A structurally valid four-role staged configuration set.

    Values here stand in for what production stages; the point of these tests is the harness's
    handling of the payload, never the specific numbers.
    """

    roles = []
    for role, model_id in HOSTED_ROLE_MODELS.items():
        prompt_in, prompt_out, reasoning = _PRICES[role]
        limits = {
            "max_calls": 56,
            "max_input_tokens": 6_000_000,
            "max_output_tokens": 200_000,
            "max_reasoning_tokens": 600_000,
            "max_usd": _ROLE_USD[role],
            "max_retries": 1,
            "max_requests_per_second": "0.5",
            "max_concurrency": 1,
        }
        if role == "judge":
            limits.update(role_limit_overrides)
        roles.append(
            {
                "role": role,
                "provider": "openrouter",
                "model_id": model_id,
                "upstream_provider": _UPSTREAM[role],
                "credential_reference": f"secretref://staged/openrouter/{role}/generation-1",
                "prompt_sha256": hosted_prompt(role).prompt_sha256,
                "policy_sha256": hashlib.sha256(f"staged:{role}".encode()).hexdigest(),
                "prices": {
                    "input_usd_per_million_tokens": prompt_in,
                    "output_usd_per_million_tokens": prompt_out,
                    "reasoning_usd_per_million_tokens": reasoning,
                },
                "limits": limits,
            }
        )
    return {
        "schema_version": "1",
        "roles": roles,
        "global_limits": {
            "max_calls": 56,
            "max_input_tokens": 6_000_000,
            "max_output_tokens": 400_000,
            "max_reasoning_tokens": 600_000,
            "max_usd": "10",
            "max_retries": 1,
            "max_requests_per_second": "0.5",
            "max_concurrency": 1,
        },
    }


def _write(tmp_path: Path, payload: Any, name: str = "staged.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_identity_comes_from_the_staged_configuration_not_from_harness_constants(
    tmp_path: Path,
) -> None:
    harness = _harness()
    configuration = harness._load_configuration_set(_write(tmp_path, _staged_payload()))
    identity = hosted_judge_identity(configuration)

    judge = next(role for role in configuration.roles if role.role == "judge")
    # The identity's model_version IS the judge role configuration hash — that is the whole
    # binding, and it must be recomputed from the staged fields.
    assert identity.judge_model_version == judge.configuration_sha256
    assert judge.credential_reference == "secretref://staged/openrouter/judge/generation-1"
    # Independence is structural and survives the rebind.
    assert identity.judge_model.split("/")[0] != identity.red_team_model.split("/")[0]


def test_changing_any_staged_field_changes_the_identity(tmp_path: Path) -> None:
    """If this ever stops holding, calibration could be reused across configurations."""

    harness = _harness()
    baseline = hosted_judge_identity(
        harness._load_configuration_set(_write(tmp_path, _staged_payload(), "a.json"))
    ).judge_model_version

    for override in ({"max_calls": 55}, {"max_usd": "3"}, {"max_output_tokens": 199_000}):
        payload = _staged_payload(**override)
        drifted = hosted_judge_identity(
            harness._load_configuration_set(
                _write(tmp_path, payload, f"drift-{tuple(override)[0]}.json")
            )
        ).judge_model_version
        assert drifted != baseline, f"{override} did not change the judge identity"


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"max_calls": 30}, "max_calls=30 cannot cover 54 labels"),
        ({"max_input_tokens": 1_000}, "max input tokens"),
        ({"max_output_tokens": 1_000}, "max output tokens"),
        ({"max_reasoning_tokens": 1_000}, "max reasoning tokens"),
    ],
)
def test_preflight_refuses_an_envelope_too_small_for_the_corpus(
    tmp_path: Path,
    override: dict[str, Any],
    expected: str,
) -> None:
    """Refusal must happen before the first billed call, not part-way through a paid capture."""

    harness = _harness()
    configuration = harness._load_configuration_set(_write(tmp_path, _staged_payload(**override)))
    with pytest.raises(SystemExit) as raised:
        harness._preflight(
            configuration,
            policy=DEFAULT_HOSTED_GENERATION_POLICY,
            sample_count=54,
        )
    assert expected in str(raised.value)


def test_preflight_accepts_the_staged_envelope_for_the_real_corpus_size(tmp_path: Path) -> None:
    harness = _harness()
    configuration = harness._load_configuration_set(_write(tmp_path, _staged_payload()))
    harness._preflight(configuration, policy=DEFAULT_HOSTED_GENERATION_POLICY, sample_count=54)


def test_malformed_or_oversized_staged_configuration_is_refused(tmp_path: Path) -> None:
    harness = _harness()

    not_json = tmp_path / "bad.json"
    not_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit, match="not valid JSON"):
        harness._load_configuration_set(not_json)

    with pytest.raises(SystemExit, match="invalid"):
        harness._load_configuration_set(_write(tmp_path, {"roles": []}, "shape.json"))

    with pytest.raises(SystemExit, match="unreadable"):
        harness._load_configuration_set(tmp_path / "does-not-exist.json")

    oversized = tmp_path / "big.json"
    oversized.write_text(" " * (harness._MAX_CONFIGURATION_BYTES + 1), encoding="utf-8")
    with pytest.raises(SystemExit, match="size bound"):
        harness._load_configuration_set(oversized)


def test_only_the_judge_credential_reference_resolves(tmp_path: Path) -> None:
    """A calibration capture must not be able to spend any other role's credential."""

    harness = _harness()
    configuration = harness._load_configuration_set(_write(tmp_path, _staged_payload()))
    judge = next(role for role in configuration.roles if role.role == "judge")

    assert harness._resolve(judge.credential_reference, configuration, "key").reveal() == "key"
    for role in configuration.roles:
        if role.role == "judge":
            continue
        with pytest.raises(harness.CaptureError):
            harness._resolve(role.credential_reference, configuration, "key")
