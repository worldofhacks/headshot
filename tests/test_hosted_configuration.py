"""Network-free authority tests for one immutable four-role OpenRouter configuration set."""

from __future__ import annotations

import hashlib
import socket
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, localcontext

import pytest

from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
    preflight_hosted_configuration_set,
)
from agentforge.agents.hosted_prompts import HOSTED_PROMPTS, hosted_prompt

MODELS = {
    "orchestrator": "anthropic/claude-opus-4.8",
    "red_team": "qwen/qwen3.5-397b-a17b",
    "judge": "google/gemini-2.5-pro",
    "documentation": "openai/gpt-5.4",
}
CALL_CAPS = {
    "orchestrator": 8,
    "red_team": 21,
    "judge": 21,
    "documentation": 6,
}
USD_CAPS = {
    "orchestrator": Decimal("0.75"),
    "red_team": Decimal("1.25"),
    "judge": Decimal("2.50"),
    "documentation": Decimal("0.50"),
}
UPSTREAM_PROVIDERS = {
    "orchestrator": "Anthropic",
    "red_team": "Together",
    "judge": "Google",
    "documentation": "OpenAI",
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _limits(role: str) -> HostedLimits:
    calls = CALL_CAPS[role]
    return HostedLimits(
        max_calls=calls,
        max_input_tokens=calls * 10_000,
        max_output_tokens=calls * 2_000,
        max_reasoning_tokens=calls * 1_000,
        max_usd=USD_CAPS[role],
        max_retries=1,
        max_requests_per_second=Decimal("0.5"),
        max_concurrency=1,
    )


def _role(role: str) -> HostedRoleConfiguration:
    return HostedRoleConfiguration(
        role=role,
        provider="openrouter",
        model_id=MODELS[role],
        upstream_provider=UPSTREAM_PROVIDERS[role],
        credential_reference=(
            f"secretref://staging/providers/openrouter/{role}/generation-20260724"
        ),
        prompt_sha256=hosted_prompt(role).prompt_sha256,
        policy_sha256=_digest(f"{role}:policy:v1"),
        prices=TokenPrices(
            input_usd_per_million_tokens=Decimal("1.25"),
            output_usd_per_million_tokens=Decimal("10"),
            reasoning_usd_per_million_tokens=Decimal("10"),
        ),
        limits=_limits(role),
    )


def _configuration(
    roles: tuple[HostedRoleConfiguration, ...] | None = None,
) -> HostedConfigurationSet:
    return HostedConfigurationSet(
        roles=roles
        or (
            _role("judge"),
            _role("documentation"),
            _role("orchestrator"),
            _role("red_team"),
        ),
        global_limits=HostedLimits(
            max_calls=56,
            max_input_tokens=560_000,
            max_output_tokens=112_000,
            max_reasoning_tokens=56_000,
            max_usd=Decimal("5"),
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def test_configuration_is_frozen_canonical_and_order_independent() -> None:
    first = _configuration()
    second = _configuration(tuple(reversed(first.roles)))

    assert [item.role for item in first.roles] == [
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    ]
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.configuration_sha256 == second.configuration_sha256
    assert len(first.configuration_sha256) == 64
    with pytest.raises(FrozenInstanceError):
        first.schema_version = "2"  # type: ignore[misc]


def test_configuration_requires_each_exact_role_once() -> None:
    complete = _configuration()

    with pytest.raises(ValueError, match="exactly once"):
        _configuration(complete.roles[:-1])
    with pytest.raises(ValueError, match="exactly once"):
        _configuration((*complete.roles[:-1], complete.roles[0]))


def test_models_are_exact_unique_non_alias_openrouter_ids() -> None:
    complete = _configuration()
    orchestrator = complete.roles[0]

    with pytest.raises(ValueError, match="provider must be openrouter"):
        replace(orchestrator, provider="anthropic")
    for alias in (
        "openrouter/auto",
        "openrouter/free",
        "anthropic/claude-latest",
        "~anthropic/claude",
    ):
        with pytest.raises(ValueError, match="model"):
            replace(orchestrator, model_id=alias)

    with pytest.raises(ValueError, match="frozen recovery assignment"):
        replace(orchestrator, model_id="anthropic/claude-opus-4.8-pinned")


def test_credential_references_are_opaque_role_unique_and_never_raw_keys() -> None:
    complete = _configuration()
    red_team = complete.roles[1]

    with pytest.raises(ValueError, match="opaque secretref"):
        replace(red_team, credential_reference="env:OPENROUTER_API_KEY")
    with pytest.raises(ValueError, match="opaque secretref"):
        replace(red_team, credential_reference="sk-or-" + ("a" * 48))
    with pytest.raises(ValueError, match="opaque secretref"):
        replace(
            red_team,
            credential_reference=(
                f"secretref://staging/providers/openrouter/sk-or-{'a' * 48}/generation-20260724"
            ),
        )

    reused = replace(
        complete.roles[2],
        credential_reference=complete.roles[1].credential_reference,
    )
    with pytest.raises(ValueError, match="credential references must be pairwise distinct"):
        _configuration((complete.roles[0], complete.roles[1], reused, complete.roles[3]))


def test_judge_and_red_team_require_frozen_independent_models_and_prompts() -> None:
    complete = _configuration()
    red_team = complete.roles[1]
    judge = complete.roles[2]

    with pytest.raises(ValueError, match="frozen recovery assignment"):
        replace(judge, model_id="qwen/gemini-2.5-pro")

    with pytest.raises(ValueError, match="server-owned role prompt"):
        replace(judge, prompt_sha256=red_team.prompt_sha256)


def test_prompt_registry_is_exact_content_addressed_and_versioned() -> None:
    assert tuple(HOSTED_PROMPTS) == (
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    )
    for role in MODELS:
        prompt = hosted_prompt(role)
        assert prompt.role == role
        assert prompt.version == _role(role).prompt_version
        assert (
            prompt.prompt_sha256 == hashlib.sha256(prompt.system_prompt.encode("utf-8")).hexdigest()
        )
        assert prompt.system_prompt == prompt.system_prompt.strip()

    with pytest.raises(ValueError, match="four-role catalog"):
        hosted_prompt("unknown")


def test_prices_and_limits_require_decimal_units_and_closed_bounds() -> None:
    with pytest.raises(TypeError, match="Decimal"):
        TokenPrices(
            input_usd_per_million_tokens=1.25,  # type: ignore[arg-type]
            output_usd_per_million_tokens=Decimal("10"),
            reasoning_usd_per_million_tokens=Decimal("10"),
        )
    with pytest.raises(TypeError, match="Decimal"):
        replace(_limits("judge"), max_requests_per_second=0.5)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="0.5"):
        replace(_limits("judge"), max_requests_per_second=Decimal("0.5001"))
    with pytest.raises(ValueError, match="concurrency"):
        replace(_limits("judge"), max_concurrency=2)
    with pytest.raises(ValueError, match="closed platform maximum"):
        replace(_limits("judge"), max_calls=57)
    with pytest.raises(ValueError, match="between zero and 1"):
        replace(_limits("judge"), max_retries=2)
    with pytest.raises(ValueError, match="closed platform maximum"):
        replace(_limits("judge"), max_usd=Decimal("5.01"))
    with pytest.raises(ValueError, match="positive"):
        replace(_limits("judge"), max_calls=0)


def test_every_identity_price_and_cap_change_rebinds_the_hash() -> None:
    baseline = _configuration()
    changed_upstream = replace(
        baseline.roles[0],
        upstream_provider="Anthropic Enterprise",
    )
    changed_price = replace(
        baseline.roles[0],
        prices=replace(
            baseline.roles[0].prices,
            input_usd_per_million_tokens=Decimal("1.26"),
        ),
    )
    changed_cap = replace(
        baseline.global_limits,
        max_usd=Decimal("4.99"),
    )

    assert _configuration((changed_upstream, *baseline.roles[1:])).configuration_sha256 != (
        baseline.configuration_sha256
    )
    assert _configuration((changed_price, *baseline.roles[1:])).configuration_sha256 != (
        baseline.configuration_sha256
    )
    assert replace(baseline, global_limits=changed_cap).configuration_sha256 != (
        baseline.configuration_sha256
    )


def test_decimal_canonicalization_is_independent_of_ambient_context() -> None:
    baseline = _configuration()

    with localcontext() as context:
        context.prec = 2
        lower = replace(
            baseline.global_limits,
            max_usd=Decimal("4.98"),
        )
        higher = replace(
            baseline.global_limits,
            max_usd=Decimal("4.99"),
        )
        lower_hash = replace(baseline, global_limits=lower).configuration_sha256
        higher_hash = replace(baseline, global_limits=higher).configuration_sha256

    assert lower_hash != higher_hash


def test_configuration_round_trips_only_its_exact_canonical_payload() -> None:
    baseline = _configuration()

    reconstructed = HostedConfigurationSet.from_payload(baseline.canonical_payload())

    assert reconstructed == baseline
    with pytest.raises(ValueError, match="invalid shape"):
        HostedConfigurationSet.from_payload(
            {**baseline.canonical_payload(), "activation": "active"}
        )


def test_preflight_is_zero_call_and_projects_hashes_not_credential_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configuration = _configuration()

    def deny_socket(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("configuration preflight attempted network access")

    monkeypatch.setattr(socket, "socket", deny_socket)
    result = preflight_hosted_configuration_set(configuration)

    assert result.ok is True
    assert result.configuration_sha256 == configuration.configuration_sha256
    assert len(result.roles) == 4
    assert all(len(item.credential_reference_sha256) == 64 for item in result.roles)
    rendered = repr(result)
    for role in configuration.roles:
        assert role.credential_reference not in rendered
