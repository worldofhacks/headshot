"""Network-free authority tests for one immutable four-role OpenRouter configuration set."""

from __future__ import annotations

import hashlib
import socket
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, localcontext

import pytest
from pydantic import ValidationError

from agentforge.agents.hosted import (
    HOSTED_MAX_PHYSICAL_CALLS,
    HostedConfigurationSet,
    HostedLimits,
    HostedReservationCostError,
    HostedRoleConfiguration,
    TokenPrices,
    preflight_hosted_configuration_set,
    resolve_hosted_prompt,
)
from agentforge.agents.prompts import load_prompt_registry
from agentforge.api.read_models import HostedRunBindingReadModel
from agentforge.api.router import HostedLimitsInput, HostedRunBindingInput

MODELS = {
    "orchestrator": "anthropic/claude-opus-4.8",
    "red_team": "qwen/qwen3.5-397b-a17b",
    "judge": "google/gemini-2.5-pro",
    "documentation": "openai/gpt-5.4",
}
CALL_CAPS = {
    "orchestrator": 9,
    "red_team": 19,
    "judge": 19,
    "documentation": 9,
}
USD_CAPS = {
    "orchestrator": Decimal("0.75"),
    "red_team": Decimal("1"),
    "judge": Decimal("2.50"),
    "documentation": Decimal("0.50"),
}
UPSTREAM_PROVIDERS = {
    "orchestrator": "amazon-bedrock/eu-west-1",
    "red_team": "atlas-cloud/fp8",
    "judge": "google-vertex/global",
    "documentation": "azure/eu",
}
COMPLETION_TOKEN_PARAMETERS = {
    "orchestrator": "max_tokens",
    "red_team": "max_tokens",
    "judge": "max_tokens",
    "documentation": "max_completion_tokens",
}
_PROMPTS = {record.role: record for record in load_prompt_registry()}


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
        completion_token_parameter=COMPLETION_TOKEN_PARAMETERS[role],
        credential_reference=(
            f"secretref://staging/providers/openrouter/{role}/generation-20260724"
        ),
        prompt_sha256=_PROMPTS[role].sha256,
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
        first.schema_version = "3"  # type: ignore[misc]


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
    assert tuple(_PROMPTS) == (
        "orchestrator",
        "red_team",
        "judge",
        "documentation",
    )
    for role in MODELS:
        prompt = _PROMPTS[role]
        assert prompt.role == role
        assert prompt.version == _role(role).prompt_version
        assert prompt.sha256 == hashlib.sha256(prompt.content.encode("utf-8")).hexdigest()
        assert prompt.content.endswith("\n")
        assert resolve_hosted_prompt(role, prompt.sha256) == prompt

    with pytest.raises(ValueError, match="four-role catalog"):
        resolve_hosted_prompt("unknown", "0" * 64)


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
    assert (
        replace(_limits("judge"), max_calls=HOSTED_MAX_PHYSICAL_CALLS).max_calls
        == HOSTED_MAX_PHYSICAL_CALLS
    )
    with pytest.raises(ValueError, match="closed platform maximum"):
        replace(_limits("judge"), max_calls=HOSTED_MAX_PHYSICAL_CALLS + 1)
    with pytest.raises(ValueError, match="between zero and 1"):
        replace(_limits("judge"), max_retries=2)
    with pytest.raises(ValueError, match="closed platform maximum"):
        replace(_limits("judge"), max_usd=Decimal("10.01"))
    with pytest.raises(ValueError, match="positive"):
        replace(_limits("judge"), max_calls=0)


def test_api_hosted_call_validators_share_the_closed_400_call_ceiling() -> None:
    binding = {
        "configuration_set_sha256": "a" * 64,
        "generation_policy_sha256": "b" * 64,
        "session_generation": "generation-20260724",
        "provider_model_call_limit": HOSTED_MAX_PHYSICAL_CALLS,
        "provider_model_spend_limit_usd": "5",
        "provider_max_retries": 1,
        "provider_max_concurrency": 1,
        "provider_timeout_seconds": 180.0,
    }
    limits = {
        "max_calls": HOSTED_MAX_PHYSICAL_CALLS,
        "max_input_tokens": 1,
        "max_output_tokens": 1,
        "max_reasoning_tokens": 1,
        "max_usd": "1",
        "max_retries": 1,
        "max_requests_per_second": "0.5",
        "max_concurrency": 1,
    }

    assert HostedRunBindingInput.model_validate(binding).provider_model_call_limit == 400
    assert HostedRunBindingReadModel.model_validate(binding).provider_model_call_limit == 400
    assert HostedLimitsInput.model_validate(limits).max_calls == 400

    with pytest.raises(ValidationError):
        HostedRunBindingInput.model_validate(
            {**binding, "provider_model_call_limit": HOSTED_MAX_PHYSICAL_CALLS + 1}
        )
    with pytest.raises(ValidationError):
        HostedRunBindingReadModel.model_validate(
            {**binding, "provider_model_call_limit": HOSTED_MAX_PHYSICAL_CALLS + 1}
        )
    with pytest.raises(ValidationError):
        HostedLimitsInput.model_validate({**limits, "max_calls": HOSTED_MAX_PHYSICAL_CALLS + 1})


@pytest.mark.parametrize(
    ("role", "invalid_cap"),
    (
        ("orchestrator", Decimal("1.51")),
        ("red_team", Decimal("1.01")),
        ("judge", Decimal("4.01")),
        ("documentation", Decimal("1.01")),
    ),
)
def test_role_cash_caps_cannot_exceed_governance_ceilings(
    role: str,
    invalid_cap: Decimal,
) -> None:
    with pytest.raises(ValueError, match="role ceiling"):
        replace(_role(role), limits=replace(_limits(role), max_usd=invalid_cap))


def test_every_identity_price_and_cap_change_rebinds_the_hash() -> None:
    baseline = _configuration()
    changed_upstream = replace(
        baseline.roles[0],
        upstream_provider="anthropic-beta",
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
    changed_completion_parameter = replace(
        baseline.roles[0],
        completion_token_parameter="max_completion_tokens",
    )

    assert _configuration((changed_upstream, *baseline.roles[1:])).configuration_sha256 != (
        baseline.configuration_sha256
    )
    assert _configuration((changed_price, *baseline.roles[1:])).configuration_sha256 != (
        baseline.configuration_sha256
    )
    assert (
        _configuration((changed_completion_parameter, *baseline.roles[1:])).configuration_sha256
        != baseline.configuration_sha256
    )
    assert replace(baseline, global_limits=changed_cap).configuration_sha256 != (
        baseline.configuration_sha256
    )


@pytest.mark.parametrize("routing_slug", ("Google", "google vertex", "auto"))
def test_routing_provider_requires_an_exact_lowercase_openrouter_slug(
    routing_slug: str,
) -> None:
    with pytest.raises(ValueError, match="provider slug"):
        replace(_role("judge"), upstream_provider=routing_slug)


def test_nested_endpoint_tag_and_completion_parameter_are_closed_authority() -> None:
    judge = _role("judge")

    assert judge.upstream_provider == "google-vertex/global"
    assert judge.completion_token_parameter == "max_tokens"
    with pytest.raises(ValueError, match="completion token parameter"):
        replace(judge, completion_token_parameter="max_output_tokens")
    for invalid_tag in ("google-vertex//global", "google-vertex/Global", "google-vertex/global/"):
        with pytest.raises(ValueError, match="provider slug"):
            replace(judge, upstream_provider=invalid_tag)


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


def test_reservation_cost_is_independent_of_hostile_ambient_precision() -> None:
    prices = TokenPrices(
        input_usd_per_million_tokens=Decimal("5.5"),
        output_usd_per_million_tokens=Decimal("27.5"),
        reasoning_usd_per_million_tokens=Decimal("27.5"),
    )

    with localcontext() as context:
        context.prec = 2
        reservation = prices.maximum_reservation_usd(
            input_tokens=65_536,
            output_tokens=2_048,
            reasoning_tokens=8_192,
            physical_attempts=100,
        )

    assert reservation == Decimal("64.2048")


def test_reservation_cost_rejects_unrepresentable_authority_without_rounding() -> None:
    hostile_price = Decimal("0." + ("1" * 300))
    prices = TokenPrices(
        input_usd_per_million_tokens=hostile_price,
        output_usd_per_million_tokens=Decimal("1"),
        reasoning_usd_per_million_tokens=Decimal("1"),
    )

    with pytest.raises(HostedReservationCostError, match="cannot be represented exactly"):
        prices.maximum_reservation_usd(
            input_tokens=1,
            output_tokens=0,
            reasoning_tokens=0,
        )


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
