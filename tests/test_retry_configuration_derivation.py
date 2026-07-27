"""The retry envelope is derived from a reviewed configuration, never inferred.

Two properties matter here and they pull in opposite directions.

The CALL ceilings are pure arithmetic and therefore final: 34 cases x (orchestrator 1 + red_team 1
+ judge 2 + documentation 1) = 34+34+68+34 = 170. The previous 56/136 was the same sum with no
retry anywhere (34 x 4 = 136), which is exactly why one malformed Judge response could not be
retried — the platform envelope had no room for a second physical call regardless of what any
configuration asked for.

The SPEND ceiling is not arithmetic. It depends on per-token prices, which are authority carried
by a reviewed ``HostedConfigurationSet`` and cannot be recovered from a run's measured averages:
an average conflates price with usage mix, says nothing about a role that never executed, and goes
stale the moment a provider re-prices. So the derivation refuses rather than guesses, and these
tests pin the refusal as hard as they pin the arithmetic.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from agentforge.agents.hosted import (
    HOSTED_MAX_GLOBAL_PHYSICAL_CALLS,
    HOSTED_MAX_LOGICAL_RETRIES,
    HOSTED_MAX_PHYSICAL_CALLS,
    HOSTED_ROLE_MAX_MEASURED_USD,
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.prompts import load_prompt_registry
from agentforge.campaign.corpus import LIVE_100_BATCH_IDS, resolve_workload

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from derive_retry_configuration import (  # type: ignore[import-not-found]  # noqa: E402
    DerivationRefused,
    _require_prices,
    check,
    derive,
    load_base,
)

_BATCH_01 = LIVE_100_BATCH_IDS[0]
_PROMPTS = {record.role: record for record in load_prompt_registry()}
_MODELS = {
    "orchestrator": ("anthropic/claude-opus-4.8", "anthropic"),
    "red_team": ("qwen/qwen3.5-397b-a17b", "chutes"),
    "judge": ("google/gemini-2.5-pro", "google-vertex"),
    "documentation": ("openai/gpt-5.4", "openai"),
}

#: A stand-in for the reviewed base. Prices are deliberately DISTINCT per role — including a
#: documentation rate unlike the Judge's — so any code that conflated two roles' prices, or reused
#: one role's rate for another, produces visibly wrong numbers here.
_BASE_PRICES = {
    "orchestrator": ("5", "25", "25"),
    "red_team": ("0.4", "3", "3"),
    "judge": ("1.25", "10", "10"),
    "documentation": ("0.6", "4.8", "4.8"),
}


def _base_configuration(**overrides) -> HostedConfigurationSet:
    roles = []
    for role, (model, upstream) in _MODELS.items():
        pin, pout, preason = _BASE_PRICES[role]
        roles.append(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=model,
                upstream_provider=upstream,
                credential_reference=f"secretref://staging/providers/openrouter/{role}/gen-1",
                prompt_sha256=_PROMPTS[role].sha256,
                policy_sha256=hashlib.sha256(f"{role}:policy:v1".encode()).hexdigest(),
                prices=TokenPrices(
                    input_usd_per_million_tokens=Decimal(pin),
                    output_usd_per_million_tokens=Decimal(pout),
                    reasoning_usd_per_million_tokens=Decimal(preason),
                ),
                limits=HostedLimits(
                    max_calls=34,
                    max_input_tokens=2_000_000,
                    max_output_tokens=500_000,
                    max_reasoning_tokens=500_000,
                    # Each role's own closed ceiling; documentation's is $2, not $4.
                    max_usd=HOSTED_ROLE_MAX_MEASURED_USD[role],
                    max_retries=0,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
        )
    base = HostedConfigurationSet(
        roles=tuple(roles),
        global_limits=HostedLimits(
            max_calls=136,
            max_input_tokens=8_000_000,
            max_output_tokens=2_000_000,
            max_reasoning_tokens=2_000_000,
            max_usd=Decimal("12"),
            max_retries=0,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )
    return dataclasses.replace(base, **overrides) if overrides else base


@pytest.fixture(scope="module")
def base():
    return _base_configuration()


@pytest.fixture(scope="module")
def derivation(base):
    return derive(base, _BATCH_01)


# --------------------------------------------------------------------------------------
# The call arithmetic.
# --------------------------------------------------------------------------------------


def test_the_ceilings_are_exactly_the_largest_batch_worst_case(derivation) -> None:
    case_count = len(resolve_workload(_BATCH_01).cases)
    assert case_count == 34

    judge = derivation["roles"]["judge"]
    assert judge["max_retries"] == 1
    assert judge["max_calls"] == case_count * 2 == 68
    assert HOSTED_MAX_PHYSICAL_CALLS == 68

    assert derivation["global"]["max_calls"] == case_count * 5 == 170
    assert HOSTED_MAX_GLOBAL_PHYSICAL_CALLS == 170


def test_only_the_judge_is_granted_a_retry(derivation) -> None:
    """The Red Team must never re-generate: a second attempt would change the attack."""

    for role, values in derivation["roles"].items():
        assert values["max_retries"] == (1 if role == "judge" else 0), role
        assert values["max_retries"] <= HOSTED_MAX_LOGICAL_RETRIES


def test_token_totals_are_the_policy_bounds_times_the_physical_calls(derivation) -> None:
    policy = DEFAULT_HOSTED_GENERATION_POLICY
    for role, values in derivation["roles"].items():
        bounds = policy.call_bounds[role]
        physical = values["max_calls"]
        assert values["max_input_tokens"] == bounds.input_tokens * physical
        assert values["max_output_tokens"] == bounds.output_tokens * physical
        assert values["max_reasoning_tokens"] == bounds.reasoning_tokens * physical


def test_the_derivation_is_bound_to_the_current_generation_policy(derivation) -> None:
    assert derivation["generation_policy_sha256"] == DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256


# --------------------------------------------------------------------------------------
# Prices come from the base, and only from the base.
# --------------------------------------------------------------------------------------


def test_every_price_is_taken_verbatim_from_the_reviewed_base(derivation) -> None:
    for role, values in derivation["roles"].items():
        expected = _BASE_PRICES[role]
        assert (
            values["price_input"],
            values["price_output"],
            values["price_reasoning"],
        ) == expected


def test_documentation_is_not_priced_as_the_judge(derivation) -> None:
    """A previous version reused the Judge's rate for Documentation, which never executed and so
    had no measured rate of its own."""

    doc = derivation["roles"]["documentation"]
    judge = derivation["roles"]["judge"]
    assert doc["price_input"] != judge["price_input"]
    assert doc["price_output"] != judge["price_output"]


def test_a_missing_role_price_refuses_rather_than_substituting(base) -> None:
    """A HostedConfigurationSet cannot omit a role, so the guard is exercised directly.

    It still matters: the guard is what stands between "this role has no authoritative price" and
    a silently substituted one, which is precisely the defect this rewrite removes.
    """

    from types import SimpleNamespace

    partial = SimpleNamespace(roles=tuple(r for r in base.roles if r.role != "documentation"))
    with pytest.raises(DerivationRefused, match="documentation"):
        _require_prices(partial, {role.role for role in base.roles})


def test_a_non_decimal_price_refuses_rather_than_coercing(base) -> None:
    from types import SimpleNamespace

    broken = SimpleNamespace(
        roles=tuple(
            SimpleNamespace(
                role=r.role,
                prices=SimpleNamespace(
                    input_usd_per_million_tokens=None,
                    output_usd_per_million_tokens=r.prices.output_usd_per_million_tokens,
                    reasoning_usd_per_million_tokens=r.prices.reasoning_usd_per_million_tokens,
                ),
            )
            if r.role == "judge"
            else r
            for r in base.roles
        )
    )
    with pytest.raises(DerivationRefused, match="judge"):
        _require_prices(broken, {role.role for role in base.roles})


def test_a_base_that_is_not_a_configuration_set_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "not-a-config.json"
    path.write_text(json.dumps({"roles": "nonsense"}), encoding="utf-8")
    with pytest.raises(DerivationRefused, match="not a valid HostedConfigurationSet"):
        load_base(path)


def test_an_unreadable_base_is_refused(tmp_path: Path) -> None:
    with pytest.raises(DerivationRefused, match="unreadable"):
        load_base(tmp_path / "missing.json")


def test_a_round_tripped_base_reproduces_its_own_digest(base, tmp_path: Path) -> None:
    """load_base must reconstruct the exact reviewed set, not an approximation of it."""

    path = tmp_path / "base.json"
    path.write_text(json.dumps(base.canonical_payload()), encoding="utf-8")
    assert load_base(path).configuration_sha256 == base.configuration_sha256


# --------------------------------------------------------------------------------------
# The derived set is a stageable configuration that changes only what the retry forces.
# --------------------------------------------------------------------------------------


def test_the_derived_payload_is_a_real_stageable_configuration(derivation) -> None:
    rebuilt = HostedConfigurationSet.from_payload(derivation["derived_payload"])
    assert rebuilt.configuration_sha256 == derivation["derived_configuration_sha256"]


def test_the_derivation_supersedes_rather_than_replaces_the_base(derivation, base) -> None:
    assert derivation["base_configuration_sha256"] == base.configuration_sha256
    assert derivation["derived_configuration_sha256"] != base.configuration_sha256


def test_unchanged_authority_is_preserved_verbatim(derivation, base) -> None:
    """Model, upstream, prompt, credential reference and prices must survive untouched."""

    derived = HostedConfigurationSet.from_payload(derivation["derived_payload"])
    original = {role.role: role for role in base.roles}
    for role in derived.roles:
        source = original[role.role]
        assert role.model_id == source.model_id
        assert role.upstream_provider == source.upstream_provider
        assert role.prompt_sha256 == source.prompt_sha256
        assert role.credential_reference == source.credential_reference
        assert role.policy_sha256 == source.policy_sha256
        assert role.prices == source.prices
        assert role.limits.max_requests_per_second == source.limits.max_requests_per_second
        assert role.limits.max_concurrency == source.limits.max_concurrency


def test_only_the_judge_limits_gain_a_retry_in_the_derived_set(derivation) -> None:
    derived = HostedConfigurationSet.from_payload(derivation["derived_payload"])
    for role in derived.roles:
        assert role.limits.max_retries == (1 if role.role == "judge" else 0), role.role
    assert derived.global_limits.max_retries == 1
    assert derived.global_limits.max_calls == 170


# --------------------------------------------------------------------------------------
# Spend is recomputed from those exact prices — never assumed to still fit.
# --------------------------------------------------------------------------------------


def test_the_derivation_fits_the_authorized_envelope(derivation) -> None:
    assert check(derivation) == []


def test_global_spend_is_the_sum_of_the_role_worst_cases(derivation) -> None:
    parts = sum(Decimal(v["worst_case_usd"]) for v in derivation["roles"].values())
    assert parts == Decimal(derivation["global"]["worst_case_usd"])


def test_expensive_prices_are_refused_instead_of_silently_widening_the_ceiling() -> None:
    """If a reviewed base prices a role higher, the ceiling must be re-derived, not assumed."""

    costly = _base_configuration()
    roles = tuple(
        dataclasses.replace(
            role,
            prices=TokenPrices(
                input_usd_per_million_tokens=role.prices.input_usd_per_million_tokens * 100,
                output_usd_per_million_tokens=role.prices.output_usd_per_million_tokens * 100,
                reasoning_usd_per_million_tokens=role.prices.reasoning_usd_per_million_tokens * 100,
            ),
        )
        for role in costly.roles
    )
    # The derivation REFUSES rather than emitting a configuration whose cap exceeds the reviewed
    # platform ceiling — a cap that large cannot even be constructed, and silently trimming it
    # would under-authorize a run that will overspend.
    with pytest.raises(DerivationRefused, match="exceeds the reviewed platform"):
        derive(dataclasses.replace(costly, roles=roles), _BATCH_01)


def test_an_oversized_workload_is_refused_rather_than_rounded_up(derivation) -> None:
    inflated = dict(derivation)
    inflated["global"] = dict(derivation["global"])
    inflated["global"]["max_calls"] = HOSTED_MAX_GLOBAL_PHYSICAL_CALLS + 1
    problems = check(inflated)
    assert any("global needs" in problem for problem in problems)


@pytest.mark.parametrize("batch_id", LIVE_100_BATCH_IDS)
def test_every_reviewed_batch_fits_the_raised_envelope(base, batch_id: str) -> None:
    assert check(derive(base, batch_id)) == []
