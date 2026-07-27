#!/usr/bin/env python3
"""Derive a stageable hosted configuration granting the Judge one structured-output retry.

Run 50da57b037d44b3c93a10e4c2edf61a8 ended on case 12 of 34 because a single Gemini response
failed the Judge's JSON Schema and could not be retried. The transport now classifies that failure
as retryable, but retry authority comes from a governed configuration set — never from code — so
the fix stays inert until a human stages a configuration whose Judge ``max_retries`` is 1.

This script derives that configuration FROM AN EXACT REVIEWED BASE and prints it with its real
``configuration_sha256``. It cannot apply it: staging is an append-only governed write requiring a
Clerk principal holding ``org:config:manage``.

Two rules make the output trustworthy:

* **Prices are never inferred.** An earlier version of this script solved per-token prices from a
  run's measured averages. That is arithmetic on a sample, not authority: it cannot distinguish a
  price from a usage mix, it silently invents a rate for any role that did not execute, and it
  would drift the moment a provider re-priced. Prices now come only from the reviewed base
  configuration, and a role whose price is absent causes a refusal rather than a guess.
* **Only the retry allocation changes.** Models, upstreams, prompts, opaque credential references,
  request rates, concurrency and every other field are copied verbatim from the base. The derived
  set differs from its base in exactly the limits that the retry makes necessary, so a reviewer
  compares two configurations rather than auditing a fabricated one.

Usage:
    python scripts/derive_retry_configuration.py --base-configuration reviewed-config.json
    python scripts/derive_retry_configuration.py --base-configuration cfg.json --emit-payload

``--base-configuration`` takes the canonical payload of a reviewed ``HostedConfigurationSet`` — the
same JSON shape ``HostedConfigurationSet.canonical_payload()`` produces. Export it from the staged
configuration you intend to supersede.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from decimal import ROUND_CEILING, Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentforge.agents.hosted import (  # noqa: E402
    HOSTED_MAX_GLOBAL_PHYSICAL_CALLS,
    HOSTED_MAX_MEASURED_USD,
    HOSTED_MAX_PHYSICAL_CALLS,
    HOSTED_ROLE_MAX_MEASURED_USD,
    HostedConfigurationSet,
)
from agentforge.agents.hosted_policy import (  # noqa: E402
    DEFAULT_HOSTED_GENERATION_POLICY,
)
from agentforge.campaign.corpus import (  # noqa: E402
    LIVE_100_BATCH_IDS,
    resolve_workload,
)


def _ceil_cents(value: Decimal) -> Decimal:
    """Round a worst case UP to the cent. Rounding down would under-authorize the run."""

    return value.quantize(Decimal("0.01"), rounding=ROUND_CEILING)


class DerivationRefused(Exception):
    """The derivation cannot be completed from authoritative inputs alone."""


#: Only the Judge is granted a retry. The Red Team must not re-generate — a second attempt would
#: change the attack — and Orchestrator/Documentation failures are not worth spending authority on.
_RETRY_ROLES = {"judge": 1}


def load_base(path: Path) -> HostedConfigurationSet:
    """Load a reviewed configuration set, refusing anything that is not exactly one."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DerivationRefused(f"base configuration is unreadable: {exc}") from exc
    try:
        return HostedConfigurationSet.from_payload(payload)
    except Exception as exc:
        raise DerivationRefused(
            f"base configuration is not a valid HostedConfigurationSet: {exc}"
        ) from exc


def _require_prices(base: HostedConfigurationSet, roles: set[str]) -> dict[str, object]:
    """Every role the workload will invoke must carry a complete price in the base."""

    by_role = {role.role: role for role in base.roles}
    missing = sorted(roles - set(by_role))
    if missing:
        raise DerivationRefused(
            f"base configuration has no entry for: {', '.join(missing)} — "
            "cannot derive spend without an authoritative price"
        )
    for name in sorted(roles):
        prices = by_role[name].prices
        for field in (
            "input_usd_per_million_tokens",
            "output_usd_per_million_tokens",
            "reasoning_usd_per_million_tokens",
        ):
            value = getattr(prices, field, None)
            if not isinstance(value, Decimal):
                raise DerivationRefused(f"{name}: {field} is absent or not a Decimal in the base")
    return by_role


def derive(base: HostedConfigurationSet, workload_id: str) -> dict:
    """Build the derived configuration and its worst case from the base's exact prices."""

    corpus = resolve_workload(workload_id)
    case_count = len(corpus.cases)
    policy = DEFAULT_HOSTED_GENERATION_POLICY
    logical = policy.required_logical_calls(case_count=case_count)
    by_role = _require_prices(base, set(logical))

    derived_roles = []
    rows: dict[str, dict] = {}
    totals = {"calls": 0, "input": 0, "output": 0, "reasoning": 0, "usd": Decimal(0)}

    for role_name, logical_calls in logical.items():
        base_role = by_role[role_name]
        retries = _RETRY_ROLES.get(role_name, 0)
        physical = logical_calls * (1 + retries)
        bounds = policy.call_bounds[role_name]
        tokens = {
            "input": bounds.input_tokens * physical,
            "output": bounds.output_tokens * physical,
            "reasoning": bounds.reasoning_tokens * physical,
        }
        prices = base_role.prices
        # Worst case charges reasoning at the higher of the output/reasoning rate, matching the
        # runtime's own preflight arithmetic in _require_hosted_workload_capacity.
        per_call = (
            prices.input_usd_per_million_tokens * bounds.input_tokens
            + prices.output_usd_per_million_tokens * bounds.output_tokens
            + max(
                prices.output_usd_per_million_tokens,
                prices.reasoning_usd_per_million_tokens,
            )
            * bounds.reasoning_tokens
        ) / Decimal(1_000_000)
        worst = (per_call * physical).quantize(Decimal("0.000001"))

        # The configured cap must COVER the worst case, not merely inherit whatever the base
        # happened to allow: inheriting is how a retry silently outgrows its authority. Round up
        # to the cent, then refuse below if that exceeds the reviewed platform ceiling.
        role_cap = max(_ceil_cents(worst), base_role.limits.max_usd)

        # Everything except the limits is copied verbatim: model, upstream, prompt hash, opaque
        # credential reference, prices. The derived set must differ from its base only where the
        # retry forces it to.
        derived_roles.append(
            dataclasses.replace(
                base_role,
                limits=dataclasses.replace(
                    base_role.limits,
                    max_calls=physical,
                    max_input_tokens=tokens["input"],
                    max_output_tokens=tokens["output"],
                    max_reasoning_tokens=tokens["reasoning"],
                    max_usd=role_cap,
                    max_retries=retries,
                ),
            )
        )
        rows[role_name] = {
            "logical_calls": logical_calls,
            "max_retries": retries,
            "max_calls": physical,
            "max_input_tokens": tokens["input"],
            "max_output_tokens": tokens["output"],
            "max_reasoning_tokens": tokens["reasoning"],
            "worst_case_usd": str(worst),
            "role_spend_cap": str(role_cap),
            "base_role_spend_cap": str(base_role.limits.max_usd),
            "platform_role_spend_ceiling": str(HOSTED_ROLE_MAX_MEASURED_USD[role_name]),
            "price_input": str(prices.input_usd_per_million_tokens),
            "price_output": str(prices.output_usd_per_million_tokens),
            "price_reasoning": str(prices.reasoning_usd_per_million_tokens),
            "model_id": base_role.model_id,
            "upstream_provider": base_role.upstream_provider,
        }
        totals["calls"] += physical
        for kind in ("input", "output", "reasoning"):
            totals[kind] += tokens[kind]
        totals["usd"] += worst

    global_worst = totals["usd"].quantize(Decimal("0.000001"))
    global_cap = max(_ceil_cents(global_worst), base.global_limits.max_usd)
    derived = dataclasses.replace(
        base,
        roles=tuple(derived_roles),
        global_limits=dataclasses.replace(
            base.global_limits,
            max_calls=totals["calls"],
            max_input_tokens=totals["input"],
            max_output_tokens=totals["output"],
            max_reasoning_tokens=totals["reasoning"],
            max_usd=global_cap,
            max_retries=max(_RETRY_ROLES.values(), default=0),
        ),
    )

    return {
        "workload_id": workload_id,
        "case_count": case_count,
        "generation_policy_sha256": DEFAULT_HOSTED_GENERATION_POLICY.policy_sha256,
        "base_configuration_sha256": base.configuration_sha256,
        "derived_configuration_sha256": derived.configuration_sha256,
        "derived_payload": derived.canonical_payload(),
        "roles": rows,
        "global": {
            "max_calls": totals["calls"],
            "max_input_tokens": totals["input"],
            "max_output_tokens": totals["output"],
            "max_reasoning_tokens": totals["reasoning"],
            "worst_case_usd": str(global_worst),
            "configured_spend_cap": str(global_cap),
            "base_configured_spend_cap": str(base.global_limits.max_usd),
            "platform_spend_ceiling": str(HOSTED_MAX_MEASURED_USD),
        },
        "platform_ceilings": {
            "per_role_calls": HOSTED_MAX_PHYSICAL_CALLS,
            "global_calls": HOSTED_MAX_GLOBAL_PHYSICAL_CALLS,
            "measured_usd": str(HOSTED_MAX_MEASURED_USD),
        },
    }


def check(derivation: dict) -> list[str]:
    """Every way this derivation could be unsafe, reported rather than raised."""

    problems: list[str] = []
    for role, values in derivation["roles"].items():
        if values["max_calls"] > HOSTED_MAX_PHYSICAL_CALLS:
            problems.append(
                f"{role} needs {values['max_calls']} calls, ceiling is {HOSTED_MAX_PHYSICAL_CALLS}"
            )
        worst = Decimal(values["worst_case_usd"])
        if worst > Decimal(values["role_spend_cap"]):
            problems.append(
                f"{role} worst case ${worst} exceeds its configured ${values['role_spend_cap']} cap"
            )
        if worst > Decimal(values["platform_role_spend_ceiling"]):
            problems.append(
                f"{role} worst case ${worst} exceeds the platform role ceiling "
                f"${values['platform_role_spend_ceiling']}"
            )
    g = derivation["global"]
    if g["max_calls"] > HOSTED_MAX_GLOBAL_PHYSICAL_CALLS:
        problems.append(
            f"global needs {g['max_calls']} calls, ceiling is {HOSTED_MAX_GLOBAL_PHYSICAL_CALLS}"
        )
    if Decimal(g["worst_case_usd"]) > HOSTED_MAX_MEASURED_USD:
        problems.append(
            f"global worst case ${g['worst_case_usd']} exceeds the platform spend ceiling "
            f"${HOSTED_MAX_MEASURED_USD} — the ceiling must be re-derived from these exact prices, "
            "not assumed"
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-configuration",
        required=True,
        type=Path,
        help="canonical payload JSON of the reviewed HostedConfigurationSet to supersede",
    )
    parser.add_argument("--workload", default=LIVE_100_BATCH_IDS[0])
    parser.add_argument(
        "--emit-payload",
        action="store_true",
        help="print the complete stageable payload instead of the summary",
    )
    args = parser.parse_args()

    try:
        base = load_base(args.base_configuration)
        derivation = derive(base, args.workload)
    except DerivationRefused as exc:
        print(f"REFUSED — {exc}", file=sys.stderr)
        print(
            "Prices are never inferred. Supply the reviewed configuration that carries them.",
            file=sys.stderr,
        )
        return 2

    problems = check(derivation)

    if args.emit_payload:
        print(json.dumps(derivation["derived_payload"], indent=2, sort_keys=True))
        print(
            f"\n# derived_configuration_sha256 = {derivation['derived_configuration_sha256']}",
            file=sys.stderr,
        )
        return 1 if problems else 0

    print(f"workload              {derivation['workload_id']} ({derivation['case_count']} cases)")
    print(f"generation policy     {derivation['generation_policy_sha256']}")
    print(f"base configuration    {derivation['base_configuration_sha256']}")
    print(f"derived configuration {derivation['derived_configuration_sha256']}")
    print()
    print(f"{'role':<14} {'retry':>5} {'physical':>9} {'in $/M':>8} {'out $/M':>8} {'worst $':>10}")
    for role, v in derivation["roles"].items():
        print(
            f"{role:<14} {v['max_retries']:>5} {v['max_calls']:>9} "
            f"{v['price_input']:>8} {v['price_output']:>8} {v['worst_case_usd']:>10}"
        )
    g = derivation["global"]
    print(f"{'GLOBAL':<14} {'':>5} {g['max_calls']:>9} {'':>8} {'':>8} {g['worst_case_usd']:>10}")
    print()
    print(
        f"spend                 worst ${g['worst_case_usd']} vs configured "
        f"${g['configured_spend_cap']} vs platform ${g['platform_spend_ceiling']}"
    )
    print()

    if problems:
        print("REFUSED — this derivation does not fit the authorized envelope:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("Derivation fits the authorized envelope.")
    print()
    print("NOT APPLIED. Staging this configuration is an append-only governed write requiring a")
    print("Clerk principal with org:config:manage. Until it is staged, Judge max_retries stays 0")
    print("and the structured-output retry cannot fire.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
