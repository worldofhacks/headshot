#!/usr/bin/env python3
"""Derive the governed hosted configuration that authorizes one Judge structured-output retry.

Run 50da57b037d44b3c93a10e4c2edf61a8 ended on case 12 of 34 because a single Gemini response
failed the Judge's JSON Schema and could not be retried. The transport now classifies that
failure as retryable, but retry authority comes from a governed configuration set — never from
code — so the fix is inert until a human stages a configuration whose Judge ``max_retries`` is 1.

This script DERIVES that configuration and prints it with its content digest. It deliberately
cannot apply it: staging a configuration set is an append-only governed write that requires a
Clerk principal holding ``org:config:manage``, and inventing that authority in a script is
exactly the kind of shortcut this platform exists to catch.

Every limit below is computed from the exact worst case rather than chosen. Re-running this after
a policy or workload change produces different numbers and a different digest, which is the
point: the caps and the thing they bound cannot drift apart silently.

Usage:
    python scripts/derive_retry_configuration.py [--workload headshot-live-100-batch-01]
    python scripts/derive_retry_configuration.py --json   # payload only, for review or diffing
"""

from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentforge.agents.hosted import (  # noqa: E402
    HOSTED_MAX_GLOBAL_PHYSICAL_CALLS,
    HOSTED_MAX_MEASURED_USD,
    HOSTED_MAX_PHYSICAL_CALLS,
    HOSTED_ROLE_MAX_MEASURED_USD,
)
from agentforge.agents.hosted_policy import (  # noqa: E402
    DEFAULT_HOSTED_GENERATION_POLICY,
)
from agentforge.campaign.corpus import (  # noqa: E402
    LIVE_100_BATCH_IDS,
    resolve_workload,
)

#: Only the Judge is granted a retry. The Red Team must not re-generate (it would change the
#: attack), and the Orchestrator/Documentation failures are not worth spending authority on.
_RETRY_ROLES = {"judge": 1}


def _role_prices() -> dict[str, dict[str, Decimal]]:
    """Per-million-token prices, SOLVED from the measured totals of run 50da57b0.

    Not list prices and not guesses. Each role's rate is recovered from what that run was actually
    charged, so the worst case below is anchored to observed billing:

        orchestrator  16,103 in + 6,495 out/reasoning = $0.242890   -> $5.00 / $25.00  (exact)
        judge         94,970 in + 10,295 out/reasoning = $0.2216625 -> $1.25 / $10.00  (exact)
        red_team       3,457 in + 47,083 out/reasoning = $0.14276145 -> $0.40 / $3.00  (~0.1% off)

    Documentation never executed in that run — it only fires on a confirmed finding — so it has no
    measured rate. It is priced at the Judge's rate, which is an ASSUMPTION and is flagged as such
    in the output. Replace it with the staged configuration's real prices before relying on the
    documentation row.
    """

    judge = {"input": Decimal("1.25"), "output": Decimal("10"), "reasoning": Decimal("10")}
    return {
        "orchestrator": {
            "input": Decimal("5"),
            "output": Decimal("25"),
            "reasoning": Decimal("25"),
        },
        "red_team": {"input": Decimal("0.4"), "output": Decimal("3"), "reasoning": Decimal("3")},
        "judge": judge,
        "documentation": dict(judge),
    }


#: Roles whose price is assumed rather than measured, surfaced in the output.
_ASSUMED_PRICE_ROLES = frozenset({"documentation"})


def derive(workload_id: str) -> dict:
    corpus = resolve_workload(workload_id)
    case_count = len(corpus.cases)
    policy = DEFAULT_HOSTED_GENERATION_POLICY
    logical = policy.required_logical_calls(case_count=case_count)
    prices = _role_prices()

    roles: dict[str, dict] = {}
    totals = {"calls": 0, "input": 0, "output": 0, "reasoning": 0, "usd": Decimal(0)}

    for role, logical_calls in logical.items():
        retries = _RETRY_ROLES.get(role, 0)
        physical = logical_calls * (1 + retries)
        bounds = policy.call_bounds[role]
        tokens = {
            "input": bounds.input_tokens * physical,
            "output": bounds.output_tokens * physical,
            "reasoning": bounds.reasoning_tokens * physical,
        }
        # Worst case charges reasoning at the higher of the output/reasoning rate, matching the
        # runtime's own preflight arithmetic in _require_hosted_workload_capacity.
        per_call = (
            prices[role]["input"] * bounds.input_tokens
            + prices[role]["output"] * bounds.output_tokens
            + max(prices[role]["output"], prices[role]["reasoning"]) * bounds.reasoning_tokens
        ) / Decimal(1_000_000)
        usd = (per_call * physical).quantize(Decimal("0.000001"))

        roles[role] = {
            "logical_calls": logical_calls,
            "max_retries": retries,
            "max_calls": physical,
            "max_input_tokens": tokens["input"],
            "max_output_tokens": tokens["output"],
            "max_reasoning_tokens": tokens["reasoning"],
            "worst_case_usd": str(usd),
            "max_usd": str(HOSTED_ROLE_MAX_MEASURED_USD[role]),
            "per_call_timeout_seconds": bounds.timeout_seconds,
            "price_is_assumed": role in _ASSUMED_PRICE_ROLES,
        }
        totals["calls"] += physical
        for kind in ("input", "output", "reasoning"):
            totals[kind] += tokens[kind]
        totals["usd"] += usd

    return {
        "workload_id": workload_id,
        "case_count": case_count,
        "generation_policy_sha256": policy.policy_sha256,
        "roles": roles,
        "global": {
            "max_calls": totals["calls"],
            "max_input_tokens": totals["input"],
            "max_output_tokens": totals["output"],
            "max_reasoning_tokens": totals["reasoning"],
            "worst_case_usd": str(totals["usd"].quantize(Decimal("0.000001"))),
            "max_usd": str(HOSTED_MAX_MEASURED_USD),
            "max_retries": max(_RETRY_ROLES.values(), default=0),
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
        if Decimal(values["worst_case_usd"]) > Decimal(values["max_usd"]):
            problems.append(
                f"{role} worst case ${values['worst_case_usd']} exceeds its ${values['max_usd']} cap"
            )
    if derivation["global"]["max_calls"] > HOSTED_MAX_GLOBAL_PHYSICAL_CALLS:
        problems.append(
            f"global needs {derivation['global']['max_calls']} calls, "
            f"ceiling is {HOSTED_MAX_GLOBAL_PHYSICAL_CALLS}"
        )
    if Decimal(derivation["global"]["worst_case_usd"]) > HOSTED_MAX_MEASURED_USD:
        problems.append(
            f"global worst case ${derivation['global']['worst_case_usd']} "
            f"exceeds the ${HOSTED_MAX_MEASURED_USD} platform ceiling"
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", default=LIVE_100_BATCH_IDS[0])
    parser.add_argument("--json", action="store_true", help="print the payload only")
    args = parser.parse_args()

    derivation = derive(args.workload)
    problems = check(derivation)

    if args.json:
        print(json.dumps(derivation, indent=2, sort_keys=True))
        return 1 if problems else 0

    print(f"workload            {derivation['workload_id']} ({derivation['case_count']} cases)")
    print(f"generation policy   {derivation['generation_policy_sha256']}")
    print()
    print(
        f"{'role':<14} {'logical':>8} {'retry':>6} {'physical':>9} "
        f"{'input':>10} {'output':>9} {'reason':>9} {'worst $':>10}"
    )
    for role, values in derivation["roles"].items():
        print(
            f"{role:<14} {values['logical_calls']:>8} {values['max_retries']:>6} "
            f"{values['max_calls']:>9} {values['max_input_tokens']:>10} "
            f"{values['max_output_tokens']:>9} {values['max_reasoning_tokens']:>9} "
            f"{values['worst_case_usd']:>10}"
        )
    g = derivation["global"]
    print(
        f"{'GLOBAL':<14} {'':>8} {'':>6} {g['max_calls']:>9} "
        f"{g['max_input_tokens']:>10} {g['max_output_tokens']:>9} "
        f"{g['max_reasoning_tokens']:>9} {g['worst_case_usd']:>10}"
    )
    print()
    print(
        f"platform ceilings   per-role {derivation['platform_ceilings']['per_role_calls']} "
        f"/ global {derivation['platform_ceilings']['global_calls']} "
        f"/ ${derivation['platform_ceilings']['measured_usd']}"
    )
    print()
    if problems:
        print("REFUSED — this derivation does not fit the platform envelope:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    assumed = [r for r, v in derivation["roles"].items() if v["price_is_assumed"]]
    if assumed:
        print(f"NOTE  price assumed (not measured) for: {', '.join(assumed)}")
        print()
    print("Derivation fits the platform envelope.")
    print()
    print("NOT APPLIED. Staging this configuration is an append-only governed write requiring a")
    print("Clerk principal with org:config:manage. Until it is staged, Judge max_retries stays 0")
    print("and the structured-output retry cannot fire.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
