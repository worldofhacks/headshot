#!/usr/bin/env python3
"""Capture one hosted-evaluator calibration bundle by really invoking the Judge model.

This is the ONLY component in the calibration chain that talks to a provider.  It exists because
``scripts/run_judge_calibration.py`` is deliberately network-free: it can measure the deterministic
oracle Judge, but the *model* Judge can only be measured from previously captured, lineage-complete
outcomes.  This script produces exactly that bundle, in the shape
``agentforge.agents.judge.calibration_results.load_captured_calibration_evaluator`` validates.

What it does NOT do:

* It never contacts a live TARGET.  No attack is executed, no campaign is launched, no target
  credential is resolved.  The only egress is OpenRouter, for the Judge role, over authored
  synthetic calibration evidence.
* It never writes a verdict, never enables the model Judge at runtime, and never approves anything.
  Calibration measurement, human approval, and runtime enablement stay three separate operations.
* It never sees or transmits a ground-truth label.  ``HostedEvaluator`` projects a BLINDED envelope
  (``_bounded_model_envelope``): the label reference, the policy-decision string, the attempt/run
  identifiers, and every trusted oracle/canary signal are stripped before the provider call, and
  the projection reports only that those channels were withheld — identically for every sample, so
  it carries no information about the sample's class.  Reconciliation back to the label happens
  locally, from the unmodified envelope.

Judge independence is structural and unchanged: the Judge model family (``google``) differs from
the Red Team model family (``qwen``), the two carry different prompt and policy identities, and the
hosted assessment schema has no ``EXPLOIT_CONFIRMED`` member — only an oracle, a canary, or a human
can confirm an exploit.

Spend is bounded three ways: the role/global ``HostedLimits``, the ``HostedRunBinding`` authorized
call and spend ceilings, and the shared ``HostedUsageLedger`` that reserves before every physical
request and settles on measured provider cost.  ``--confirm-provider-spend`` is required so a
paid provider run is always an explicit act.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from agentforge.agents.hosted import (
    HOSTED_ROLE_MODELS,
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_prompts import hosted_prompt
from agentforge.agents.hosted_runtime import (
    HostedCallBounds,
    HostedExecutionLineage,
    HostedRoleRuntime,
    hosted_judge_identity,
)
from agentforge.agents.judge import CalibrationInputError, HostedEvaluator
from agentforge.correlation import campaign_trace_id
from agentforge.evals.validation import validate_ground_truth_slice
from agentforge.providers import HostedUsageLedger, OpenRouterTransport
from agentforge.secrets import Secret
from agentforge.target.spec import HostedRunBinding

_ROOT = Path(__file__).resolve().parents[1]
_GROUND_TRUTH = _ROOT / "evals" / "ground-truth"

# The exact non-secret provider envelope this capture is authorized to use. Every value is
# recorded in the emitted bundle's provenance so the measurement is reproducible and auditable.
_CREDENTIAL_REFERENCE_PREFIX = "secretref://local/openrouter"
_SESSION_GENERATION = "generation-1"
_GLOBAL_MAX_CALLS = 56
_GLOBAL_MAX_USD = Decimal("10")

# Upstream OpenRouter routing slugs, pinned per role. `provider.only` is sent with
# `allow_fallbacks: false`, so a silent reroute to a different upstream cannot happen.
_UPSTREAM = {
    "orchestrator": "anthropic",
    "red_team": "together",
    "judge": "google-vertex",
    "documentation": "openai",
}

# Ceilings must be >= the endpoint's live list price or OpenRouter refuses the request outright
# (`provider.max_price`, USD per million tokens). These are price CEILINGS, never a cost estimate:
# the bundle records the provider's own measured cost per sample.
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

_JUDGE_CALL_BOUNDS = HostedCallBounds(
    input_tokens=120_000,
    output_tokens=4_000,
    reasoning_tokens=8_000,
    timeout_seconds=180.0,
)


class CaptureError(RuntimeError):
    """The capture could not be completed safely."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--slice-dir",
        type=Path,
        default=_GROUND_TRUTH,
        help="versioned ground-truth slice directory (default: evals/ground-truth)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="directory to write captured-results.json, judge-identity.json and the run manifest",
    )
    parser.add_argument(
        "--capture-run-id",
        required=True,
        help="stable identifier for this capture; seeds the per-sample correlation trace ids",
    )
    parser.add_argument(
        "--confirm-provider-spend",
        action="store_true",
        help="required acknowledgement that this makes real, billed OpenRouter calls",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=_GLOBAL_MAX_CALLS,
        help=f"refuse to start if the corpus exceeds this many labels (default {_GLOBAL_MAX_CALLS})",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if not args.confirm_provider_spend:
        raise SystemExit(
            "refusing to run: --confirm-provider-spend is required because this issues real, "
            "billed OpenRouter requests"
        )
    credential = os.environ.get("OPENROUTER_API_KEY", "")
    if not credential:
        raise SystemExit("refusing to run: OPENROUTER_API_KEY is not set")

    slices = _load_slices(args.slice_dir)
    labels = [(item["category"], label) for item in slices for label in item["labels"]]
    labels.sort(key=lambda pair: pair[1]["label_id"])
    if not labels:
        raise SystemExit("refusing to run: the ground-truth corpus has no labels")
    if len(labels) > args.max_samples:
        raise SystemExit(
            f"refusing to run: {len(labels)} labels exceeds the authorized call budget "
            f"({args.max_samples})"
        )

    configuration = _configuration(call_capacity=len(labels))
    identity = hosted_judge_identity(configuration)
    generation_policy_sha256 = _generation_policy_sha256(configuration, sample_count=len(labels))
    authorization = HostedRunBinding(
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=generation_policy_sha256,
        session_generation=_SESSION_GENERATION,
        provider_model_call_limit=_GLOBAL_MAX_CALLS,
        provider_model_spend_limit_usd=format(_GLOBAL_MAX_USD, "f"),
        provider_max_retries=1,
        provider_max_concurrency=1,
        provider_timeout_seconds=_JUDGE_CALL_BOUNDS.timeout_seconds,
    )

    lifecycle = _InMemoryExecutionLifecycle()
    ledger = HostedUsageLedger(configuration)
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda reference: _resolve(reference, configuration, credential),
        ledger=ledger,
    )
    try:
        runtime = HostedRoleRuntime(
            configuration=configuration,
            transport=transport,
            authorization=authorization,
            call_bounds=dict.fromkeys(
                (role.role for role in configuration.roles), _JUDGE_CALL_BOUNDS
            ),
            execution_lifecycle=lifecycle,
        )
        evaluator = HostedEvaluator(runtime=runtime)
        samples: list[dict[str, Any]] = []
        returned_models: set[str] = set()
        for index, (category, label) in enumerate(labels, start=1):
            label_id = label["label_id"]
            print(f"[{index}/{len(labels)}] {category} {label_id}", flush=True)
            result = evaluator.evaluate(
                label["evidence_envelope"],
                integrity_ok=True,
                sanitized=True,
            )
            lineage = result.lineage
            returned_models.add(lineage.returned_model)
            samples.append(
                {
                    "label_id": label_id,
                    "assessment": dict(result.assessment),
                    "provider_request_id": lineage.provider_request_id,
                    "trace_id": campaign_trace_id(f"{args.capture_run_id}:{label_id}"),
                    "returned_model": lineage.returned_model,
                    "input_tokens": lineage.input_tokens,
                    "output_tokens": lineage.output_tokens,
                    "reasoning_tokens": lineage.reasoning_tokens,
                    "measured_cost_usd": lineage.measured_cost_usd,
                }
            )
    finally:
        transport.close()

    if len(returned_models) != 1:
        raise CaptureError("provider returned more than one model identity across the capture")
    judge_role = next(role for role in configuration.roles if role.role == "judge")
    bundle = {
        "schema_version": "1",
        "judge_identity": identity.payload(),
        "provenance": {
            "capture_kind": "openrouter_hosted_evaluator",
            "configuration_sha256": configuration.configuration_sha256,
            "role_configuration_sha256": judge_role.configuration_sha256,
            "generation_policy_sha256": generation_policy_sha256,
            "requested_model": judge_role.model_id,
            "returned_model": returned_models.pop(),
            "captured_at": datetime.now(UTC).isoformat(),
        },
        "samples": samples,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.output_dir / "captured-results.json", bundle)
    _write_json(args.output_dir / "judge-identity.json", identity.payload())
    _write_json(
        args.output_dir / "capture-manifest.json",
        {
            "capture_run_id": args.capture_run_id,
            "sample_count": len(samples),
            "slice_ids": sorted(item["slice_id"] for item in slices),
            "ledger": {
                "physical_calls": ledger.snapshot.physical_calls,
                "measured_usd": format(ledger.snapshot.measured_usd, "f"),
                "unresolved_exposure_usd": format(
                    ledger.snapshot.unresolved_exposure_usd,
                    "f",
                ),
            },
            "executions": lifecycle.summary(),
            "trace_id_derivation": (
                "agentforge.correlation.campaign_trace_id('<capture_run_id>:<label_id>') — the "
                "platform's W3C-compatible correlation id. This offline capture does not export "
                "to Langfuse, so this is NOT a Langfuse trace id."
            ),
        },
    )
    print(
        f"captured {len(samples)} assessments; measured spend "
        f"${format(ledger.snapshot.measured_usd, 'f')}",
        flush=True,
    )
    return 0


def _resolve(
    reference: str,
    configuration: HostedConfigurationSet,
    credential: str,
) -> Secret:
    """Hand the OpenRouter key to the Judge role only; every other role stays uncallable."""

    judge = next(role for role in configuration.roles if role.role == "judge")
    if reference != judge.credential_reference:
        raise CaptureError("only the Judge role is authorized in a calibration capture")
    return Secret(credential)


def _token_capacity(call_capacity: int) -> int:
    """Per-role token budget in whole calls, with headroom for reserve-then-settle accounting."""

    return min(max(call_capacity, 1) + 2, _GLOBAL_MAX_CALLS)


def _configuration(*, call_capacity: int) -> HostedConfigurationSet:
    """Build the frozen four-role set. Only the Judge role is ever invoked here.

    All four roles must be present: ``HostedConfigurationSet`` validates the complete set so that
    Judge/Red Team independence (distinct model family, prompt identity, and policy identity) is
    checked structurally rather than asserted.
    """

    roles = tuple(
        HostedRoleConfiguration(
            role=role,  # type: ignore[arg-type]
            provider="openrouter",
            model_id=model_id,
            upstream_provider=_UPSTREAM[role],
            credential_reference=(
                f"{_CREDENTIAL_REFERENCE_PREFIX}/{role}/judge-calibration-{_SESSION_GENERATION}"
            ),
            prompt_sha256=hosted_prompt(role).prompt_sha256,
            policy_sha256=hashlib.sha256(
                f"judge-calibration-capture:{role}:v1".encode()
            ).hexdigest(),
            prices=_PRICES[role],
            limits=HostedLimits(
                max_calls=(max(call_capacity, 1) if role == "judge" else 1),
                # The ledger RESERVES the full per-call upper bound before each request and only
                # settles down to measured usage afterwards, so a budget sized to exactly
                # bounds * capacity sits on the boundary and can exhaust on the final sample.
                # Two calls of headroom keeps the cap meaningful without making it decorative.
                max_input_tokens=_JUDGE_CALL_BOUNDS.input_tokens * _token_capacity(call_capacity),
                max_output_tokens=_JUDGE_CALL_BOUNDS.output_tokens * _token_capacity(call_capacity),
                max_reasoning_tokens=(
                    _JUDGE_CALL_BOUNDS.reasoning_tokens * _token_capacity(call_capacity)
                ),
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
            max_calls=_GLOBAL_MAX_CALLS,
            max_input_tokens=_JUDGE_CALL_BOUNDS.input_tokens * _GLOBAL_MAX_CALLS,
            max_output_tokens=_JUDGE_CALL_BOUNDS.output_tokens * _GLOBAL_MAX_CALLS,
            max_reasoning_tokens=_JUDGE_CALL_BOUNDS.reasoning_tokens * _GLOBAL_MAX_CALLS,
            max_usd=_GLOBAL_MAX_USD,
            max_retries=1,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _generation_policy_sha256(
    configuration: HostedConfigurationSet,
    *,
    sample_count: int,
) -> str:
    """Content-address the exact generation envelope this capture is authorized to use."""

    return hashlib.sha256(
        json.dumps(
            {
                "purpose": "judge-calibration-capture",
                "configuration_sha256": configuration.configuration_sha256,
                "sample_count": sample_count,
                "call_bounds": {
                    "input_tokens": _JUDGE_CALL_BOUNDS.input_tokens,
                    "output_tokens": _JUDGE_CALL_BOUNDS.output_tokens,
                    "reasoning_tokens": _JUDGE_CALL_BOUNDS.reasoning_tokens,
                    "timeout_seconds": _JUDGE_CALL_BOUNDS.timeout_seconds,
                },
            },
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


class _InMemoryExecutionLifecycle:
    """Satisfy the mandatory lifecycle seam without a control-plane database.

    A calibration capture is not a campaign: there is no run row, no attempt, and no durable
    ledger to write to. The lifecycle is still exercised (start before the call, finish after it)
    so the runtime's ordering guarantees hold, and its tally is written into the run manifest.
    """

    def __init__(self) -> None:
        self._starts: list[dict[str, Any]] = []
        self._finishes: list[dict[str, Any]] = []

    def start(self, **kwargs: Any) -> str:
        self._starts.append(dict(kwargs))
        return f"judge-calibration-execution-{len(self._starts)}"

    def finish(
        self,
        *,
        execution_id: str,
        status: str,
        output_payload: Mapping[str, Any],
        lineage: HostedExecutionLineage | None,
        error_code: str | None,
        failed_physical_attempts: int | None = None,
    ) -> None:
        self._finishes.append(
            {
                "execution_id": execution_id,
                "status": status,
                "error_code": error_code,
                "failed_physical_attempts": failed_physical_attempts,
                "physical_attempts": (None if lineage is None else lineage.physical_attempts),
            }
        )

    def summary(self) -> dict[str, Any]:
        return {
            "started": len(self._starts),
            "finished": len(self._finishes),
            "succeeded": sum(item["status"] == "succeeded" for item in self._finishes),
            "failed": sum(item["status"] == "failed" for item in self._finishes),
            "physical_attempts_total": sum(
                item["physical_attempts"] or item["failed_physical_attempts"] or 0
                for item in self._finishes
            ),
        }


def _load_slices(path: Path) -> list[dict[str, Any]]:
    candidates = sorted(path.glob("*.json"))
    if not candidates:
        raise SystemExit("ground-truth slice directory has no JSON slices")
    slices: list[dict[str, Any]] = []
    for candidate in candidates:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
        try:
            validate_ground_truth_slice(payload, source=candidate)
        except Exception as exc:
            raise CalibrationInputError(
                f"ground-truth slice {candidate.name} fails validation"
            ) from exc
        slices.append(payload)
    return slices


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
