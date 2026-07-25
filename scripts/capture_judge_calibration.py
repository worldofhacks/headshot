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
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentforge.agents.hosted import HostedConfigurationSet
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.hosted_runtime import (
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
_MAX_CONFIGURATION_BYTES = 256 * 1024


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
        "--judge-role-config",
        type=Path,
        required=True,
        help=(
            "the STAGED hosted configuration-set payload "
            "({schema_version, roles, global_limits}) the campaign will run under. Required: the "
            "Judge identity content-addresses this whole role configuration, so calibrating "
            "against anything else produces an identity the runtime rejects as identity_drift. "
            "Must be the full four-role set — HostedConfigurationSet validates the set as a unit "
            "and the identity binds the Red Team role too, for independence."
        ),
    )
    parser.add_argument(
        "--confirm-provider-spend",
        action="store_true",
        help="required acknowledgement that this makes real, billed OpenRouter calls",
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

    configuration = _load_configuration_set(args.judge_role_config)
    policy = DEFAULT_HOSTED_GENERATION_POLICY
    call_bounds = {item.role: item.bounds for item in policy.roles}
    _preflight(configuration, policy=policy, sample_count=len(labels))

    identity = hosted_judge_identity(configuration)
    global_limits = configuration.global_limits
    authorization = HostedRunBinding(
        configuration_set_sha256=configuration.configuration_sha256,
        # Server-owned, resolved by the private Runner through a closed registry. Using the real
        # policy identity (rather than one minted here) keeps the capture inside the same
        # generation envelope a campaign runs under.
        generation_policy_sha256=policy.policy_sha256,
        session_generation=args.capture_run_id,
        # Derived from the staged configuration, never chosen here: _validate_hosted_authority
        # requires the binding and the configuration-set global limits to agree exactly.
        provider_model_call_limit=global_limits.max_calls,
        provider_model_spend_limit_usd=format(global_limits.max_usd, "f"),
        provider_max_retries=global_limits.max_retries,
        provider_max_concurrency=global_limits.max_concurrency,
        provider_timeout_seconds=call_bounds["judge"].timeout_seconds,
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
            call_bounds=call_bounds,
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
            "generation_policy_sha256": policy.policy_sha256,
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
            "configuration_sha256": configuration.configuration_sha256,
            "judge_role_configuration_sha256": judge_role.configuration_sha256,
            "generation_policy_sha256": policy.policy_sha256,
            "judge_role_config_source": str(args.judge_role_config),
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


def _load_configuration_set(path: Path) -> HostedConfigurationSet:
    """Load the STAGED four-role configuration set and rebuild it through its own validator.

    Rebuilding via ``from_payload`` rather than trusting the file means the content-addressed
    identity is recomputed here from the staged fields. If the payload were altered in transit the
    resulting ``configuration_sha256`` simply would not match what production holds, and the
    calibration would be rejected downstream as identity drift rather than quietly binding to a
    configuration nobody staged.
    """

    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise SystemExit(
            f"refusing to run: staged configuration set is unreadable ({exc})"
        ) from exc
    if len(encoded) > _MAX_CONFIGURATION_BYTES:
        raise SystemExit("refusing to run: staged configuration set exceeds its size bound")
    try:
        payload = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SystemExit(
            f"refusing to run: staged configuration set is not valid JSON ({exc})"
        ) from exc
    try:
        return HostedConfigurationSet.from_payload(payload)
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"refusing to run: staged configuration set is invalid ({exc})") from exc


def _preflight(
    configuration: HostedConfigurationSet,
    *,
    policy: Any,
    sample_count: int,
) -> None:
    """Refuse before the first billed call if the staged envelope cannot cover the corpus.

    Every check here is one that would otherwise surface partway through a paid capture -- the
    usage ledger reserves against role and global caps on each request, so an under-sized cap
    aborts mid-run after spending real money and leaves a partial bundle that covers only some
    labels (which ``load_captured_calibration_evaluator`` then rejects for incomplete coverage).
    """

    judge = next((role for role in configuration.roles if role.role == "judge"), None)
    if judge is None:
        raise SystemExit("refusing to run: staged configuration set has no judge role")
    bounds = {item.role: item.bounds for item in policy.roles}["judge"]

    problems: list[str] = []
    if judge.limits.max_calls < sample_count:
        problems.append(
            f"judge role max_calls={judge.limits.max_calls} cannot cover {sample_count} labels"
        )
    if configuration.global_limits.max_calls < sample_count:
        problems.append(
            f"global max_calls={configuration.global_limits.max_calls} cannot cover "
            f"{sample_count} labels"
        )
    # The ledger reserves the full per-call upper bound before each request and settles down to
    # measured usage afterwards, so the budget has to cover the reserved worst case.
    for label, required, allowed in (
        ("input tokens", bounds.input_tokens * sample_count, judge.limits.max_input_tokens),
        ("output tokens", bounds.output_tokens * sample_count, judge.limits.max_output_tokens),
        (
            "reasoning tokens",
            bounds.reasoning_tokens * sample_count,
            judge.limits.max_reasoning_tokens,
        ),
    ):
        if allowed < required:
            problems.append(
                f"judge role max {label} = {allowed:,} below the {required:,} reserved for "
                f"{sample_count} calls at the server-owned generation policy bounds"
            )
    if bounds.timeout_seconds <= 0:
        problems.append("generation policy judge timeout is not positive")
    if problems:
        raise SystemExit(
            "refusing to run, staged envelope cannot cover this corpus:\n  - "
            + "\n  - ".join(problems)
        )


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
