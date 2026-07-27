#!/usr/bin/env python3
"""Capture one hosted-evaluator calibration bundle by really invoking the Judge model.

This is the ONLY component in the calibration chain that talks to a provider.  It exists because
``scripts/run_judge_calibration.py`` is deliberately network-free: it can measure the deterministic
oracle Judge, but the *model* Judge can only be measured from previously captured, lineage-complete
outcomes.  This script produces exactly that bundle, in the shape
``agentforge.agents.judge.calibration_results.load_captured_calibration_evaluator`` validates.

IDENTITY IS SUPPLIED, NEVER SYNTHESIZED
---------------------------------------
A calibration is only meaningful for the exact evaluator that will run in production, so this
capture refuses to invent one.  ``--hosted-configuration-set`` takes the staged four-role
configuration set *as deployed*, and ``--expected-configuration-sha256`` pins the value the
deploying operator attested; the run aborts on any mismatch.  Every identity-bearing field then
comes from that staged set:

    judge_model_version == judge_role.configuration_sha256
                        == sha256(role, provider, model_id, upstream_provider,
                                  credential_reference, prompt_sha256, policy_sha256,
                                  prices, limits)

so model, prompt, and limits are all inside the identity hash, and ``HostedRoleConfiguration``
independently rejects a staged ``prompt_sha256`` that does not equal this release's server-owned
role prompt.  An earlier revision of this script built its own configuration set, whose
``credential_reference``, ``prices``, and *sample-count-scaled* ``limits`` were capture-local
inventions.  The identity it produced therefore changed with the corpus size and could never equal
the deployed one — the measurement was real, but it attested an evaluator production would never
run.  That path is deliberately gone.

The provider secret is still resolved locally from ``OPENROUTER_API_KEY``.  Only the staged
``credential_reference`` *string* is identity-bearing; the secret value behind it is not, and is
never written to the bundle.

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
import re
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentforge.agents.hosted import (
    HOSTED_MAX_PHYSICAL_CALLS,
    HostedConfigurationSet,
)
from agentforge.agents.hosted_runtime import (
    HostedCallBounds,
    HostedExecutionLineage,
    HostedRoleRuntime,
    hosted_judge_identity,
)
from agentforge.agents.judge import (
    CalibrationInputError,
    HostedEvaluator,
    HostedEvaluatorError,
)
from agentforge.correlation import campaign_trace_id
from agentforge.evals.validation import validate_ground_truth_slice
from agentforge.providers import HostedUsageLedger, OpenRouterTransport
from agentforge.providers.lineage import (
    ProviderInvocationContextV1,
    ProviderLogicalContextV1,
    ProviderTerminalEventV1,
)
from agentforge.secrets import Secret
from agentforge.target.spec import HostedRunBinding
from agentforge.telemetry.outbound import (
    _LangfuseBridge,
    _observation_field,
    _observation_metadata,
)

_ROOT = Path(__file__).resolve().parents[1]
_GROUND_TRUTH = _ROOT / "evals" / "ground-truth"

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")

# A run label for the authorization binding. It is NOT identity-bearing: the staged role
# configuration (and therefore judge_model_version) is unaffected by it.
_DEFAULT_SESSION_GENERATION = "generation-1"

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
        "--hosted-configuration-set",
        type=Path,
        required=True,
        help=(
            "staged production four-role hosted configuration set, as deployed "
            "(HostedConfigurationSet.from_payload shape). The Judge identity being calibrated is "
            "derived from this file and is never synthesized"
        ),
    )
    parser.add_argument(
        "--expected-configuration-sha256",
        required=True,
        help=(
            "the configuration_sha256 the deploying operator attested for the staged set; the "
            "capture aborts if the supplied file does not hash to exactly this value"
        ),
    )
    parser.add_argument(
        "--session-generation",
        default=_DEFAULT_SESSION_GENERATION,
        help=(
            "run label recorded in the authorization binding (not identity-bearing; default "
            f"{_DEFAULT_SESSION_GENERATION})"
        ),
    )
    parser.add_argument(
        "--confirm-provider-spend",
        action="store_true",
        help="required acknowledgement that this makes real, billed OpenRouter calls",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help=(
            "labels per sub-run. Defaults to the staged Judge role's max_calls (bounded by the "
            f"{HOSTED_MAX_PHYSICAL_CALLS}-call platform ceiling). A corpus larger than one batch "
            "is captured as several sub-runs against the SAME staged configuration, which keeps "
            "judge_model_version constant — raising the cap instead would change the identity"
        ),
    )
    parser.add_argument(
        "--batch-index",
        type=int,
        default=0,
        help="0-based index of the sub-run to capture (default 0)",
    )
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="print the batch plan and the derived identity, then exit without calling a provider",
    )
    parser.add_argument(
        "--require-langfuse-query-back",
        action="store_true",
        help=(
            "project every calibration generation to Langfuse and refuse unless exact remote "
            "query-back observes every provider request id"
        ),
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    configuration = _staged_configuration(
        args.hosted_configuration_set,
        expected_sha256=args.expected_configuration_sha256,
    )
    judge_role = next(role for role in configuration.roles if role.role == "judge")

    slices = _load_slices(args.slice_dir)
    labels = [(item["category"], label) for item in slices for label in item["labels"]]
    labels.sort(key=lambda pair: pair[1]["label_id"])
    if not labels:
        raise SystemExit("refusing to run: the ground-truth corpus has no labels")

    plan = _batch_plan(
        labels,
        configuration=configuration,
        judge_role=judge_role,
        batch_size=args.batch_size,
    )
    identity = hosted_judge_identity(configuration)
    generation_policy_sha256 = _generation_policy_sha256(
        configuration,
        total_sample_count=plan["total_sample_count"],
        batch_size=plan["batch_size"],
    )
    if args.plan_only:
        _print_plan(plan, identity=identity, generation_policy_sha256=generation_policy_sha256)
        return 0

    if not 0 <= args.batch_index < plan["batch_count"]:
        raise SystemExit(
            f"refusing to run: --batch-index {args.batch_index} is outside the "
            f"{plan['batch_count']}-batch plan for this corpus"
        )
    batch = plan["batches"][args.batch_index]
    labels = batch["labels"]

    if not args.confirm_provider_spend:
        raise SystemExit(
            "refusing to run: --confirm-provider-spend is required because this issues real, "
            "billed OpenRouter requests"
        )
    credential = os.environ.get("OPENROUTER_API_KEY", "")
    if not credential:
        raise SystemExit("refusing to run: OPENROUTER_API_KEY is not set")
    langfuse = (
        _LangfuseCaptureVerifier(
            capture_run_id=args.capture_run_id,
            judge_identity=identity.payload(),
            judge_model_version=judge_role.configuration_sha256,
        )
        if args.require_langfuse_query_back
        else None
    )
    print(
        f"batch {args.batch_index + 1}/{plan['batch_count']}: "
        f"{len(labels)} labels ({batch['first_label_id']} … {batch['last_label_id']})",
        flush=True,
    )
    authorization = HostedRunBinding(
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=generation_policy_sha256,
        session_generation=args.session_generation,
        provider_model_call_limit=configuration.global_limits.max_calls,
        provider_model_spend_limit_usd=format(configuration.global_limits.max_usd, "f"),
        provider_max_retries=configuration.global_limits.max_retries,
        provider_max_concurrency=configuration.global_limits.max_concurrency,
        provider_timeout_seconds=_JUDGE_CALL_BOUNDS.timeout_seconds,
    )

    lifecycle = _InMemoryExecutionLifecycle(capture_run_id=args.capture_run_id)
    ledger = HostedUsageLedger(configuration)
    transport = OpenRouterTransport(
        configuration=configuration,
        credential_resolver=lambda reference: _resolve(reference, configuration, credential),
        ledger=ledger,
        lineage_recorder=lifecycle,
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
            try:
                result = evaluator.evaluate(
                    label["evidence_envelope"],
                    integrity_ok=True,
                    sanitized=True,
                )
            except HostedEvaluatorError:
                execution_id = f"judge-calibration-execution-{index}"
                lineage = lifecycle.failed_lineage(execution_id)
                if lineage is None:
                    raise
                assessment = {
                    "state": "ERROR",
                    "confidence": 0.0,
                    "rationale": (
                        "Provider response failed the trusted Judge assessment validator."
                    ),
                    "criteria_hits": [],
                    "error_code": "invalid_structured_output",
                }
            else:
                lineage = result.lineage
                assessment = dict(result.assessment)
            returned_models.add(lineage.returned_model)
            samples.append(
                {
                    "label_id": label_id,
                    "assessment": assessment,
                    "provider_request_id": lineage.provider_request_id,
                    "trace_id": campaign_trace_id(f"{args.capture_run_id}:{label_id}"),
                    "returned_model": lineage.returned_model,
                    "input_tokens": lineage.input_tokens,
                    "output_tokens": lineage.output_tokens,
                    "reasoning_tokens": lineage.reasoning_tokens,
                    "measured_cost_usd": lineage.measured_cost_usd,
                }
            )
            if langfuse is not None:
                langfuse.record(samples[-1])
    finally:
        transport.close()

    langfuse_attestation = (
        None if langfuse is None else langfuse.verify(samples)
    )
    if len(returned_models) != 1:
        raise CaptureError("provider returned more than one model identity across the capture")
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
    if langfuse_attestation is not None:
        _write_json(args.output_dir / "langfuse-attestation.json", langfuse_attestation)
    _write_json(
        args.output_dir / "capture-manifest.json",
        {
            "capture_run_id": args.capture_run_id,
            "sample_count": len(samples),
            "slice_ids": sorted(item["slice_id"] for item in slices),
            "batch": {
                "batch_index": args.batch_index,
                "batch_count": plan["batch_count"],
                "batch_size": plan["batch_size"],
                "total_sample_count": plan["total_sample_count"],
                "label_ids": batch["label_ids"],
                "note": (
                    "One sub-run of a batched campaign. Every batch runs against the SAME staged "
                    "configuration, so judge_model_version is identical across batches and the "
                    "bundles can be merged by scripts/merge_calibration_batches.py."
                ),
            },
            "identity_binding": {
                "source": "staged_production_configuration_set",
                "hosted_configuration_set_path": str(args.hosted_configuration_set),
                "attested_configuration_sha256": args.expected_configuration_sha256,
                "observed_configuration_sha256": configuration.configuration_sha256,
                "judge_role_configuration_sha256": judge_role.configuration_sha256,
                "judge_prompt_sha256": judge_role.prompt_sha256,
                "judge_policy_sha256": judge_role.policy_sha256,
                "judge_limits": judge_role.limits.canonical_payload(),
                "note": (
                    "judge_model_version == judge_role_configuration_sha256, which hashes model, "
                    "prompt, policy, prices, credential reference, and limits together. The "
                    "configuration was supplied by the deployment, not synthesized here."
                ),
            },
            "evidence_provenance": {
                "kind": "authored_synthetic_ground_truth",
                "target_executed": False,
                "note": (
                    "The Judge model calls are real and billed, but the evidence they judge is "
                    "authored offline for calibration; the ground-truth envelopes carry "
                    "campaign_run_id 'ground-truth-unexecuted' and no live target was contacted. "
                    "This measures the evaluator, not the target."
                ),
            },
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
                "platform's W3C-compatible correlation id for provider lineage. When query-back "
                "is required, a separate batch trace in langfuse-attestation.json carries the "
                "sanitized calibration projection."
            ),
            "langfuse_query_back": (
                None
                if langfuse_attestation is None
                else {
                    "trace_id": langfuse_attestation["trace_id"],
                    "matched_generation_count": langfuse_attestation[
                        "matched_generation_count"
                    ],
                    "verified_at": langfuse_attestation["verified_at"],
                }
            ),
        },
    )
    print(
        f"captured {len(samples)} assessments; measured spend "
        f"${format(ledger.snapshot.measured_usd, 'f')}",
        flush=True,
    )
    return 0


class _LangfuseCaptureVerifier:
    """Sanitized projection plus exact remote query-back for calibration generations."""

    _OBSERVATION_NAME = "agent.judge.runtime"

    def __init__(
        self,
        *,
        capture_run_id: str,
        judge_identity: Mapping[str, str],
        judge_model_version: str,
        bridge: _LangfuseBridge | None = None,
    ) -> None:
        self.capture_run_id = capture_run_id
        self.judge_identity = dict(judge_identity)
        self.judge_model_version = judge_model_version
        self.trace_id = campaign_trace_id(f"judge-calibration:{capture_run_id}")
        self.bridge = bridge or _LangfuseBridge()
        if not self.bridge.configured():
            raise CaptureError("Langfuse query-back was required but credentials are unavailable")
        if self.bridge.auth_check() is not True:
            raise CaptureError("Langfuse query-back was required but authentication failed")

    def record(self, sample: Mapping[str, Any]) -> None:
        provider_request_id = str(sample["provider_request_id"])
        label_digest = hashlib.sha256(str(sample["label_id"]).encode("utf-8")).hexdigest()
        state = self.bridge.start_agent(
            trace_id=self.trace_id,
            role="judge",
            provider="openrouter",
            model=str(sample["returned_model"]),
            execution_mode="calibration",
            version=self.judge_model_version,
            input_payload={"label_sha256": label_digest},
            metadata={
                "calibration.capture_run_id": self.capture_run_id,
                "calibration.label_sha256": label_digest,
                "calibration.provider_request_id": provider_request_id,
            },
        )
        if state is None:
            raise CaptureError("Langfuse calibration observation did not open")
        self.bridge.finish_agent(
            state,
            output={"state": sample["assessment"]["state"]},
            metadata={
                "calibration.capture_run_id": self.capture_run_id,
                "calibration.label_sha256": label_digest,
                "calibration.provider_request_id": provider_request_id,
            },
            error_code=None,
            status="succeeded",
            input_tokens=int(sample["input_tokens"]),
            output_tokens=int(sample["output_tokens"]),
            reasoning_tokens=int(sample["reasoning_tokens"]),
            measured_cost=float(str(sample["measured_cost_usd"])),
            cost_measurement_state="measured",
            provider_event_ids=[],
            returned_model=str(sample["returned_model"]),
        )

    def verify(self, samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        expected = {str(sample["provider_request_id"]) for sample in samples}
        observed: set[str] = set()
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            self.bridge.flush()
            observed = self._observed_provider_request_ids()
            if observed == expected:
                break
            time.sleep(1.0)
        if observed != expected:
            missing = len(expected - observed)
            extra = len(observed - expected)
            raise CaptureError(
                "Langfuse query-back did not reconcile the exact calibration generation set "
                f"(missing={missing}, extra={extra})"
            )
        request_id_digest = hashlib.sha256(
            "\n".join(sorted(expected)).encode("utf-8")
        ).hexdigest()
        return {
            "schema_version": "1",
            "attestation_kind": "langfuse_query_back_verified",
            "capture_run_id": self.capture_run_id,
            "trace_id": self.trace_id,
            "observation_name": self._OBSERVATION_NAME,
            "judge_identity": self.judge_identity,
            "matched_generation_count": len(observed),
            "provider_request_ids_sha256": request_id_digest,
            "verified_at": datetime.now(UTC).isoformat(),
            "disclosure": (
                "Every calibration generation was remotely queryable in Langfuse with its exact "
                "provider request id. This verifies the tracing projection, not an independent "
                "OpenRouter usage export."
            ),
        }

    def _observed_provider_request_ids(self) -> set[str]:
        client = self.bridge._client()
        observations = getattr(getattr(client, "api", None), "observations", None)
        query = None
        for name in ("get_many", "get", "list"):
            candidate = getattr(observations, name, None)
            if callable(candidate):
                query = candidate
                break
        if query is None:
            raise CaptureError("Langfuse observation query API is unavailable")

        found: set[str] = set()
        cursor: str | None = None
        seen: set[str] = set()
        for _page in range(100):
            parameters: dict[str, Any] = {
                "trace_id": self.trace_id,
                "limit": 1000,
                "fields": "core,basic,io,metadata",
            }
            if cursor is not None:
                parameters["cursor"] = cursor
            response = query(**parameters)
            data = _observation_field(response, "data")
            if not isinstance(data, (list, tuple)):
                raise CaptureError("Langfuse observation query returned no data list")
            for observation in data:
                if _observation_field(observation, "name") != self._OBSERVATION_NAME:
                    continue
                if _observation_field(observation, "end_time", "endTime") is None:
                    continue
                metadata = _observation_metadata(observation)
                request_id = metadata.get("calibration.provider_request_id")
                if isinstance(request_id, str) and request_id:
                    found.add(request_id)
            meta = _observation_field(response, "meta")
            next_cursor = _observation_field(meta, "cursor", "next", "after")
            if next_cursor is None:
                page = _observation_field(meta, "page")
                if isinstance(page, Mapping):
                    next_cursor = page.get("cursor")
            if next_cursor is None:
                return found
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen:
                raise CaptureError("Langfuse observation pagination is invalid")
            seen.add(next_cursor)
            cursor = next_cursor
        raise CaptureError("Langfuse observation pagination exceeded its bound")


def _resolve(
    reference: str,
    configuration: HostedConfigurationSet,
    credential: str,
) -> Secret:
    """Hand the OpenRouter key to the Judge role only; every other role stays uncallable.

    The staged ``credential_reference`` is matched exactly, so the capture cannot quietly call a
    role the deployment did not bind. Only the reference string is identity-bearing; the secret
    value comes from the local environment and never reaches the emitted bundle.
    """

    judge = next(role for role in configuration.roles if role.role == "judge")
    if reference != judge.credential_reference:
        raise CaptureError("only the Judge role is authorized in a calibration capture")
    return Secret(credential)


def _staged_configuration(path: Path, *, expected_sha256: str) -> HostedConfigurationSet:
    """Load the deployed four-role set and pin it to the operator-attested hash.

    Reconstruction is itself a check: ``HostedRoleConfiguration`` rejects a staged
    ``prompt_sha256`` that does not match this release's server-owned role prompt, and
    ``HostedConfigurationSet`` re-validates four-role completeness and Judge/Red-Team
    independence. Nothing here is defaulted or repaired — a staged set that does not load is a
    refusal, not a fallback.
    """

    if _HEX64.fullmatch(expected_sha256 or "") is None:
        raise SystemExit(
            "refusing to run: --expected-configuration-sha256 must be a 64-character "
            "lowercase hex digest"
        )
    try:
        with path.open("rb") as handle:
            encoded = handle.read(4 * 1024 * 1024 + 1)
    except OSError as exc:
        raise SystemExit(
            f"refusing to run: staged hosted configuration set is unreadable ({exc})"
        ) from exc
    if len(encoded) > 4 * 1024 * 1024:
        raise SystemExit("refusing to run: staged hosted configuration set exceeds its size bound")
    try:
        payload = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SystemExit(
            "refusing to run: staged hosted configuration set is not valid JSON"
        ) from exc
    try:
        configuration = HostedConfigurationSet.from_payload(payload)
    except (TypeError, ValueError) as exc:
        raise SystemExit(
            f"refusing to run: staged hosted configuration set is invalid for this release ({exc})"
        ) from exc
    if configuration.configuration_sha256 != expected_sha256:
        raise SystemExit(
            "refusing to run: staged configuration drifted from the attested identity — "
            f"attested {expected_sha256}, loaded {configuration.configuration_sha256}. "
            "Calibrating a configuration the deployment did not attest would bind the result "
            "to an evaluator production never runs."
        )
    return configuration


def _batch_plan(
    labels: Sequence[tuple[str, Mapping[str, Any]]],
    *,
    configuration: HostedConfigurationSet,
    judge_role: Any,
    batch_size: int | None,
) -> dict[str, Any]:
    """Split the corpus into sub-runs that each fit the staged envelope, unchanged.

    ``HostedLimits.max_calls`` is capped platform-wide at ``HOSTED_MAX_PHYSICAL_CALLS`` (56) and
    one label costs one physical call, so a larger corpus cannot be captured in a single run under
    ANY valid configuration.  The answer is several sub-runs against the SAME staged configuration
    — not a wider cap.  Widening it would change ``limits``, which sits inside the Judge role's
    ``configuration_sha256`` and therefore inside ``judge_model_version``: the batches would attest
    different identities and could not be aggregated at all.

    Batches are cut from the label list sorted by ``label_id``, so the plan is deterministic and
    every sub-run is reproducible from its index alone.
    """

    ceiling = min(judge_role.limits.max_calls, configuration.global_limits.max_calls)
    resolved = ceiling if batch_size is None else batch_size
    if resolved < 1:
        raise SystemExit("refusing to run: --batch-size must be at least 1")
    if resolved > ceiling:
        raise SystemExit(
            f"refusing to run: --batch-size {resolved} exceeds the staged envelope "
            f"({ceiling} physical calls; platform ceiling {HOSTED_MAX_PHYSICAL_CALLS}). Reduce "
            "the batch size — do NOT raise the staged limits, which would change "
            "judge_model_version and make the batches un-aggregatable."
        )

    batches = []
    for index in range(0, len(labels), resolved):
        window = list(labels[index : index + resolved])
        batches.append(
            {
                "batch_index": len(batches),
                "labels": window,
                "label_ids": [label["label_id"] for _category, label in window],
                "first_label_id": window[0][1]["label_id"],
                "last_label_id": window[-1][1]["label_id"],
            }
        )
    return {
        "total_sample_count": len(labels),
        "batch_size": resolved,
        "batch_count": len(batches),
        "batches": batches,
    }


def _print_plan(
    plan: Mapping[str, Any],
    *,
    identity: Any,
    generation_policy_sha256: str,
) -> None:
    payload = identity.payload()
    print(f"corpus            {plan['total_sample_count']} labels")
    print(f"batch size        {plan['batch_size']} (one physical Judge call per label)")
    print(f"batches           {plan['batch_count']}")
    print(f"identity_sha256   {_identity_sha256(payload)}")
    print(f"judge_model       {payload['judge_model']} via {payload['judge_provider']}")
    print(f"judge_model_ver   {payload['judge_model_version']}  (constant across every batch)")
    print(f"generation_policy {generation_policy_sha256}  (bound to the campaign, not the batch)")
    for batch in plan["batches"]:
        print(
            f"  batch {batch['batch_index']}: {len(batch['labels']):>3} labels  "
            f"{batch['first_label_id']} … {batch['last_label_id']}"
        )


def _identity_sha256(payload: Mapping[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _generation_policy_sha256(
    configuration: HostedConfigurationSet,
    *,
    total_sample_count: int,
    batch_size: int,
) -> str:
    """Content-address the generation envelope for the whole CAMPAIGN, not one sub-run.

    It binds the corpus size and the batch size rather than the per-batch sample count, so every
    sub-run of one campaign carries the identical value and the merged bundle has a single
    coherent ``generation_policy_sha256``. A per-batch count would make the trailing short batch
    disagree with the others for no reason that means anything.
    """

    return hashlib.sha256(
        json.dumps(
            {
                "purpose": "judge-calibration-capture",
                "configuration_sha256": configuration.configuration_sha256,
                "total_sample_count": total_sample_count,
                "batch_size": batch_size,
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

    A calibration capture is not a campaign: there is no run row, no attempt, and no control-plane
    database to write to. The lifecycle and physical-call lineage seams are still exercised in
    memory (reservation before send, terminal event after send), and their tallies are written into
    the run manifest. This keeps the target-free harness aligned with the production transport
    contract without fabricating campaign persistence.
    """

    def __init__(self, *, capture_run_id: str) -> None:
        self._campaign_run_id = hashlib.sha256(
            f"judge-calibration:{capture_run_id}".encode()
        ).hexdigest()
        self._starts: list[dict[str, Any]] = []
        self._finishes: list[dict[str, Any]] = []
        self._invocations: dict[str, ProviderInvocationContextV1] = {}
        self._events: dict[str, ProviderTerminalEventV1] = {}

    def start(self, **kwargs: Any) -> str:
        self._starts.append(dict(kwargs))
        return f"judge-calibration-execution-{len(self._starts)}"

    def provider_context(
        self,
        *,
        execution_id: str,
        prompt_version: str,
        prompt_sha256: str,
    ) -> ProviderLogicalContextV1:
        try:
            started = next(
                item
                for index, item in enumerate(self._starts, start=1)
                if execution_id == f"judge-calibration-execution-{index}"
            )
        except StopIteration as exc:
            raise CaptureError("calibration execution context is unavailable") from exc
        return ProviderLogicalContextV1(
            organization_id="org-headshot-calibration",
            campaign_run_id=self._campaign_run_id,
            campaign_attempt_id=None,
            logical_execution_id=execution_id,
            parent_execution_id=started["parent_execution_id"],
            agent_role=started["role"],
            requested_model=started["model"],
            configured_upstream=started["upstream_provider"],
            prompt_version=prompt_version,
            prompt_sha256=prompt_sha256,
            configuration_set_sha256=started["configuration_sha256"],
            role_configuration_sha256=started["role_configuration_sha256"],
            generation_policy_sha256=started["generation_policy_sha256"],
        )

    def begin_physical_attempt(
        self,
        logical_context: ProviderLogicalContextV1,
        sequence: int,
    ) -> ProviderInvocationContextV1:
        invocation_id = hashlib.sha256(
            (
                f"{logical_context.organization_id}:{logical_context.campaign_run_id}:"
                f"{logical_context.logical_execution_id}:{sequence}"
            ).encode()
        ).hexdigest()
        if invocation_id in self._invocations:
            raise CaptureError("duplicate calibration provider-call reservation")
        invocation = ProviderInvocationContextV1(
            invocation_id=invocation_id,
            organization_id=logical_context.organization_id,
            campaign_run_id=logical_context.campaign_run_id,
            campaign_attempt_id=logical_context.campaign_attempt_id,
            logical_execution_id=logical_context.logical_execution_id,
            parent_execution_id=logical_context.parent_execution_id,
            agent_role=logical_context.agent_role,
            physical_sequence=sequence,
            idempotency_key=f"provider-call:{invocation_id}",
            requested_model=logical_context.requested_model,
            configured_upstream=logical_context.configured_upstream,
            prompt_version=logical_context.prompt_version,
            prompt_sha256=logical_context.prompt_sha256,
            configuration_set_sha256=logical_context.configuration_set_sha256,
            role_configuration_sha256=logical_context.role_configuration_sha256,
            generation_policy_sha256=logical_context.generation_policy_sha256,
            started_at=datetime.now(UTC),
        )
        self._invocations[invocation_id] = invocation
        return invocation

    def finish_physical_attempt(
        self,
        invocation: ProviderInvocationContextV1,
        event: ProviderTerminalEventV1,
    ) -> ProviderTerminalEventV1:
        reserved = self._invocations.get(invocation.invocation_id)
        if reserved != invocation:
            raise CaptureError("calibration provider-call reservation is unavailable")
        if event.invocation_id != invocation.invocation_id:
            raise CaptureError("calibration provider-call terminal identity differs")
        if event.physical_sequence != invocation.physical_sequence:
            raise CaptureError("calibration provider-call terminal sequence differs")
        if event.invocation_id in self._events:
            raise CaptureError("duplicate calibration provider-call terminal event")
        self._events[event.invocation_id] = event
        return event

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
                "lineage": lineage,
            }
        )

    def failed_lineage(self, execution_id: str) -> HostedExecutionLineage | None:
        for item in reversed(self._finishes):
            if item["execution_id"] == execution_id and item["status"] == "failed":
                lineage = item["lineage"]
                return lineage if isinstance(lineage, HostedExecutionLineage) else None
        return None

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
            "provider_calls_reserved": len(self._invocations),
            "provider_calls_terminal": len(self._events),
            "provider_calls_open": len(set(self._invocations) - set(self._events)),
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
