"""Component-ready traced Red Team generation pending governed production composition.

The future two-stage loop's GENERATION is the Red Team's LLM work. This provider can make a hosted
generation/mutation call a traced qwen invocation with the same lineage contract as the other
roles, but it is not production-live until its quarantine, human review, and fresh-authorization
composition root exists:

* it routes through the SAME :class:`~agentforge.providers.openrouter.OpenRouterTransport` as the
  other roles (``role='red_team'``), so the shared :class:`HostedUsageLedger` enforces the Red Team
  per-role cost subcap + call/token caps within the global kill switch — no separate SDK client;
* it emits through the SAME execution lifecycle seam the four-role runtime uses
  (``start`` -> ``invoke`` -> :class:`HostedExecutionLineage` -> ``finish``), so the generation
  lands in ``agent_executions`` with the identical shape: ``agent_role='red_team'``,
  ``returned_model``, ``trace_id`` (via the recorder), tokens, ``measured_cost``,
  ``parent_execution_id``, ``provider_request_id`` — surfaced by ``AgentActivityReadModel``.

Governance is unchanged: the Red Team is the UNTRUSTED generator. It produces PROPOSED input only
(``input_sequence`` continuations) — never a credential, ``content_hash``, or verdict — and never
holds a target credential or a second network exit. The provider credential (the model-provider
key) is resolved only inside the transport via the sealed reference. Candidates still flow
review -> authorization -> dispatch through the Policy Gateway.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Protocol

from agentforge.agents.hosted_runtime import HostedCallBounds, HostedExecutionLineage
from agentforge.agents.prompts import PromptRegistryError, prompt_for_identity
from agentforge.agents.red_team.providers import _collect_usable
from agentforge.providers.lineage import ProviderLogicalContextV1

_GENERATION_SCHEMA_NAME = "red_team_variants"
_MAX_VARIANTS = 16

# The store accepts only a lowercase typed reason. Normalizing before the FIRST write matters:
# an exception carrying anything else would be refused on both the write and its one retry,
# spending the fallback on a record that could never have been accepted either.
_TYPED_REASON = re.compile(r"\A[a-z][a-z0-9_-]{0,63}\Z")
_GENERATION_FAILED = "red-team-generation-failed"
# A successful generation whose terminal record the store refused. The generation happened; only
# its output could not be persisted, and the two must not be reported as the same failure.
_TERMINAL_RECORD_REFUSED = "red-team-terminal-record-refused"


def _typed_reason(code: Any) -> str:
    """Normalize an exception's code to the shape the store will accept."""

    if isinstance(code, str) and _TYPED_REASON.fullmatch(code) is not None:
        return code
    return _GENERATION_FAILED


# The Red Team per-role measured-spend subcap ceiling. The shared HostedUsageLedger enforces the
# configured red_team ``limits.max_usd`` on every call; this ceiling is the policy bound the
# composition root asserts the configuration honors before a live run.
RED_TEAM_SUBCAP_CEILING_USD = Decimal("1")


class _Invoker(Protocol):
    def invoke(self, **kwargs: Any) -> Any: ...


class _Lifecycle(Protocol):
    def start(self, **kwargs: Any) -> str: ...
    def finish(self, **kwargs: Any) -> None: ...
    def provider_context(self, **kwargs: Any) -> ProviderLogicalContextV1: ...


class TracedRedTeamGenerationError(RuntimeError):
    """The traced hosted generation could not preserve its execution lineage."""

    code = "red-team-generation-failed"


@dataclass(frozen=True, slots=True)
class RedTeamRoleIdentity:
    """The stable role-configuration fields the execution lifecycle records for the Red Team."""

    provider: str
    model: str
    upstream_provider: str
    prompt_version: str
    prompt_sha256: str
    role_configuration_sha256: str


@dataclass(frozen=True, slots=True)
class RedTeamGenerationResult:
    """One traced generation's variants + the measured cost/token/model/trace the recorder needs.

    Returned by :meth:`TracedHostedRedTeamProvider.generate_traced` so a composition root that owns
    its own ``start/finish_agent_execution`` (the runner) can record the Red Team execution with the
    same measured ``measured_cost`` / ``input_tokens`` / ``output_tokens`` and ``returned_model`` /
    ``provider_request_id`` fields the other three roles carry.
    """

    variants: list[dict[str, Any]]
    returned_model: str
    provider_request_id: str
    upstream_provider: str
    input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    measured_cost_usd: str
    physical_attempts: int


def require_red_team_subcap(
    configuration: Any,
    *,
    ceiling_usd: Decimal = RED_TEAM_SUBCAP_CEILING_USD,
    effective_subcap_usd: Decimal | None = None,
) -> Decimal:
    """Assert the effective Red Team measured-spend subcap is authorized and below the ceiling.

    By default the effective subcap is the configuration's Red Team ``limits.max_usd``. A runtime
    using a narrower, configuration-contained :class:`HostedUsageEnvelope` may pass that ledger's
    effective cap explicitly. The explicit value must still be positive, no larger than the
    reviewed configuration, and no larger than the absolute policy ceiling (default $1).
    """
    try:
        role = next(item for item in configuration.roles if item.role == "red_team")
        # Coerce through str so a float-typed cap cannot smuggle binary representation drift into a
        # $-denominated cost control (Decimal(0.10) != 0.10); the cap stays exactly what was set.
        configured_subcap = Decimal(str(role.limits.max_usd))
        subcap = (
            configured_subcap
            if effective_subcap_usd is None
            else Decimal(str(effective_subcap_usd))
        )
    except (StopIteration, AttributeError, ArithmeticError, TypeError, ValueError) as exc:
        raise TracedRedTeamGenerationError("red_team role subcap is unavailable") from exc
    if subcap <= 0:
        raise TracedRedTeamGenerationError(
            f"red_team measured-spend subcap {subcap} must be a positive amount"
        )
    if subcap > configured_subcap:
        raise TracedRedTeamGenerationError(
            "red_team measured-spend subcap exceeds the reviewed configuration"
        )
    if subcap > ceiling_usd:
        raise TracedRedTeamGenerationError(
            f"red_team measured-spend subcap {subcap} exceeds the authorized ceiling {ceiling_usd}"
        )
    return subcap


def variants_output_schema(count: int) -> dict[str, Any]:
    """Strict structured-output schema pinning EXACTLY ``count`` string variants."""
    if not isinstance(count, int) or isinstance(count, bool) or count < 1 or count > _MAX_VARIANTS:
        raise TracedRedTeamGenerationError("variant count is out of bounds")
    return {
        "type": "object",
        "properties": {
            "variants": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
                "minItems": count,
                "maxItems": count,
            }
        },
        "required": ["variants"],
        "additionalProperties": False,
    }


def build_generation_messages(
    seed: Mapping[str, Any],
    count: int,
    category: str,
    *,
    prompt_version: str,
    prompt_sha256: str,
) -> tuple[dict[str, str], ...]:
    """Exact authority prompt + user JSON requesting distinct adversarial continuations.

    The generated text is the NEXT attacker turn only; the seed's own turns are provided as context
    so a multi-turn attack stays first-class. The system message is byte-for-byte package-owned
    T-F17a authority; caller-controlled seed, category, and count exist only in the user message.
    """
    try:
        prompt = prompt_for_identity("red_team", prompt_version, prompt_sha256)
    except PromptRegistryError:
        raise TracedRedTeamGenerationError(
            "red_team prompt identity does not match the immutable prompt authority"
        ) from None
    seed_turns = [turn for turn in seed.get("input_sequence", []) if isinstance(turn, str)]
    user = {
        "category": category,
        "count": count,
        "output_contract": {
            "field": "variants",
            "item_kind": "proposed_next_attacker_turn",
            "required_distinct_items": count,
        },
        "seed_case_ref": seed.get("case_ref"),
        "seed_turns": seed_turns,
    }
    return (
        {"role": "system", "content": prompt.content},
        {
            "role": "user",
            "content": json.dumps(
                user, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ),
        },
    )


class TracedHostedRedTeamProvider:
    """A component whose generation is a traced, cost-capped, lineage-emitting qwen call.

    It is ready for the governed two-stage composition; it is not the authorized case-selection
    implementation used by the current production Runner.
    """

    def __init__(
        self,
        *,
        transport: _Invoker,
        lifecycle: _Lifecycle,
        role_identity: RedTeamRoleIdentity,
        configuration_sha256: str,
        generation_policy_sha256: str,
        call_bounds: HostedCallBounds,
        parent_execution_id: str | None = None,
        parent_request_id: str | None = None,
    ) -> None:
        if not callable(getattr(transport, "invoke", None)):
            raise TracedRedTeamGenerationError("hosted transport is unavailable")
        if (
            not callable(getattr(lifecycle, "start", None))
            or not callable(getattr(lifecycle, "finish", None))
            or not callable(getattr(lifecycle, "provider_context", None))
        ):
            raise TracedRedTeamGenerationError("execution lifecycle is unavailable")
        try:
            prompt_for_identity(
                "red_team",
                role_identity.prompt_version,
                role_identity.prompt_sha256,
            )
        except (AttributeError, PromptRegistryError):
            raise TracedRedTeamGenerationError(
                "red_team prompt identity does not match the immutable prompt authority"
            ) from None
        self._transport = transport
        self._lifecycle = lifecycle
        self._role = role_identity
        self._configuration_sha256 = configuration_sha256
        self._generation_policy_sha256 = generation_policy_sha256
        self._call_bounds = call_bounds
        self._parent_execution_id = parent_execution_id
        # The parent's provider request id (e.g. the orchestrator's), threaded into the lineage
        # exactly as the four-role runtime does (hosted_runtime.py:345) so the four-agent request
        # chain is uniform — never silently dropped to None.
        self._parent_request_id = parent_request_id

    def _invoke_transport(
        self,
        seed: dict[str, Any],
        count: int,
        category: str,
        *,
        execution_id: str | None,
    ) -> Any:
        """Invoke qwen with the durable logical identity required by the physical recorder."""

        if not isinstance(execution_id, str) or not execution_id:
            raise TracedRedTeamGenerationError(
                "red_team provider lineage requires its logical execution identity"
            )
        try:
            prompt = prompt_for_identity(
                "red_team",
                self._role.prompt_version,
                self._role.prompt_sha256,
            )
        except PromptRegistryError:
            raise TracedRedTeamGenerationError(
                "red_team prompt identity does not match the immutable prompt authority"
            ) from None
        provider_context = self._lifecycle.provider_context(
            execution_id=execution_id,
            prompt_version=prompt.version,
            prompt_sha256=prompt.sha256,
        )
        if not isinstance(provider_context, ProviderLogicalContextV1):
            raise TracedRedTeamGenerationError("red_team provider lineage context is invalid")
        return self._transport.invoke(
            role="red_team",
            messages=build_generation_messages(
                seed,
                count,
                category,
                prompt_version=self._role.prompt_version,
                prompt_sha256=self._role.prompt_sha256,
            ),
            output_schema=variants_output_schema(count),
            schema_name=_GENERATION_SCHEMA_NAME,
            generation_policy_sha256=self._generation_policy_sha256,
            input_tokens_upper_bound=self._call_bounds.input_tokens,
            max_output_tokens=self._call_bounds.output_tokens,
            max_reasoning_tokens=self._call_bounds.reasoning_tokens,
            timeout_seconds=self._call_bounds.timeout_seconds,
            provider_context=provider_context,
        )

    def generate_traced(
        self,
        seed: dict[str, Any],
        *,
        count: int,
        category: str,
        execution_id: str | None = None,
    ) -> RedTeamGenerationResult:
        """Run the traced qwen generation and return variants + measured cost/token/trace metadata.

        The caller owns recording (used by a composition root that already starts/finishes the
        red_team agent execution). The shared ledger still enforces the red_team subcap here.
        """
        result = self._invoke_transport(
            seed,
            count,
            category,
            execution_id=execution_id,
        )
        variants = _collect_usable(seed, list(result.output.get("variants", [])), count)
        return RedTeamGenerationResult(
            variants=variants,
            returned_model=result.returned_model,
            provider_request_id=result.request_id,
            upstream_provider=result.upstream_provider,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            reasoning_tokens=result.reasoning_tokens,
            measured_cost_usd=format(result.measured_cost_usd, "f"),
            physical_attempts=result.physical_attempts,
        )

    def _observed_lineage(self, execution_id: str, result: Any) -> HostedExecutionLineage | None:
        """Preserve the exact charged usage of a call that happened, without trusting its output.

        Structural rather than isinstance-checked, because this module deliberately reaches the
        transport through a Protocol. Anything that will not assemble yields ``None`` so the
        caller degrades to a smaller record instead of writing a guess — and, unlike the previous
        inline construction, a provider-controlled value that cannot be formatted can no longer
        raise on the success path with the execution already open and nothing closing it.
        """

        if result is None:
            return None
        try:
            measured_cost_usd = result.measured_cost_usd
            return HostedExecutionLineage(
                execution_id=execution_id,
                parent_execution_id=self._parent_execution_id,
                role="red_team",
                parent_request_id=self._parent_request_id,
                requested_model=result.requested_model,
                returned_model=result.returned_model,
                upstream_provider=result.upstream_provider,
                provider_request_id=result.request_id,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                reasoning_tokens=result.reasoning_tokens,
                # The amount is separable from the identity and usage. An unusable cost must not
                # take the rest of the evidence down with it; the store records that case as
                # cost_measurement_state='invalid' with a NULL value.
                measured_cost_usd=(
                    format(measured_cost_usd, "f") if measured_cost_usd is not None else None
                ),
                configuration_sha256=result.configuration_sha256,
                role_configuration_sha256=result.role_configuration_sha256,
                generation_policy_sha256=result.generation_policy_sha256,
                physical_attempts=result.physical_attempts,
            )
        except (AttributeError, TypeError, ValueError):
            return None

    def _terminalize_failure(
        self,
        *,
        execution_id: str,
        error_code: str,
        lineage: HostedExecutionLineage | None,
        physical_attempts: int | None,
    ) -> None:
        """Close the execution, surrendering the observation before surrendering the record.

        Mirrors ``HostedRoleRuntime._record_failure``. The store can refuse the observation itself
        — a token count beyond the column, an output that trips credential screening, a payload
        over the size bound. Leaving the row ``running`` is the worst outcome available: no
        terminal record, no audit event, and nothing that can ever close it. So a refused write
        degrades to the smallest record the store cannot refuse. What is lost is the observation,
        never the fact that the call ended.
        """

        terminal: dict[str, Any] = {
            "execution_id": execution_id,
            "status": "failed",
            "output_payload": {"status": "failed"},
            "lineage": lineage,
            "error_code": error_code,
        }
        # The lifecycle refuses both together, so the one retry the fallback has must not be spent
        # on a combination the runner rejects before it ever reaches the store.
        if lineage is None and physical_attempts is not None:
            terminal["failed_physical_attempts"] = physical_attempts
        try:
            self._lifecycle.finish(**terminal)
        except Exception:
            if lineage is None:
                raise
            # Keep the attempt count: it is what tells the store this call was physically made,
            # so the degraded record reads as an unusable amount rather than as no call at all.
            self._terminalize_failure(
                execution_id=execution_id,
                error_code=error_code,
                lineage=None,
                physical_attempts=lineage.physical_attempts,
            )

    def generate(self, seed: dict[str, Any], *, count: int, category: str) -> list[dict[str, Any]]:
        """Generate ``count`` variant continuations as one SELF-RECORDED traced red_team execution.

        Drop-in for ``mutation.mutate(..., provider=...)``: it owns the start/invoke/finish steps
        and emits the identical :class:`HostedExecutionLineage`.
        """
        execution_id = self._lifecycle.start(
            role="red_team",
            parent_execution_id=self._parent_execution_id,
            input_payload={
                "generation": {
                    "category": category,
                    "count": count,
                    "seed_case_ref": seed.get("case_ref"),
                }
            },
            provider=self._role.provider,
            model=self._role.model,
            upstream_provider=self._role.upstream_provider,
            configuration_sha256=self._configuration_sha256,
            role_configuration_sha256=self._role.role_configuration_sha256,
            generation_policy_sha256=self._generation_policy_sha256,
            judge_calibration_id=None,
        )
        if not isinstance(execution_id, str) or not execution_id:
            raise TracedRedTeamGenerationError("execution lifecycle returned no identity")

        result: Any = None
        try:
            result = self._invoke_transport(
                seed,
                count,
                category,
                execution_id=execution_id,
            )
            # _collect_usable stays INSIDE the try: a short/exhausted generation raises
            # ProviderExhaustedError AFTER the (cost-incurring) transport call has already STARTED
            # the execution, so it must be recorded as a failed finish here — never left dangling as
            # a perpetually-"running" red_team execution that would break the uniform four-agent
            # lineage.
            variants = _collect_usable(seed, list(result.output.get("variants", [])), count)
        except Exception as exc:
            # A rejected response still carries its measurements: the transport surrenders them on
            # the exception precisely so a refusal cannot make a billed call look like it never
            # happened. Falling back to `result` covers a failure AFTER a clean invoke, e.g. an
            # exhausted generation, where the call succeeded and only its content was unusable.
            observed = getattr(exc, "observed_result", None)
            if observed is None:
                observed = result
            physical_attempts = getattr(exc, "physical_attempts", None)
            if (
                isinstance(physical_attempts, bool)
                or not isinstance(physical_attempts, int)
                or physical_attempts <= 0
            ):
                physical_attempts = None
            try:
                self._terminalize_failure(
                    execution_id=execution_id,
                    error_code=_typed_reason(getattr(exc, "code", None)),
                    lineage=self._observed_lineage(execution_id, observed),
                    physical_attempts=physical_attempts,
                )
            except Exception as lifecycle_exc:
                # The durable/Langfuse write of the failed finish ITSELF failed. Do not let that
                # replace the root cause: raise a typed terminal-record error whose __cause__ is the
                # ORIGINAL provider failure (preserving its .code), mirroring the four-role runtime
                # guard so all four agents fail uniformly.
                failure = TracedRedTeamGenerationError(
                    "traced red_team generation failure could not be terminally recorded"
                )
                failure.add_note(f"lifecycle failure type: {type(lifecycle_exc).__name__}")
                raise failure from exc
            raise

        record = self._observed_lineage(execution_id, result)
        try:
            if record is None:
                raise TracedRedTeamGenerationError(
                    "traced red_team generation produced no usable provider lineage"
                )
            self._lifecycle.finish(
                execution_id=execution_id,
                status="succeeded",
                output_payload=result.output,
                lineage=record,
                error_code=None,
            )
        except Exception as lifecycle_exc:
            # The terminal SUCCESS write itself failed — a real, cost-incurred qwen generation whose
            # durable record the store would not take. The store screens agent output for
            # credential material and bounds its size, and producing credential-shaped payloads is
            # this agent's ENTIRE JOB, so this is honest, in-contract model output, not a defect.
            # Re-labelling the exception and returning was leaving the row 'running' with
            # 'agent.started' as its only audit event and nothing able to close it: the platform
            # stranded its fourth agent the first time the model wrote a credible payload.
            #
            # So the execution terminalizes as a FAILURE carrying the reason and the observation.
            # The result is still not returned as if it had been recorded — the caller gets the
            # typed error — but the execution is closed and its cost is on the books.
            failure = TracedRedTeamGenerationError(
                "traced red_team generation result could not be terminally recorded"
            )
            failure.add_note(f"lifecycle failure type: {type(lifecycle_exc).__name__}")
            try:
                self._terminalize_failure(
                    execution_id=execution_id,
                    error_code=_TERMINAL_RECORD_REFUSED,
                    lineage=record,
                    physical_attempts=(None if record is None else record.physical_attempts),
                )
            except Exception as fallback_exc:
                failure.add_note(
                    f"fallback terminalization failure type: {type(fallback_exc).__name__}"
                )
            raise failure from lifecycle_exc
        return variants


__all__ = [
    "RED_TEAM_SUBCAP_CEILING_USD",
    "RedTeamGenerationResult",
    "RedTeamRoleIdentity",
    "TracedHostedRedTeamProvider",
    "TracedRedTeamGenerationError",
    "build_generation_messages",
    "require_red_team_subcap",
    "variants_output_schema",
]
