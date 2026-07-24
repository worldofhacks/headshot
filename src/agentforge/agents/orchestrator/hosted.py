"""Live, bounded Planner adapter over verified orchestration signals."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentforge.agents.hosted_runtime import (
    HostedCompositionError,
    HostedExecutionLineage,
    HostedRoleRuntime,
    require_safe_model_text,
)
from agentforge.agents.orchestrator.orchestrator import (
    OrchestrationDecision,
    OrchestrationInputError,
    Orchestrator,
)
from agentforge.contracts import validate

MAX_PLANNER_FINDINGS = 64
MAX_PLANNER_REGRESSIONS = 64
_PRIORITY_REASONS = (
    "regression_reappearance",
    "unresolved_critical_finding",
    "unresolved_finding",
    "low_signal_redirect",
    "coverage_gap",
)
_MUTATION_POLICIES = (
    "deterministic_regression_replay",
    "validate_unresolved_finding",
    "redirect_after_low_signal",
    "coverage_guided",
)


class HostedPlannerError(HostedCompositionError):
    """The live Planner response could not be clamped to authorized work."""

    code = "hosted-planner-failed"


@dataclass(frozen=True, slots=True)
class HostedPlannerResult:
    """One model-selected, code-clamped recommendation plus its durable call identity."""

    decision: OrchestrationDecision
    execution_id: str
    provider_request_id: str
    lineage: HostedExecutionLineage

    @property
    def recommendation(self) -> OrchestrationDecision:
        return self.decision


class HostedPlanner:
    """Use the hosted Orchestrator to select work after deterministic safety guards pass."""

    def __init__(
        self,
        *,
        runtime: HostedRoleRuntime,
        safety_governor: Orchestrator | None = None,
    ) -> None:
        if not isinstance(runtime, HostedRoleRuntime):
            raise HostedPlannerError("hosted role runtime is unavailable")
        self._runtime = runtime
        self._safety_governor = safety_governor or Orchestrator()

    def decide(
        self,
        snapshot: Mapping[str, Any],
        *,
        parent_execution_id: str | None = None,
        parent_request_id: str | None = None,
    ) -> HostedPlannerResult:
        """Select a category live; code retains all breaker, identity, and cap authority."""

        try:
            candidate = self._safety_governor.guard(snapshot)
        except (OrchestrationInputError, TypeError, ValueError):
            raise
        categories = tuple(row["category"] for row in candidate["coverage"])
        allowed_regressions = {
            row["regression_id"]: row
            for row in candidate["regressions"]
            if row["state"] in {"failing", "regressed", "reopened"}
        }
        model_input = self._model_input(candidate)
        holder: dict[str, OrchestrationDecision] = {}

        def validate_recommendation(raw: Mapping[str, Any]) -> Mapping[str, Any]:
            if set(raw) != {
                "category",
                "coverage_goal",
                "mutation_policy",
                "priority_reason",
                "regression_triggers",
            }:
                raise HostedPlannerError("Planner response has an invalid shape")
            category = raw.get("category")
            if category not in categories:
                raise HostedPlannerError("Planner selected an unauthorized category")
            coverage_goal = require_safe_model_text(
                "Planner coverage goal",
                raw.get("coverage_goal"),
                maximum=1_000,
            )
            priority_reason = raw.get("priority_reason")
            mutation_policy = raw.get("mutation_policy")
            if priority_reason not in _PRIORITY_REASONS:
                raise HostedPlannerError("Planner priority reason is invalid")
            if mutation_policy not in _MUTATION_POLICIES:
                raise HostedPlannerError("Planner mutation policy is invalid")
            raw_triggers = raw.get("regression_triggers")
            if (
                not isinstance(raw_triggers, list)
                or len(raw_triggers) > MAX_PLANNER_REGRESSIONS
                or any(not isinstance(trigger, str) for trigger in raw_triggers)
            ):
                raise HostedPlannerError("Planner regression triggers are invalid")
            if len(set(raw_triggers)) != len(raw_triggers):
                raise HostedPlannerError("Planner regression triggers contain duplicates")
            triggers: tuple[str, ...] = tuple(raw_triggers)
            if any(
                not isinstance(trigger, str)
                or trigger not in allowed_regressions
                or allowed_regressions[trigger]["category"] != category
                for trigger in triggers
            ):
                raise HostedPlannerError("Planner selected an unauthorized regression trigger")
            if priority_reason == "regression_reappearance" and not triggers:
                raise HostedPlannerError("regression priority requires an active trigger")
            if triggers and mutation_policy != "deterministic_regression_replay":
                raise HostedPlannerError("regression triggers require the replay mutation policy")
            if (
                priority_reason == "low_signal_redirect"
                and len(categories) > 1
                and category == candidate["previous_category"]
            ):
                raise HostedPlannerError("low-signal redirect did not change category")

            directive: dict[str, Any] = {
                "schema_version": "1",
                "campaign_id": candidate["campaign_run_id"],
                "target_ref": candidate["target_ref"],
                "category": category,
                "coverage_goal": coverage_goal,
                "mutation_policy": mutation_policy,
                # Model output can never widen these trusted values.
                "caps": dict(candidate["authorized_caps"]),
            }
            try:
                validate("campaign_directive", directive)
            except Exception as exc:
                raise HostedPlannerError("Planner directive failed its contract") from exc
            decision = OrchestrationDecision(
                directive=directive,
                priority_reason=priority_reason,
                signal_sha256=self._safety_governor.signal_sha256(candidate),
                regression_triggers=triggers,
            )
            holder["decision"] = decision
            return {
                "directive": directive,
                "priority_reason": priority_reason,
                "signal_sha256": decision.signal_sha256,
                "regression_triggers": list(triggers),
            }

        invocation = self._runtime.invoke(
            "orchestrator",
            input_payload=model_input,
            output_schema=self._output_schema(categories),
            schema_name="orchestrator_recommendation",
            parent_execution_id=parent_execution_id,
            parent_request_id=parent_request_id,
            validate_output=validate_recommendation,
        )
        decision = holder.get("decision")
        if decision is None:
            raise HostedPlannerError("Planner recommendation was not validated")
        return HostedPlannerResult(
            decision=decision,
            execution_id=invocation.execution_id,
            provider_request_id=invocation.provider_request_id,
            lineage=invocation.lineage,
        )

    @staticmethod
    def _model_input(snapshot: Mapping[str, Any]) -> dict[str, Any]:
        """Bound high-cardinality signals while preserving all safety and coverage facts."""

        findings = sorted(
            snapshot["findings"],
            key=lambda row: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}[row["severity"]],
                row["category"],
                row["finding_id"],
            ),
        )
        regressions = sorted(
            snapshot["regressions"],
            key=lambda row: (
                0 if row["state"] in {"failing", "regressed", "reopened"} else 1,
                {"critical": 0, "high": 1, "medium": 2, "low": 3}[row["severity"]],
                row["category"],
                row["regression_id"],
            ),
        )
        return {
            "schema_version": "1",
            "planning_scope": {
                "campaign_run_id": snapshot["campaign_run_id"],
                "target_ref": snapshot["target_ref"],
                "target_version": snapshot["target_version"],
                "signal_provenance": snapshot["signal_provenance"],
                "coverage": list(snapshot["coverage"]),
                "findings": findings[:MAX_PLANNER_FINDINGS],
                "omitted_finding_count": max(0, len(findings) - MAX_PLANNER_FINDINGS),
                "regressions": regressions[:MAX_PLANNER_REGRESSIONS],
                "omitted_regression_count": max(0, len(regressions) - MAX_PLANNER_REGRESSIONS),
                "budget": dict(snapshot["budget"]),
                "queue": dict(snapshot["queue"]),
                "authorized_caps": dict(snapshot["authorized_caps"]),
                "low_signal_streak": snapshot["low_signal_streak"],
                "previous_category": snapshot["previous_category"],
            },
        }

    @staticmethod
    def _output_schema(categories: tuple[str, ...]) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "category": {"enum": list(categories)},
                "coverage_goal": {"type": "string", "minLength": 1, "maxLength": 1_000},
                "mutation_policy": {"enum": list(_MUTATION_POLICIES)},
                "priority_reason": {"enum": list(_PRIORITY_REASONS)},
                "regression_triggers": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 160},
                    "maxItems": MAX_PLANNER_REGRESSIONS,
                    "uniqueItems": True,
                },
            },
            "required": [
                "category",
                "coverage_goal",
                "mutation_policy",
                "priority_reason",
                "regression_triggers",
            ],
            "additionalProperties": False,
        }


__all__ = [
    "MAX_PLANNER_FINDINGS",
    "MAX_PLANNER_REGRESSIONS",
    "HostedPlanner",
    "HostedPlannerError",
    "HostedPlannerResult",
]
