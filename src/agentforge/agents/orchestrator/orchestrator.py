"""Trusted campaign governor over hash-verified Postgres signals.

The Orchestrator chooses what to test next; it cannot reach a target or expand the caps already
authorized for the campaign.  It accepts no raw span/transcript input and emits a validated
``CampaignDirective`` plus regression-trigger metadata for the trusted Runner.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentforge.contracts import validate

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_CLOSED_FINDING_STATES = frozenset({"resolved", "fixed"})
_REGRESSION_ALERT_STATES = frozenset({"failing", "regressed", "reopened"})


class OrchestrationInputError(ValueError):
    """Verified-signal input is malformed, contradictory, or untrusted."""


class OrchestratorHalt(RuntimeError):
    """A cost or backpressure breaker stopped orchestration before directive emission."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class OrchestrationDecision:
    directive: dict[str, Any]
    priority_reason: str
    signal_sha256: str
    regression_triggers: tuple[str, ...] = ()


class Orchestrator:
    """Deterministic governor with explicit priority and circuit-breaker rules."""

    def __init__(self, *, low_signal_redirect_threshold: int = 3) -> None:
        if (
            isinstance(low_signal_redirect_threshold, bool)
            or not isinstance(low_signal_redirect_threshold, int)
            or low_signal_redirect_threshold < 1
        ):
            raise ValueError("low-signal redirect threshold must be a positive integer")
        self.low_signal_redirect_threshold = low_signal_redirect_threshold

    def decide(self, snapshot: Mapping[str, Any]) -> OrchestrationDecision:
        candidate = dict(snapshot)
        try:
            validate("orchestration_snapshot", candidate)
        except Exception as exc:
            raise OrchestrationInputError(
                f"orchestration snapshot fails its contract: {exc}"
            ) from exc
        coverage = [dict(row) for row in candidate["coverage"]]
        self._validate_consistency(candidate, coverage)

        budget = candidate["budget"]
        queue = candidate["queue"]
        if budget["spent_usd"] >= budget["cap_usd"]:
            raise OrchestratorHalt("budget_exhausted")
        if queue["depth"] >= queue["backpressure_threshold"]:
            raise OrchestratorHalt("queue_backpressure")

        category, reason, mutation_policy, regression_triggers = self._priority(candidate, coverage)
        caps = dict(candidate["authorized_caps"])
        if caps["budget_usd"] != budget["cap_usd"]:
            raise OrchestrationInputError("authorized budget and budget circuit-breaker cap differ")
        directive: dict[str, Any] = {
            "schema_version": "1",
            "campaign_id": candidate["campaign_run_id"],
            "target_ref": candidate["target_ref"],
            "category": category,
            "coverage_goal": self._coverage_goal(category, coverage, reason),
            "mutation_policy": mutation_policy,
            "caps": caps,
        }
        try:
            validate("campaign_directive", directive)
        except Exception as exc:
            raise OrchestrationInputError(
                f"Orchestrator produced an invalid CampaignDirective: {exc}"
            ) from exc
        return OrchestrationDecision(
            directive=directive,
            priority_reason=reason,
            signal_sha256=self._signal_hash(candidate),
            regression_triggers=regression_triggers,
        )

    def _priority(
        self,
        snapshot: dict[str, Any],
        coverage: list[dict[str, Any]],
    ) -> tuple[str, str, str, tuple[str, ...]]:
        regressions = [
            dict(row) for row in snapshot["regressions"] if row["state"] in _REGRESSION_ALERT_STATES
        ]
        if regressions:
            ordered = sorted(
                regressions,
                key=lambda row: (
                    -_SEVERITY_RANK[row["severity"]],
                    row["category"],
                    row["regression_id"],
                ),
            )
            triggers = tuple(sorted(row["regression_id"] for row in regressions))
            return (
                ordered[0]["category"],
                "regression_reappearance",
                "deterministic_regression_replay",
                triggers,
            )

        findings = [
            dict(row) for row in snapshot["findings"] if row["status"] not in _CLOSED_FINDING_STATES
        ]
        if findings:
            ordered = sorted(
                findings,
                key=lambda row: (
                    -_SEVERITY_RANK[row["severity"]],
                    row["category"],
                    row["finding_id"],
                ),
            )
            top = ordered[0]
            reason = (
                "unresolved_critical_finding"
                if top["severity"] == "critical"
                else "unresolved_finding"
            )
            return top["category"], reason, "validate_unresolved_finding", ()

        previous = snapshot["previous_category"]
        if (
            snapshot["low_signal_streak"] >= self.low_signal_redirect_threshold
            and previous is not None
        ):
            alternatives = [row for row in coverage if row["category"] != previous]
            if alternatives:
                selected = min(alternatives, key=self._coverage_rank)
                return (
                    selected["category"],
                    "low_signal_redirect",
                    "redirect_after_low_signal",
                    (),
                )

        selected = min(coverage, key=self._coverage_rank)
        return selected["category"], "coverage_gap", "coverage_guided", ()

    @staticmethod
    def _coverage_rank(row: Mapping[str, Any]) -> tuple[int, float, int, str]:
        return (
            0 if row["deterministic_anchor_count"] == 0 else 1,
            row["verified_attempt_count"] / row["total_case_count"],
            row["verified_attempt_count"],
            row["category"],
        )

    @staticmethod
    def _coverage_goal(
        category: str,
        coverage: list[dict[str, Any]],
        reason: str,
    ) -> str:
        row = next(item for item in coverage if item["category"] == category)
        return (
            f"{reason}: {category} has {row['verified_attempt_count']}/"
            f"{row['total_case_count']} verified attempts and "
            f"{row['deterministic_anchor_count']} deterministic anchors"
        )

    @staticmethod
    def _validate_consistency(snapshot: Mapping[str, Any], coverage: list[dict[str, Any]]) -> None:
        categories = [row["category"] for row in coverage]
        if len(categories) != len(set(categories)):
            raise OrchestrationInputError("duplicate coverage category")
        for row in coverage:
            if (
                row["verified_attempt_count"] > row["total_case_count"]
                or row["deterministic_anchor_count"] > row["verified_attempt_count"]
            ):
                raise OrchestrationInputError("coverage counts are internally inconsistent")
        known = set(categories)
        for signal in (*snapshot["findings"], *snapshot["regressions"]):
            if signal["category"] not in known:
                raise OrchestrationInputError("signal category is outside authorized coverage")

    @staticmethod
    def _signal_hash(snapshot: Mapping[str, Any]) -> str:
        canonical = json.dumps(
            snapshot,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(canonical).hexdigest()
