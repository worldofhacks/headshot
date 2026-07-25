"""Pure regression lifecycle wiring from reproduction through reappearance signal.

Execution and human authorization remain external responsibilities. This module only connects
their already-verified artifacts and refuses skipped or reordered transitions.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from agentforge.contracts import validate
from agentforge.regression.admission import RegressionAdmissionGate
from agentforge.regression.replay import RegressionReplayGate, ReplayObservation


class RegressionLifecycleError(ValueError):
    """The requested regression transition lacks exact verified lineage."""


class RegressionLifecycle:
    """Connect confirmed finding → reproduction → approval → replay → alert."""

    def __init__(self) -> None:
        self._admission = RegressionAdmissionGate()
        self._replay = RegressionReplayGate()

    def plan_reproduction(
        self,
        *,
        pending_disposition: Mapping[str, Any],
        report: Mapping[str, Any],
        attack_attempt: Mapping[str, Any],
        source_case_version: str,
        target_id: str,
        target_version: str,
        required_oracle_ids: Sequence[str],
        repetitions: int = 3,
    ) -> dict[str, Any]:
        """Create an execution-blocked plan for deterministic reproduction."""

        return self._replay.plan(
            disposition=pending_disposition,
            report=report,
            attack_attempt=attack_attempt,
            source_case_version=source_case_version,
            target_id=target_id,
            source_target_version=target_version,
            replay_target_version=target_version,
            required_oracle_ids=required_oracle_ids,
            trigger="deterministic_reproduction",
            repetitions=repetitions,
        )

    def evaluate_reproduction(
        self,
        *,
        plan: Mapping[str, Any],
        campaign_run_id: str,
        authorization_scope_hash: str,
        observations: Sequence[ReplayObservation],
    ) -> dict[str, Any]:
        """Evaluate scope-bound observations; execution itself remains gateway-only."""

        plan_payload = self._contract("regression_replay_plan", plan)
        if plan_payload["trigger"] != "deterministic_reproduction":
            raise RegressionLifecycleError("reproduction evaluation requires a reproduction plan")
        return self._replay.evaluate(
            plan=plan_payload,
            campaign_run_id=campaign_run_id,
            authorization_scope_hash=authorization_scope_hash,
            observations=observations,
        )

    def admission_after_reproduction(
        self,
        *,
        source_verdict: Mapping[str, Any],
        pending_disposition: Mapping[str, Any],
        report: Mapping[str, Any],
        reproduction_plan: Mapping[str, Any],
        reproduction_result: Mapping[str, Any],
        human_approval_verified: bool,
    ) -> dict[str, Any]:
        """Emit a blocked or admitted disposition after deterministic reproduction.

        ``human_approval_verified`` is accepted only as the result of the authenticated backend
        approval command. This pure transition has no identity store and grants no authority.
        """

        if not isinstance(human_approval_verified, bool):
            raise RegressionLifecycleError("human approval verification must be boolean")
        disposition = self._contract("regression_disposition", pending_disposition)
        report_payload = self._contract("vuln_report", report)
        plan = self._contract("regression_replay_plan", reproduction_plan)
        result = self._contract("regression_replay_result", reproduction_result)
        verdict = self._contract("verdict", source_verdict)
        if (
            disposition["state"] != "pending_deterministic_reproduction"
            or disposition["admitted"]
            or plan["trigger"] != "deterministic_reproduction"
        ):
            raise RegressionLifecycleError("regression candidate is not pending reproduction")
        for key in ("finding_id", "report_id"):
            if plan[key] != report_payload[key] or disposition[key] != report_payload[key]:
                raise RegressionLifecycleError("reproduction lineage differs from the report")
        if (
            disposition["campaign_run_id"] != report_payload["campaign_run_id"]
            or disposition["attempt_id"] != report_payload["attempt_id"]
            or verdict["campaign_run_id"] != report_payload["campaign_run_id"]
            or verdict["attempt_id"] != report_payload["attempt_id"]
        ):
            raise RegressionLifecycleError("source verdict lineage differs from the report")
        if (
            result["replay_id"] != plan["replay_id"]
            or result["regression_case_id"] != plan["regression_case_id"]
            or result["attack_sequence_sha256"] != plan["attack_sequence_sha256"]
        ):
            raise RegressionLifecycleError("reproduction result differs from its plan")
        reproduced = (
            result["state"] == "failing"
            and result["deterministic"]
            and result["passes_for_right_reason"]
            and result["reappeared"]
        )
        return self._admission.evaluate(
            verdict=verdict,
            finding_id=report_payload["finding_id"],
            report_id=report_payload["report_id"],
            reproduction_attempted=True,
            deterministic_reproduction=reproduced,
            passes_for_right_reason=reproduced,
            human_approved=human_approval_verified,
        )

    def reappearance_signal(
        self,
        *,
        report: Mapping[str, Any],
        replay_plan: Mapping[str, Any],
        replay_result: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Project a failing replay into the verified Orchestrator regression signal."""

        report_payload = self._contract("vuln_report", report)
        plan = self._contract("regression_replay_plan", replay_plan)
        result = self._contract("regression_replay_result", replay_result)
        if (
            result["replay_id"] != plan["replay_id"]
            or result["regression_case_id"] != plan["regression_case_id"]
            or plan["finding_id"] != report_payload["finding_id"]
            or plan["report_id"] != report_payload["report_id"]
        ):
            raise RegressionLifecycleError("reappearance lineage is inconsistent")
        if result["state"] != "failing" or not result["reappeared"]:
            return None
        signal = {
            "regression_id": plan["regression_case_id"],
            "finding_id": report_payload["finding_id"],
            "category": report_payload["category"],
            "severity": report_payload["severity"],
            "state": "regressed",
            "evidence_verified": True,
        }
        snapshot_probe = {
            "schema_version": "1",
            "campaign_run_id": "reappearance-projection",
            "target_ref": plan["target_id"],
            "target_version": result["replay_target_version"],
            "signal_provenance": "hash_verified_postgres",
            "coverage": [
                {
                    "category": report_payload["category"],
                    "total_case_count": 1,
                    "verified_attempt_count": 1,
                    "deterministic_anchor_count": 1,
                }
            ],
            "findings": [],
            "regressions": [signal],
            "budget": {"cap_usd": 1.0, "spent_usd": 0.0},
            "queue": {"depth": 0, "backpressure_threshold": 1},
            "authorized_caps": {
                "budget_usd": 1.0,
                "rate_per_min": 1,
                "timeout_s": 1,
            },
            "low_signal_streak": 0,
            "previous_category": None,
        }
        self._contract("orchestration_snapshot", snapshot_probe)
        return signal

    @staticmethod
    def _contract(name: str, value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise RegressionLifecycleError(f"{name} payload must be a mapping")
        candidate = copy.deepcopy(dict(value))
        try:
            validate(name, candidate)
        except Exception as exc:
            raise RegressionLifecycleError(f"{name} payload fails its contract") from exc
        return candidate


__all__ = ["RegressionLifecycle", "RegressionLifecycleError"]
