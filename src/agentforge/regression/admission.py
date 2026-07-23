"""Deterministic regression admission gate.

No model can promote a regression.  A report is admitted only after deterministic reproduction,
proof that the fixed behavior passed for the expected reason, and human approval.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from agentforge.contracts import validate


class RegressionAdmissionError(ValueError):
    """Regression admission input is invalid or does not name a confirmed exploit."""


class RegressionAdmissionGate:
    """Emit one schema-validated disposition without side effects."""

    def evaluate(
        self,
        *,
        verdict: Mapping[str, Any],
        finding_id: str,
        report_id: str,
        deterministic_reproduction: bool,
        passes_for_right_reason: bool,
        human_approved: bool,
        reproduction_attempted: bool = False,
    ) -> dict[str, Any]:
        try:
            candidate = dict(verdict)
            validate("verdict", candidate)
        except Exception as exc:
            raise RegressionAdmissionError(f"input fails the verdict contract: {exc}") from exc
        if candidate["state"] != "EXPLOIT_CONFIRMED":
            raise RegressionAdmissionError(
                "only a confirmed exploit may receive a regression disposition"
            )
        if not all(
            isinstance(value, bool)
            for value in (
                reproduction_attempted,
                deterministic_reproduction,
                passes_for_right_reason,
                human_approved,
            )
        ):
            raise RegressionAdmissionError("regression gate values must be booleans")
        if deterministic_reproduction or passes_for_right_reason:
            reproduction_attempted = True
        if passes_for_right_reason and not deterministic_reproduction:
            raise RegressionAdmissionError(
                "passing for the right reason requires deterministic reproduction"
            )

        if not reproduction_attempted:
            state = "pending_deterministic_reproduction"
            reasons = ["deterministic_reproduction_not_run"]
            deterministic_reproduction = False
            passes_for_right_reason = False
            human_approved = False
        elif not deterministic_reproduction:
            state = "rejected_non_deterministic"
            reasons = ["deterministic_reproduction_failed"]
        elif not passes_for_right_reason:
            state = "rejected_wrong_reason"
            reasons = ["safe_behavior_not_observed_for_right_reason"]
        elif not human_approved:
            state = "blocked_pending_human_approval"
            reasons = ["human_approval_required"]
        else:
            state = "admitted"
            reasons = ["admission_requirements_satisfied"]

        disposition_id = self._disposition_id(
            finding_id=finding_id,
            state=state,
            reproduction_attempted=reproduction_attempted,
            deterministic_reproduction=deterministic_reproduction,
            passes_for_right_reason=passes_for_right_reason,
            human_approved=human_approved,
        )
        disposition: dict[str, Any] = {
            "schema_version": "1",
            "disposition_id": disposition_id,
            "finding_id": self._bounded_id("finding id", finding_id, 160),
            "report_id": self._bounded_id("report id", report_id, 80),
            "campaign_run_id": candidate["campaign_run_id"],
            "attempt_id": candidate["attempt_id"],
            "state": state,
            "reason_codes": reasons,
            "reproduction_attempted": reproduction_attempted,
            "deterministic_reproduction": deterministic_reproduction,
            "passes_for_right_reason": passes_for_right_reason,
            "human_approved": human_approved,
            "admitted": state == "admitted",
        }
        try:
            validate("regression_disposition", disposition)
        except Exception as exc:
            raise RegressionAdmissionError(
                f"gate produced an invalid regression disposition: {exc}"
            ) from exc
        return disposition

    @staticmethod
    def _bounded_id(label: str, value: str, maximum: int) -> str:
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise RegressionAdmissionError(
                f"{label} must be a non-empty string no longer than {maximum} characters"
            )
        return value

    @staticmethod
    def _disposition_id(
        *,
        finding_id: str,
        state: str,
        reproduction_attempted: bool,
        deterministic_reproduction: bool,
        passes_for_right_reason: bool,
        human_approved: bool,
    ) -> str:
        if not isinstance(finding_id, str):
            raise RegressionAdmissionError("finding id must be a string")
        identity = "\0".join(
            (
                "regression-disposition:v1",
                finding_id,
                state,
                str(reproduction_attempted).lower(),
                str(deterministic_reproduction).lower(),
                str(passes_for_right_reason).lower(),
                str(human_approved).lower(),
            )
        )
        digest = hashlib.sha256(identity.encode()).hexdigest()
        return f"RD-{digest}"
