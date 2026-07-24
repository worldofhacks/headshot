"""Closed reason-code vocabulary for human finding review decisions.

The structured code supports aggregation and audit review; the required free-text
``rationale`` remains the approver's complete explanation.  Codes are intentionally
decision-specific so a rejection reason cannot be attached to an approval.
"""

from __future__ import annotations

from typing import Literal

type FindingDecisionReasonCode = Literal[
    "human_confirmed",
    "not_a_real_exploit",
    "insufficient_evidence",
    "duplicate_finding",
    "outside_authorized_scope",
]

FINDING_DECISION_REASON_CODES: dict[str, frozenset[FindingDecisionReasonCode]] = {
    "approved": frozenset({"human_confirmed"}),
    "rejected": frozenset(
        {
            "not_a_real_exploit",
            "insufficient_evidence",
            "duplicate_finding",
            "outside_authorized_scope",
        }
    ),
}


def validate_finding_decision_reason_code(*, decision: str, reason_code: object) -> str:
    """Return a decision-compatible code or reject absent/open-ended values."""

    allowed = FINDING_DECISION_REASON_CODES.get(decision)
    if allowed is None:
        raise ValueError("finding review decision is invalid")
    if not isinstance(reason_code, str) or reason_code not in allowed:
        raise ValueError("finding decision reason code is invalid for the decision")
    return reason_code


__all__ = [
    "FINDING_DECISION_REASON_CODES",
    "FindingDecisionReasonCode",
    "validate_finding_decision_reason_code",
]
