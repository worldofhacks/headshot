"""Regression admission is deterministic, reason-aware, and human-gated."""

from __future__ import annotations

import copy

import pytest

from agentforge.contracts import is_valid
from agentforge.regression import RegressionAdmissionError, RegressionAdmissionGate


def _verdict(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1",
        "campaign_run_id": "run-reg-1",
        "attempt_id": "attempt-reg-1",
        "state": "EXPLOIT_CONFIRMED",
        "confidence": 1.0,
        "reason_codes": ["oracle_confirmed"],
        "confirmation_source": "oracle",
    }
    payload.update(updates)
    return payload


def test_confirmed_finding_starts_pending_deterministic_reproduction() -> None:
    disposition = RegressionAdmissionGate().evaluate(
        verdict=_verdict(),
        finding_id="finding-reg-1",
        report_id="report-reg-1",
        deterministic_reproduction=False,
        passes_for_right_reason=False,
        human_approved=False,
    )

    assert is_valid("regression_disposition", disposition)
    assert disposition["state"] == "pending_deterministic_reproduction"
    assert disposition["admitted"] is False


def test_reproduced_right_reason_still_blocks_without_human_approval() -> None:
    disposition = RegressionAdmissionGate().evaluate(
        verdict=_verdict(),
        finding_id="finding-reg-1",
        report_id="report-reg-1",
        deterministic_reproduction=True,
        passes_for_right_reason=True,
        human_approved=False,
    )

    assert disposition["state"] == "blocked_pending_human_approval"
    assert disposition["admitted"] is False


def test_admission_requires_reproduction_right_reason_and_human_approval() -> None:
    disposition = RegressionAdmissionGate().evaluate(
        verdict=_verdict(),
        finding_id="finding-reg-1",
        report_id="report-reg-1",
        deterministic_reproduction=True,
        passes_for_right_reason=True,
        human_approved=True,
    )

    assert disposition["state"] == "admitted"
    assert disposition["admitted"] is True
    assert is_valid("regression_disposition", disposition)


def test_wrong_reason_is_rejected_even_if_a_human_approved() -> None:
    disposition = RegressionAdmissionGate().evaluate(
        verdict=_verdict(),
        finding_id="finding-reg-1",
        report_id="report-reg-1",
        deterministic_reproduction=True,
        passes_for_right_reason=False,
        human_approved=True,
    )

    assert disposition["state"] == "rejected_wrong_reason"
    assert disposition["admitted"] is False


def test_non_confirmed_or_invalid_verdict_fails_closed() -> None:
    verdict = _verdict(
        state="INDETERMINATE",
        confidence=0.0,
        reason_codes=["non_oracle_uncalibrated_indeterminate"],
    )
    verdict.pop("confirmation_source")
    with pytest.raises(RegressionAdmissionError, match="confirmed"):
        RegressionAdmissionGate().evaluate(
            verdict=verdict,
            finding_id="finding-reg-1",
            report_id="report-reg-1",
            deterministic_reproduction=False,
            passes_for_right_reason=False,
            human_approved=False,
        )


def test_contract_prevents_claiming_admission_without_all_three_gates() -> None:
    disposition = RegressionAdmissionGate().evaluate(
        verdict=_verdict(),
        finding_id="finding-reg-1",
        report_id="report-reg-1",
        deterministic_reproduction=False,
        passes_for_right_reason=False,
        human_approved=False,
    )
    forged = copy.deepcopy(disposition)
    forged["state"] = "admitted"
    forged["admitted"] = True

    assert not is_valid("regression_disposition", forged)
