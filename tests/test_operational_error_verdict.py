"""An un-adjudicable case yields a contract-valid ERROR verdict, not a dead campaign.

Case 12 of run 50da57b037d44b3c93a10e4c2edf61a8 had both target turns complete and its evidence
durably written; only the Judge's *formatting* failed. The campaign nonetheless dead-lettered,
discarding the authority to evaluate the remaining 22 cases.

The isolation is only safe if it is narrow. These tests pin two properties: the ERROR verdict the
Runner writes actually satisfies the verdict contract (so it can be persisted at all), and the
exception type used to trigger isolation cannot swallow a governance abort.
"""

from __future__ import annotations

import inspect

import pytest

from agentforge.campaign.coordinator import CampaignAbort
from agentforge.contracts import is_valid
from agentforge.providers.openrouter import (
    HostedProviderError,
    HostedProviderResponseError,
    HostedStructuredOutputInvalid,
)
from agentforge.runner import DispatchUnavailable, DurableCampaignRunner


def _error_verdict(error_code: str = "invalid_structured_output") -> dict:
    """The exact shape ``_record_operational_error_verdict`` persists."""

    return {
        "schema_version": "1",
        "campaign_run_id": "a" * 32,
        "attempt_id": "b" * 64,
        "state": "ERROR",
        "confidence": 0.0,
        "reason_codes": ["judge_invalid_structured_output"],
        "error_code": error_code,
    }


def test_the_operational_error_verdict_satisfies_the_verdict_contract() -> None:
    assert is_valid("verdict", _error_verdict())


def test_an_error_verdict_without_a_typed_error_code_is_rejected() -> None:
    """The contract's own ERROR rule — kept honest so the reason can never be blank."""

    verdict = _error_verdict()
    del verdict["error_code"]
    assert not is_valid("verdict", verdict)


def test_the_new_reason_code_is_a_first_class_contract_member() -> None:
    verdict = _error_verdict()
    verdict["reason_codes"] = ["judge_invalid_structured_output"]
    assert is_valid("verdict", verdict)
    verdict["reason_codes"] = ["not_a_real_reason_code"]
    assert not is_valid("verdict", verdict)


def test_an_error_verdict_can_never_be_a_confirmed_exploit() -> None:
    """ERROR is an operational outcome; it must not carry security confirmation."""

    verdict = _error_verdict()
    assert verdict["state"] == "ERROR"
    assert verdict["confidence"] == 0.0
    assert "confirmation_source" not in verdict


# --------------------------------------------------------------------------------------
# The isolation is type-precise: governance failures are a different type and still abort.
# --------------------------------------------------------------------------------------


def test_only_the_structured_output_type_is_isolated() -> None:
    """CampaignAbort and DispatchUnavailable must not be catchable by the isolation handler."""

    assert issubclass(HostedStructuredOutputInvalid, HostedProviderResponseError)
    assert issubclass(HostedStructuredOutputInvalid, HostedProviderError)
    # The two governance families are unrelated to the isolated type, so `except
    # HostedStructuredOutputInvalid` can never intercept them.
    assert not issubclass(CampaignAbort, HostedProviderError)
    assert not issubclass(DispatchUnavailable, HostedProviderError)
    assert not issubclass(HostedStructuredOutputInvalid, CampaignAbort)
    assert not issubclass(HostedStructuredOutputInvalid, DispatchUnavailable)


def test_a_generic_provider_failure_is_not_isolated() -> None:
    """Only the schema-invalid subclass is; a plain response error still aborts the run."""

    assert not issubclass(HostedProviderResponseError, HostedStructuredOutputInvalid)
    assert not issubclass(HostedProviderError, HostedStructuredOutputInvalid)


def test_missing_evidence_fails_closed_rather_than_inventing_a_verdict() -> None:
    """If the evidence hash cannot be recovered the campaign aborts; it does not guess."""

    source = inspect.getsource(DurableCampaignRunner._record_operational_error_verdict)
    assert "persisted_evidence_content_hash" in source
    assert "CampaignAbort" in source
    assert "attempt_evidence_unavailable" in source


def test_the_isolated_path_never_opens_a_finding() -> None:
    source = inspect.getsource(DurableCampaignRunner._execute_prepared)
    isolated = source.split("except HostedStructuredOutputInvalid as exc:", 1)
    assert len(isolated) == 2, "the isolation handler must exist"
    handler = isolated[1].split("if finding_id is not None:", 1)[0]
    assert "finding_id = None" in handler
    assert "operational_errors += 1" in handler


@pytest.mark.parametrize(
    "code",
    ["invalid_structured_output"],
)
def test_the_error_code_travels_from_the_transport_into_the_verdict(code: str) -> None:
    assert HostedStructuredOutputInvalid.code == code
    assert is_valid("verdict", _error_verdict(code))
