"""A candidate finding must be reviewable, and must never be mistaken for a confirmed one.

Before migration 0031 a finding was opened only for `EXPLOIT_CONFIRMED`, and a vulnerability report
only for a finding. `EXPLOIT_CONFIRMED` requires a deterministic oracle or canary hit, and no oracle
has ever fired: across every campaign to date — including a completed 34/34 run that produced eight
`EXPLOIT_LIKELY` verdicts — `finding` stayed empty, the Documentation agent never executed, and
`vuln_reports` had zero rows. The reviewer was asked to approve findings with nothing to read.

`EXPLOIT_LIKELY` now opens a `candidate` finding and is documented like any other, so review can
precede approval. The entire risk of that change is one thing: a candidate reading as confirmed.
These tests pin the boundary at each layer that could blur it.
"""

from __future__ import annotations

import pytest
from jsonschema.exceptions import ValidationError

from agentforge.agents.documentation import DocumentationAgent, DocumentationInputError
from agentforge.contracts import validate


def _verdict(state: str, source: str) -> dict[str, object]:
    return {
        "schema_version": "1",
        "state": state,
        "confidence": 0.9,
        "campaign_run_id": "run-0001",
        "attempt_id": "a" * 64,
        "reason_codes": ["calibrated_positive"],
        "confirmation_source": source,
    }


# ---------------------------------------------------------------------------------------
# Which verdicts may be documented, and what each is allowed to claim about itself.
# ---------------------------------------------------------------------------------------


def test_the_two_documentable_states_map_to_distinct_confirmation_status() -> None:
    """The mapping is the single place state and claim are tied together."""

    mapping = DocumentationAgent._DOCUMENTABLE_STATES

    assert mapping["EXPLOIT_CONFIRMED"][1] == "confirmed"
    assert mapping["EXPLOIT_LIKELY"][1] == "candidate_unconfirmed"

    # A confirmed report may only rest on a trusted source; a candidate only on the model. Neither
    # set may leak into the other, or a report would misstate its own authority.
    assert mapping["EXPLOIT_CONFIRMED"][0] == frozenset({"oracle", "canary", "human"})
    assert mapping["EXPLOIT_LIKELY"][0] == frozenset({"calibrated_model"})
    assert not (mapping["EXPLOIT_CONFIRMED"][0] & mapping["EXPLOIT_LIKELY"][0])


@pytest.mark.parametrize("state", ["INDETERMINATE", "NO_EXPLOIT_OBSERVED", "ERROR"])
def test_no_other_verdict_state_can_be_documented(state: str) -> None:
    """ERROR especially: an operational fault is not a security signal and opens nothing."""

    assert state not in DocumentationAgent._DOCUMENTABLE_STATES
    with pytest.raises(DocumentationInputError):
        DocumentationAgent._validate_verdict(_verdict(state, "calibrated_model"))


def test_a_confirmed_verdict_claiming_the_model_as_its_source_is_refused() -> None:
    """Fails closed rather than emitting a report that overstates its own authority."""

    with pytest.raises(DocumentationInputError):
        DocumentationAgent._validate_verdict(_verdict("EXPLOIT_CONFIRMED", "calibrated_model"))


@pytest.mark.parametrize("source", ["oracle", "canary", "human"])
def test_a_likely_verdict_claiming_a_trusted_source_is_refused(source: str) -> None:
    """The inverse mislabel, and the more dangerous one: it would understate an oracle hit as a
    candidate, or let a candidate borrow an oracle's authority."""

    with pytest.raises(DocumentationInputError):
        DocumentationAgent._validate_verdict(_verdict("EXPLOIT_LIKELY", source))


def test_confirmation_status_is_read_from_the_verdict_and_is_not_caller_supplied() -> None:
    """The caller supplies sanitized narrative; it does not get to say whether this is confirmed.

    Reading the fact from the verdict is what makes mislabelling structurally impossible rather
    than merely discouraged, so `DocumentationInput` must have no such field to override.
    """

    from dataclasses import fields  # noqa: PLC0415

    from agentforge.agents.documentation import DocumentationInput  # noqa: PLC0415

    assert "confirmation_status" not in {f.name for f in fields(DocumentationInput)}
    assert (
        DocumentationAgent._confirmation_status(_verdict("EXPLOIT_LIKELY", "calibrated_model"))
        == "candidate_unconfirmed"
    )
    assert (
        DocumentationAgent._confirmation_status(_verdict("EXPLOIT_CONFIRMED", "oracle"))
        == "confirmed"
    )


# ---------------------------------------------------------------------------------------
# The contract itself refuses a publishable candidate, independently of any code path.
# ---------------------------------------------------------------------------------------


def _report(**overrides: object) -> dict[str, object]:
    report: dict[str, object] = {
        "schema_version": "1",
        "report_id": "report-0001",
        "finding_id": "f" * 64,
        "campaign_run_id": "run-0001",
        "attempt_id": "a" * 64,
        "source_case_id": "AF-M11-TM-015",
        "severity": "high",
        "category": "information-disclosure",
        "confirmation_status": "candidate_unconfirmed",
        "description": "The target disclosed guarded configuration.",
        "clinical_impact": "Internal enforcement labels aid filter evasion.",
        "minimal_reproduction": ["send the probe"],
        "reproduction_sha256": "b" * 64,
        "observed_behavior": "The model evaluator returned EXPLOIT_LIKELY.",
        "expected_behavior": "Keep guarded configuration non-disclosable.",
        "recommended_remediation": "Enforce and regression-test the property.",
        "status": "draft",
        "model_assessment": {
            "authority": "advisory_never_confirmatory",
            "rationale": "The output included an internal verdicts array.",
        },
        "fix_validation": {
            "state": "not_run",
            "summary": "No remediation has been validated.",
            "evidence_references": [],
        },
        "evidence_references": ["evidence://sha256/" + "c" * 64],
        "publication_state": "blocked_pending_human_approval",
    }
    report.update(overrides)
    return report


def test_a_candidate_report_is_schema_valid_only_while_blocked() -> None:
    validate("vuln_report", _report())

    with pytest.raises(ValidationError):
        validate("vuln_report", _report(publication_state="draft_unpublished"))


def test_a_candidate_report_must_carry_the_opinion_it_rests_on() -> None:
    """A candidate is nothing BUT the model's assessment, so omitting it would leave a report that
    asserts a vulnerability with no stated basis at all."""

    payload = _report()
    del payload["model_assessment"]
    with pytest.raises(ValidationError):
        validate("vuln_report", payload)

    # A confirmed report has trusted evidence behind it, so the assessment stays optional there.
    confirmed = _report(
        confirmation_status="confirmed",
        publication_state="draft_unpublished",
        observed_behavior="The independent Judge returned EXPLOIT_CONFIRMED from trusted oracle "
        "evidence; inspect the content-addressed evidence.",
    )
    del confirmed["model_assessment"]
    validate("vuln_report", confirmed)


def test_confirmation_status_is_required_so_a_report_can_never_be_silent_about_it() -> None:
    """An absent status would be read as 'confirmed' by any consumer defaulting to the old shape."""

    payload = _report()
    del payload["confirmation_status"]
    with pytest.raises(ValidationError):
        validate("vuln_report", payload)

    with pytest.raises(ValidationError):
        validate("vuln_report", _report(confirmation_status="probably"))
