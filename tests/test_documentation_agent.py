"""Documentation Agent trust-boundary and data-quality tests.

The agent may draft only from a schema-valid confirmed verdict plus explicitly sanitized,
approved evidence references.  It never receives a raw transcript and never publishes.
"""

from __future__ import annotations

import copy

import pytest

from agentforge.agents.documentation import (
    DocumentationAgent,
    DocumentationInput,
    DocumentationInputError,
    DuplicateReproductionError,
)
from agentforge.contracts import is_valid

HEX64 = "a" * 64


def _verdict(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1",
        "campaign_run_id": "run-doc-1",
        "attempt_id": "attempt-doc-1",
        "state": "EXPLOIT_CONFIRMED",
        "confidence": 1.0,
        "reason_codes": ["canary_hit"],
        "confirmation_source": "canary",
    }
    payload.update(updates)
    return payload


def _request(**updates: object) -> DocumentationInput:
    values: dict[str, object] = {
        "organization_id": "org-doc-1",
        "finding_id": "finding-doc-1",
        "campaign_run_id": "run-doc-1",
        "attempt_id": "attempt-doc-1",
        "source_case_id": "AF-M11-DX-001",
        "severity": "critical",
        "category": "data_exfiltration",
        "description": "A patient-scoped request crossed the retrieval boundary.",
        "clinical_impact": "Synthetic cross-patient disclosure models a confidentiality failure.",
        "minimal_reproduction": (
            "Launch the reviewed synthetic alpha-patient fixture.",
            "Submit the sanitized cross-patient retrieval case AF-M11-DX-001.",
            "Verify the trusted canary detector records the boundary violation.",
        ),
        "observed_behavior": "A trusted canary detector confirmed cross-scope content.",
        "expected_behavior": "Retrieval remains inside the authorized patient scope.",
        "recommended_remediation": "Enforce patient scope before retrieval and after ranking.",
        "evidence_references": (f"evidence://sha256/{HEX64}",),
        "sanitized": True,
    }
    values.update(updates)
    return DocumentationInput(**values)  # type: ignore[arg-type]


def test_confirmed_verdict_produces_contract_valid_reproducible_draft() -> None:
    agent = DocumentationAgent()

    report = agent.draft(verdict=_verdict(), report_input=_request())

    assert is_valid("vuln_report", report)
    assert report["finding_id"] == "finding-doc-1"
    assert report["status"] == "draft"
    assert report["fix_validation"]["state"] == "not_run"
    assert report["publication_state"] == "blocked_pending_human_approval"
    assert report["reproduction_sha256"]
    assert "transcript" not in report


def test_draft_is_idempotent_for_the_same_finding_and_reproduction() -> None:
    agent = DocumentationAgent()

    first = agent.draft(verdict=_verdict(), report_input=_request())
    second = agent.draft(verdict=_verdict(), report_input=_request())

    assert first == second


def test_content_addressed_finding_identifier_is_not_misclassified_as_a_secret() -> None:
    report = DocumentationAgent().draft(
        verdict=_verdict(),
        report_input=_request(finding_id="c" * 64),
    )

    assert report["finding_id"] == "c" * 64


@pytest.mark.parametrize(
    "state,source",
    [
        ("EXPLOIT_LIKELY", "calibrated_model"),
        ("NO_EXPLOIT_OBSERVED", "calibrated_model"),
        ("INDETERMINATE", None),
        ("ERROR", None),
    ],
)
def test_non_confirmed_verdict_never_produces_a_report(state: str, source: str | None) -> None:
    verdict = _verdict(state=state, confidence=0.5)
    if source is None:
        verdict.pop("confirmation_source", None)
    else:
        verdict["confirmation_source"] = source
    if state == "ERROR":
        verdict["error_code"] = "evidence-integrity-failed"
        verdict["reason_codes"] = ["evidence_integrity_failed"]
    elif state == "INDETERMINATE":
        verdict["reason_codes"] = ["non_oracle_uncalibrated_indeterminate"]
    elif state == "EXPLOIT_LIKELY":
        verdict["reason_codes"] = ["calibrated_positive"]
    else:
        verdict["reason_codes"] = ["calibrated_negative"]

    with pytest.raises(DocumentationInputError, match="confirmed"):
        DocumentationAgent().draft(verdict=verdict, report_input=_request())


def test_schema_invalid_verdict_fails_closed() -> None:
    verdict = _verdict()
    verdict["unexpected"] = "field"

    with pytest.raises(DocumentationInputError, match="verdict contract"):
        DocumentationAgent().draft(verdict=verdict, report_input=_request())


def test_correlation_mismatch_fails_closed() -> None:
    with pytest.raises(DocumentationInputError, match="correlation"):
        DocumentationAgent().draft(
            verdict=_verdict(),
            report_input=_request(attempt_id="different-attempt"),
        )


def test_unsanitized_or_unreferenced_evidence_is_rejected() -> None:
    agent = DocumentationAgent()

    with pytest.raises(DocumentationInputError, match="sanitized"):
        agent.draft(verdict=_verdict(), report_input=_request(sanitized=False))
    with pytest.raises(DocumentationInputError, match="evidence reference"):
        agent.draft(verdict=_verdict(), report_input=_request(evidence_references=()))
    with pytest.raises(DocumentationInputError, match="evidence reference"):
        agent.draft(
            verdict=_verdict(),
            report_input=_request(evidence_references=("/tmp/raw-transcript.json",)),
        )


def test_critical_draft_cannot_claim_approval_or_publication() -> None:
    report = DocumentationAgent().draft(verdict=_verdict(), report_input=_request())

    approved = copy.deepcopy(report)
    approved["publication_state"] = "published"
    assert not is_valid("vuln_report", approved)


def test_duplicate_reproduction_cannot_be_laundered_as_a_new_finding() -> None:
    agent = DocumentationAgent()
    agent.draft(verdict=_verdict(), report_input=_request())

    with pytest.raises(DuplicateReproductionError, match="duplicate reproduction"):
        agent.draft(
            verdict=_verdict(),
            report_input=_request(finding_id="finding-doc-2"),
        )


def test_duplicate_reproduction_index_is_isolated_by_organization() -> None:
    agent = DocumentationAgent()
    first = agent.draft(verdict=_verdict(), report_input=_request())

    second = agent.draft(
        verdict=_verdict(),
        report_input=_request(
            organization_id="org-doc-2",
            finding_id="finding-doc-2",
        ),
    )

    assert first["reproduction_sha256"] == second["reproduction_sha256"]
    assert first["finding_id"] != second["finding_id"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("description", ""),
        ("clinical_impact", ""),
        ("minimal_reproduction", ()),
        ("observed_behavior", ""),
        ("expected_behavior", ""),
        ("recommended_remediation", ""),
    ],
)
def test_required_report_content_is_rejected_before_contract_emission(
    field: str, value: object
) -> None:
    with pytest.raises(DocumentationInputError):
        DocumentationAgent().draft(
            verdict=_verdict(),
            report_input=_request(**{field: value}),
        )
