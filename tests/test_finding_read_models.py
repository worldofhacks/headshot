"""Finding read contracts bind integrity labels to real SHA-256 evidence identities."""

from __future__ import annotations

import datetime
from typing import Any

import pytest
from pydantic import ValidationError

from agentforge.api.read_models import FindingReadModel

_NOW = datetime.datetime(2026, 7, 24, tzinfo=datetime.UTC)


def _finding(**overrides: Any) -> FindingReadModel:
    values: dict[str, Any] = {
        "finding_id": "finding-1",
        "state": "confirmed",
        "severity": "high",
        "category": "prompt_injection",
        "target_version": "1.0.0",
        "publication_status": "gated",
        "evidence_integrity": "verified",
        "source_kind": "campaign",
        "execution_profile": "live",
        "evidence_provenance": "live_target",
        "campaign_run_id": "run-1",
        "attempt_id": "attempt-1",
        "evidence_content_hash": "a" * 64,
        "history": (
            {
                "decision": "confirmed",
                "actor_user_id": "judge-1",
                "rationale": "Bound evidence satisfied the deterministic oracle.",
                "reason_code": None,
                "created_at": _NOW,
            },
        ),
    }
    values.update(overrides)
    return FindingReadModel(**values)


def test_verified_finding_requires_lowercase_sha256() -> None:
    finding = _finding()

    assert finding.evidence_content_hash == "a" * 64
    assert finding.evidence_integrity == "verified"


def test_unavailable_finding_requires_null_hash() -> None:
    finding = _finding(evidence_integrity="unavailable", evidence_content_hash=None)

    assert finding.evidence_content_hash is None
    assert finding.evidence_integrity == "unavailable"


def test_finding_history_accepts_only_the_closed_reason_code_vocabulary() -> None:
    finding = _finding(
        history=(
            {
                "decision": "rejected",
                "actor_user_id": "user-approver",
                "rationale": "The reviewed behavior does not establish an exploit.",
                "reason_code": "not_a_real_exploit",
                "created_at": _NOW,
            },
        )
    )

    assert finding.history[0].reason_code == "not_a_real_exploit"
    with pytest.raises(ValidationError):
        _finding(
            history=(
                {
                    "decision": "rejected",
                    "actor_user_id": "user-approver",
                    "rationale": "Unknown structured code.",
                    "reason_code": "open_ended_code",
                    "created_at": _NOW,
                },
            )
        )


@pytest.mark.parametrize(
    ("decision", "reason_code"),
    (
        ("approved", "not_a_real_exploit"),
        ("rejected", "human_confirmed"),
        ("resolved", "human_confirmed"),
        ("resolved", "duplicate_finding"),
    ),
)
def test_finding_history_rejects_decision_reason_mismatch(
    decision: str,
    reason_code: str,
) -> None:
    with pytest.raises(ValidationError):
        _finding(
            history=(
                {
                    "decision": decision,
                    "actor_user_id": "user-approver",
                    "rationale": "The code must match the recorded decision.",
                    "reason_code": reason_code,
                    "created_at": _NOW,
                },
            )
        )


@pytest.mark.parametrize("decision", ("approved", "rejected", "resolved", "confirmed"))
def test_finding_history_keeps_legacy_null_reason_readable(decision: str) -> None:
    finding = _finding(
        history=(
            {
                "decision": decision,
                "actor_user_id": "user-approver",
                "rationale": "Legacy row created before structured review codes were required.",
                "reason_code": None,
                "created_at": _NOW,
            },
        )
    )

    assert finding.history[0].reason_code is None


@pytest.mark.parametrize(
    ("integrity", "content_hash"),
    (
        ("verified", None),
        ("verified", "a" * 63),
        ("verified", "A" * 64),
        ("verified", "g" * 64),
        ("unavailable", "a" * 64),
    ),
)
def test_finding_rejects_mislabeled_integrity_binding(
    integrity: str,
    content_hash: str | None,
) -> None:
    with pytest.raises(ValidationError):
        _finding(evidence_integrity=integrity, evidence_content_hash=content_hash)
