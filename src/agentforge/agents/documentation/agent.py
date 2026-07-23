"""Fail-closed Documentation Agent for structured vulnerability-report drafts.

This boundary consumes only a schema-valid, deterministically/human-confirmed Judge Verdict and
an explicitly sanitized structured input whose evidence references are content-addressed.  It
never accepts a raw transcript, never has target credentials, and cannot publish.  The v1 output
contract therefore has no published state; publication must cross the separate human gate.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentforge.contracts import validate
from agentforge.secrets import looks_like_provider_key

_EVIDENCE_REFERENCE_RE = re.compile(r"\Aevidence://sha256/[0-9a-f]{64}\Z")
_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
_MAX_TEXT = 4_000
_MAX_STEPS = 32
_MAX_REFERENCES = 32


class DocumentationInputError(ValueError):
    """The trusted Documentation boundary rejected malformed or unsafe input."""


class DuplicateReproductionError(DocumentationInputError):
    """A reproduction sequence already belongs to a different finding."""


@dataclass(frozen=True, slots=True)
class DocumentationInput:
    """Sanitized, structured material approved for report drafting.

    ``sanitized`` is an explicit trust label supplied by the trusted caller after it removes
    secrets/raw evidence.  The narrow type deliberately exposes no transcript field.  Content is
    bounded again inside :class:`DocumentationAgent`; evidence can only be addressed by SHA-256.
    """

    organization_id: str
    finding_id: str
    campaign_run_id: str
    attempt_id: str
    source_case_id: str
    severity: str
    category: str
    description: str
    clinical_impact: str
    minimal_reproduction: tuple[str, ...]
    observed_behavior: str
    expected_behavior: str
    recommended_remediation: str
    evidence_references: tuple[str, ...]
    sanitized: bool


class DocumentationAgent:
    """Create deterministic, schema-validated drafts and reject duplicate reproductions.

    The in-process indexes make retries idempotent and pin the data-quality behavior.  Durable
    uniqueness remains a storage-boundary responsibility; this class never claims that an
    in-memory index is a multi-process system of record.
    """

    def __init__(self) -> None:
        self._reports_by_id: dict[tuple[str, str], dict[str, Any]] = {}
        self._finding_by_reproduction: dict[tuple[str, str], str] = {}

    def draft(
        self,
        *,
        verdict: Mapping[str, Any],
        report_input: DocumentationInput,
    ) -> dict[str, Any]:
        """Return a draft-only ``VulnReport`` or fail closed without emitting a payload."""

        self._validate_verdict(verdict)
        self._validate_input(report_input)
        if (
            verdict["campaign_run_id"] != report_input.campaign_run_id
            or verdict["attempt_id"] != report_input.attempt_id
        ):
            raise DocumentationInputError("verdict/report correlation mismatch; refusing to draft")

        steps = tuple(
            self._bounded_text("minimal reproduction", step)
            for step in report_input.minimal_reproduction
        )
        reproduction_sha256 = self._reproduction_sha256(steps)
        reproduction_key = (report_input.organization_id, reproduction_sha256)
        prior_finding = self._finding_by_reproduction.get(reproduction_key)
        if prior_finding is not None and prior_finding != report_input.finding_id:
            raise DuplicateReproductionError(
                "duplicate reproduction sequence already belongs to another finding"
            )

        report_id = self._report_id(report_input.finding_id)
        report_key = (report_input.organization_id, report_id)
        report: dict[str, Any] = {
            "schema_version": "1",
            "report_id": report_id,
            "finding_id": report_input.finding_id,
            "campaign_run_id": report_input.campaign_run_id,
            "attempt_id": report_input.attempt_id,
            "source_case_id": report_input.source_case_id,
            "severity": report_input.severity,
            "category": report_input.category,
            "description": report_input.description,
            "clinical_impact": report_input.clinical_impact,
            "minimal_reproduction": list(steps),
            "reproduction_sha256": reproduction_sha256,
            "observed_behavior": report_input.observed_behavior,
            "expected_behavior": report_input.expected_behavior,
            "recommended_remediation": report_input.recommended_remediation,
            "status": "draft",
            "fix_validation": {
                "state": "not_run",
                "summary": "No remediation has been validated.",
                "evidence_references": [],
            },
            "evidence_references": list(report_input.evidence_references),
            "publication_state": (
                "blocked_pending_human_approval"
                if report_input.severity == "critical"
                else "draft_unpublished"
            ),
        }
        try:
            validate("vuln_report", report)
        except Exception as exc:
            raise DocumentationInputError(
                f"Documentation Agent produced an invalid VulnReport: {exc}"
            ) from exc

        previous = self._reports_by_id.get(report_key)
        if previous is not None:
            if previous != report:
                raise DocumentationInputError(
                    "report id already exists with different content; refusing overwrite"
                )
            return copy.deepcopy(previous)
        self._reports_by_id[report_key] = copy.deepcopy(report)
        self._finding_by_reproduction[reproduction_key] = report_input.finding_id
        return copy.deepcopy(report)

    @staticmethod
    def _validate_verdict(verdict: Mapping[str, Any]) -> None:
        try:
            candidate = dict(verdict)
            validate("verdict", candidate)
        except Exception as exc:
            raise DocumentationInputError(
                f"input fails the verdict contract; refusing to draft: {exc}"
            ) from exc
        if candidate["state"] != "EXPLOIT_CONFIRMED":
            raise DocumentationInputError("only a confirmed exploit may enter Documentation")
        if candidate.get("confirmation_source") not in {"oracle", "canary", "human"}:
            raise DocumentationInputError("confirmed verdict lacks a trusted confirmation source")

    @classmethod
    def _validate_input(cls, value: DocumentationInput) -> None:
        if not isinstance(value, DocumentationInput):
            raise DocumentationInputError("report input must use DocumentationInput")
        if value.sanitized is not True:
            raise DocumentationInputError(
                "report input is not explicitly sanitized; raw evidence is refused"
            )
        cls._bounded_text("organization id", value.organization_id, maximum=64, screen_secret=False)
        cls._bounded_text("finding id", value.finding_id, maximum=160, screen_secret=False)
        cls._bounded_text(
            "campaign run id", value.campaign_run_id, maximum=128, screen_secret=False
        )
        cls._bounded_text("attempt id", value.attempt_id, maximum=128, screen_secret=False)
        cls._bounded_text("source case id", value.source_case_id, maximum=120, screen_secret=False)
        cls._bounded_text("category", value.category, maximum=120, screen_secret=False)
        for field, text in (
            ("description", value.description),
            ("clinical impact", value.clinical_impact),
            ("observed behavior", value.observed_behavior),
            ("expected behavior", value.expected_behavior),
            ("recommended remediation", value.recommended_remediation),
        ):
            cls._bounded_text(field, text)
        if value.severity not in _SEVERITIES:
            raise DocumentationInputError("severity is outside the VulnReport taxonomy")
        if not isinstance(value.minimal_reproduction, tuple) or not (
            1 <= len(value.minimal_reproduction) <= _MAX_STEPS
        ):
            raise DocumentationInputError(
                "minimal reproduction must contain 1 to 32 sanitized steps"
            )
        if not isinstance(value.evidence_references, tuple) or not (
            1 <= len(value.evidence_references) <= _MAX_REFERENCES
        ):
            raise DocumentationInputError("at least one approved evidence reference is required")
        if len(set(value.evidence_references)) != len(value.evidence_references):
            raise DocumentationInputError("evidence references must be unique")
        if any(
            not isinstance(reference, str) or not _EVIDENCE_REFERENCE_RE.fullmatch(reference)
            for reference in value.evidence_references
        ):
            raise DocumentationInputError(
                "evidence reference must be a content-addressed evidence://sha256 URI"
            )

    @staticmethod
    def _bounded_text(
        label: str,
        value: str,
        *,
        maximum: int = _MAX_TEXT,
        screen_secret: bool = True,
    ) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise DocumentationInputError(
                f"{label} must be a non-empty string no longer than {maximum} characters"
            )
        if "\x00" in value or (screen_secret and looks_like_provider_key(value.strip())):
            raise DocumentationInputError(f"{label} contains prohibited raw secret material")
        return value

    @staticmethod
    def _reproduction_sha256(steps: tuple[str, ...]) -> str:
        canonical = json.dumps(
            list(steps), allow_nan=False, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _report_id(finding_id: str) -> str:
        digest = hashlib.sha256(f"vuln-report:v1\0{finding_id}".encode()).hexdigest()
        return f"VR-{digest}"
