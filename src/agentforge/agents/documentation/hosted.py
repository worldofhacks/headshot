"""Live report-writer adapter that can emit only a canonical unpublished VulnReport."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from agentforge.agents.documentation.agent import (
    DocumentationAgent,
    DocumentationInput,
    DocumentationInputError,
)
from agentforge.agents.hosted_runtime import (
    HostedCompositionError,
    HostedExecutionLineage,
    HostedRoleRuntime,
    require_safe_model_text,
)

MAX_REPORT_WRITER_REPRODUCTION_STEPS = 8
MAX_REPORT_WRITER_STEP_CHARS = 1_000
_NARRATIVE_FIELDS = (
    "description",
    "clinical_impact",
    "recommended_remediation",
)


class HostedReportWriterError(HostedCompositionError):
    """The report-writer response could not become a safe canonical draft."""

    code = "hosted-report-writer-failed"


@dataclass(frozen=True, slots=True)
class HostedReportWriterResult:
    """One canonical draft-only report plus the durable hosted execution identity."""

    report: Mapping[str, Any]
    execution_id: str
    provider_request_id: str
    lineage: HostedExecutionLineage


class HostedReportWriter:
    """Draft bounded prose live; deterministic code owns report identity and publication state."""

    def __init__(
        self,
        *,
        runtime: HostedRoleRuntime,
        canonical_agent: DocumentationAgent | None = None,
    ) -> None:
        if not isinstance(runtime, HostedRoleRuntime):
            raise HostedReportWriterError("hosted role runtime is unavailable")
        self._runtime = runtime
        self._canonical_agent = canonical_agent or DocumentationAgent()

    def draft(
        self,
        *,
        verdict: Mapping[str, Any],
        report_input: DocumentationInput,
        parent_execution_id: str | None = None,
        parent_request_id: str | None = None,
    ) -> HostedReportWriterResult:
        """Run the model only after confirmed/sanitized validation, then build a canonical draft."""

        try:
            self._canonical_agent.validate_request(
                verdict=verdict,
                report_input=report_input,
            )
        except DocumentationInputError:
            raise
        holder: dict[str, Mapping[str, Any]] = {}

        def validate_draft(raw: Mapping[str, Any]) -> Mapping[str, Any]:
            if set(raw) != set(_NARRATIVE_FIELDS):
                raise HostedReportWriterError("report-writer response has an invalid shape")
            narrative = {
                field: require_safe_model_text(
                    f"report-writer {field}",
                    raw.get(field),
                    maximum=4_000,
                )
                for field in _NARRATIVE_FIELDS
            }
            # IDs, severity/category, exact observed/expected behavior, reproduction, evidence
            # hashes, and publication state remain trusted deterministic fields.
            candidate = replace(
                report_input,
                description=narrative["description"],
                clinical_impact=narrative["clinical_impact"],
                recommended_remediation=narrative["recommended_remediation"],
            )
            try:
                report = self._canonical_agent.draft(
                    verdict=verdict,
                    report_input=candidate,
                )
            except DocumentationInputError as exc:
                raise HostedReportWriterError(
                    "report-writer output failed the canonical draft contract"
                ) from exc
            holder["report"] = report
            return report

        invocation = self._runtime.invoke(
            "documentation",
            input_payload=self._model_input(verdict=verdict, report_input=report_input),
            output_schema=_narrative_schema(),
            schema_name="documentation_narrative",
            parent_execution_id=parent_execution_id,
            parent_request_id=parent_request_id,
            validate_output=validate_draft,
        )
        report = holder.get("report")
        if report is None:
            raise HostedReportWriterError("report-writer draft was not validated")
        return HostedReportWriterResult(
            report=dict(report),
            execution_id=invocation.execution_id,
            provider_request_id=invocation.provider_request_id,
            lineage=invocation.lineage,
        )

    @staticmethod
    def _model_input(
        *,
        verdict: Mapping[str, Any],
        report_input: DocumentationInput,
    ) -> dict[str, Any]:
        reproduction = [
            require_safe_model_text(
                "report-writer reproduction step",
                step[:MAX_REPORT_WRITER_STEP_CHARS],
                maximum=MAX_REPORT_WRITER_STEP_CHARS,
            )
            for step in report_input.minimal_reproduction[:MAX_REPORT_WRITER_REPRODUCTION_STEPS]
        ]
        return {
            "confirmed_verdict": {
                "schema_version": verdict["schema_version"],
                "campaign_run_id": verdict["campaign_run_id"],
                "attempt_id": verdict["attempt_id"],
                "state": verdict["state"],
                "reason_codes": list(verdict["reason_codes"]),
                "confirmation_source": verdict["confirmation_source"],
            },
            "sanitized_report_material": {
                "finding_id": report_input.finding_id,
                "source_case_id": report_input.source_case_id,
                "severity": report_input.severity,
                "category": report_input.category,
                "description": require_safe_model_text(
                    "report-writer description",
                    report_input.description,
                    maximum=4_000,
                ),
                "clinical_impact": require_safe_model_text(
                    "report-writer clinical impact",
                    report_input.clinical_impact,
                    maximum=4_000,
                ),
                "observed_behavior": require_safe_model_text(
                    "report-writer observed behavior",
                    report_input.observed_behavior,
                    maximum=4_000,
                ),
                "expected_behavior": require_safe_model_text(
                    "report-writer expected behavior",
                    report_input.expected_behavior,
                    maximum=4_000,
                ),
                "recommended_remediation": require_safe_model_text(
                    "report-writer recommended remediation",
                    report_input.recommended_remediation,
                    maximum=4_000,
                ),
                "minimal_reproduction": reproduction,
                "omitted_reproduction_step_count": max(
                    0,
                    len(report_input.minimal_reproduction) - MAX_REPORT_WRITER_REPRODUCTION_STEPS,
                ),
                "evidence_references": list(report_input.evidence_references),
                "sanitized": True,
            },
        }


def _narrative_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            field: {"type": "string", "minLength": 1, "maxLength": 4_000}
            for field in _NARRATIVE_FIELDS
        },
        "required": list(_NARRATIVE_FIELDS),
        "additionalProperties": False,
    }


__all__ = [
    "MAX_REPORT_WRITER_REPRODUCTION_STEPS",
    "MAX_REPORT_WRITER_STEP_CHARS",
    "HostedReportWriter",
    "HostedReportWriterError",
    "HostedReportWriterResult",
]
