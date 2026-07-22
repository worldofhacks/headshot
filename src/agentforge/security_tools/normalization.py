"""Normalize scanner output without granting it target-evidence authority.

The adapters deliberately accept a small, documented interchange fixture instead of importing
large scanner SDKs into the platform runtime. A future real execution supplies the same fields
from the pinned tool parser. Every result remains ``scan_only`` (or explicitly ``simulated``),
and publication is always blocked for a human decision.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol

from agentforge.contracts import validate

ADAPTER_INTEGRATION_STATUS = "adapter integrated, execution deferred"
_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_DISPOSITIONS = {"validate", "remediate", "defer", "document", "false_positive"}
_VALIDATION_STATES = {
    "validate": "unvalidated",
    "remediate": "remediated",
    "defer": "deferred",
    "document": "documented",
    "false_positive": "rejected",
}


@dataclass(frozen=True)
class NormalizationContext:
    tool_name: str
    tool_version: str
    configuration_sha256: str
    run_id: str
    run_nonce: str
    target_id: str
    surface_id: str
    scan_provenance: str
    observed_at: str
    artifact_locator: str
    evidence_provenance: str = "scan_only"


class SecurityToolAdapter(Protocol):
    name: str
    interface_version: str

    def parse(self, raw: bytes, context: NormalizationContext) -> list[dict[str, Any]]: ...


def _artifact_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _finding_id(context: NormalizationContext, external_id: str) -> str:
    digest = hashlib.sha256(
        f"{context.tool_name}\0{context.run_id}\0{external_id}".encode()
    ).hexdigest()[:24]
    return f"{context.tool_name}:{digest}"


def normalize_fixture_findings(
    raw: bytes,
    context: NormalizationContext,
    *,
    raw_artifact_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Parse the deterministic adapter interchange format and validate every ToolFinding.

    Fixture format: ``{"findings": [{id, severity, confidence, owasp_mappings, summary,
    disposition}]}``. Unknown fields are ignored at the untrusted parser edge and never copied
    into the normalized contract.
    """
    try:
        decoded = json.loads(raw)
        records = decoded["findings"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("malformed security-tool artifact") from exc
    if not isinstance(records, list):
        raise ValueError("security-tool findings must be an array")

    artifact_sha256 = raw_artifact_sha256 or _artifact_hash(raw)
    normalized: list[dict[str, Any]] = []
    external_ids: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"finding {index} must be an object")
        external_id = record.get("id")
        if not isinstance(external_id, str) or not external_id or len(external_id) > 160:
            raise ValueError(f"finding {index} has an invalid id")
        if external_id in external_ids:
            raise ValueError(f"duplicate external finding id: {external_id}")
        external_ids.add(external_id)

        severity = record.get("severity")
        disposition = record.get("disposition", "validate")
        confidence = record.get("confidence")
        mappings = record.get("owasp_mappings")
        summary = record.get("summary")
        if severity not in _SEVERITIES:
            raise ValueError(f"finding {external_id} has an invalid severity")
        if disposition not in _DISPOSITIONS:
            raise ValueError(f"finding {external_id} has an invalid disposition")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            raise ValueError(f"finding {external_id} has an invalid confidence")
        if not isinstance(mappings, list) or not mappings:
            raise ValueError(f"finding {external_id} has no OWASP mapping")
        if not isinstance(summary, str) or not summary:
            raise ValueError(f"finding {external_id} has no summary")

        payload = {
            "schema_version": "1",
            "finding_id": _finding_id(context, external_id),
            "tool_name": context.tool_name,
            "tool_version": context.tool_version,
            "configuration_sha256": context.configuration_sha256,
            "run_id": context.run_id,
            "run_nonce": context.run_nonce,
            "target_id": context.target_id,
            "surface_id": context.surface_id,
            "scan_provenance": context.scan_provenance,
            "observed_at": context.observed_at,
            "raw_artifact_sha256": artifact_sha256,
            "owasp_mappings": sorted(set(mappings)),
            "severity": severity,
            "confidence": float(confidence),
            "reproduction_evidence": {
                "summary": summary,
                "artifact_locator": f"{context.artifact_locator}#finding={index}",
            },
            "validation_state": _VALIDATION_STATES[disposition],
            "disposition": disposition,
            "human_publication_state": "blocked_pending_human_approval",
            "source_kind": "security_tool",
            "evidence_provenance": context.evidence_provenance,
        }
        validate("tool_finding", payload)
        normalized.append(payload)
    return normalized


class _FixtureAdapter:
    name = ""
    interface_version = "1"

    def parse(self, raw: bytes, context: NormalizationContext) -> list[dict[str, Any]]:
        if context.tool_name != self.name:
            raise ValueError(f"{self.name} adapter cannot normalize {context.tool_name}")
        return normalize_fixture_findings(raw, context)


class GarakAdapter(_FixtureAdapter):
    name = "garak"


class PyritAdapter(_FixtureAdapter):
    name = "pyrit"


class GiskardAdapter(_FixtureAdapter):
    name = "giskard"
