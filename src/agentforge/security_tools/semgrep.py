"""Parser for pinned Semgrep JSON output."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agentforge.security_tools.normalization import NormalizationContext, normalize_fixture_findings

_SEVERITY = {"INFO": "info", "WARNING": "medium", "ERROR": "high"}


def normalize_semgrep(raw: bytes, context: NormalizationContext) -> list[dict[str, Any]]:
    try:
        document = json.loads(raw)
        results = document["results"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("malformed Semgrep JSON artifact") from exc
    if not isinstance(results, list):
        raise ValueError("Semgrep results must be an array")
    findings = []
    for index, result in enumerate(results):
        try:
            metadata = result["extra"].get("metadata", {})
            mappings = metadata["owasp"]
            findings.append(
                {
                    "id": f"{result['check_id']}:{result['path']}:{result['start']['line']}",
                    "severity": _SEVERITY[result["extra"]["severity"]],
                    "confidence": float(metadata.get("confidence_score", 0.8)),
                    "owasp_mappings": mappings,
                    "summary": result["extra"]["message"],
                    "disposition": "validate",
                }
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"malformed Semgrep result at index {index}") from exc
    return normalize_fixture_findings(
        json.dumps({"findings": findings}, sort_keys=True, separators=(",", ":")).encode(),
        context,
        raw_artifact_sha256=hashlib.sha256(raw).hexdigest(),
    )
