"""Append-only Postgres repository for normalized security-tool evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

from sqlalchemy import Engine, text
from sqlalchemy.exc import IntegrityError

from agentforge.contracts import validate

_ORG_ID = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")


class SecurityToolEvidenceError(ValueError):
    """A tool-evidence batch failed contract, integrity, or provenance checks."""


class SecurityToolEvidenceRepository:
    def __init__(self, engine: Engine) -> None:
        if not isinstance(engine, Engine):
            raise TypeError("security-tool evidence repository requires a SQLAlchemy Engine")
        self._engine = engine

    def ingest(
        self,
        *,
        organization_id: str,
        run: dict[str, Any],
        artifact: dict[str, Any],
        sanitized_artifact: bytes,
        findings: Iterable[dict[str, Any]],
        errors: Iterable[dict[str, Any]] = (),
    ) -> None:
        """Atomically persist one run and its artifact/findings/errors after independent checks."""
        if not _ORG_ID.match(organization_id):
            raise SecurityToolEvidenceError("organization id is invalid")
        validate("security_tool_run", run)
        validate("scan_artifact", artifact)
        finding_rows = list(findings)
        error_rows = list(errors)
        for finding in finding_rows:
            validate("tool_finding", finding)
        for error in error_rows:
            validate("tool_execution_error", error)

        digest = hashlib.sha256(sanitized_artifact).hexdigest()
        if artifact["sha256"] != digest or artifact["byte_length"] != len(sanitized_artifact):
            raise SecurityToolEvidenceError("artifact bytes do not match the declared digest")
        if run["artifact_sha256"] != digest:
            raise SecurityToolEvidenceError("run does not bind the persisted artifact")
        if artifact["run_id"] != run["run_id"]:
            raise SecurityToolEvidenceError("artifact run binding does not match")
        if (
            artifact["tool_name"] != run["tool_name"]
            or artifact["tool_version"] != run["tool_version"]
        ):
            raise SecurityToolEvidenceError("artifact tool binding does not match")

        for finding in finding_rows:
            bound_fields = (
                "run_id",
                "tool_name",
                "tool_version",
                "configuration_sha256",
                "run_nonce",
                "target_id",
                "surface_id",
                "scan_provenance",
            )
            if any(finding[field] != run[field] for field in bound_fields):
                raise SecurityToolEvidenceError("finding binding does not match its run")
            if finding["raw_artifact_sha256"] != digest:
                raise SecurityToolEvidenceError("finding does not bind the persisted artifact")
            if (
                finding["source_kind"] != "security_tool"
                or finding["human_publication_state"] != "blocked_pending_human_approval"
            ):
                raise SecurityToolEvidenceError(
                    "scanner output cannot assert publication authority"
                )
        for error in error_rows:
            if any(error[field] != run[field] for field in ("run_id", "tool_name", "tool_version")):
                raise SecurityToolEvidenceError("tool error binding does not match its run")

        try:
            with self._engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO security_tool_runs "
                        "(organization_id, run_id, tool_name, tool_version, configuration_sha256, "
                        "run_nonce, target_id, surface_id, scan_provenance, status, started_at, "
                        "finished_at, artifact_sha256) VALUES "
                        "(:org, :run_id, :tool_name, :tool_version, :configuration_sha256, "
                        ":run_nonce, :target_id, :surface_id, :scan_provenance, :status, "
                        ":started_at, :finished_at, :artifact_sha256)"
                    ),
                    {"org": organization_id, **run},
                )
                connection.execute(
                    text(
                        "INSERT INTO scan_artifacts "
                        "(organization_id, artifact_id, run_id, sha256, media_type, byte_length, "
                        "artifact_locator, sanitized_payload, contract_payload) VALUES "
                        "(:org, :artifact_id, :run_id, :sha256, :media_type, :byte_length, "
                        ":artifact_locator, :sanitized_payload, CAST(:contract_payload AS jsonb))"
                    ),
                    {
                        "org": organization_id,
                        **artifact,
                        "sanitized_payload": sanitized_artifact,
                        "contract_payload": json.dumps(artifact, sort_keys=True),
                    },
                )
                for finding in finding_rows:
                    connection.execute(
                        text(
                            "INSERT INTO security_tool_findings "
                            "(organization_id, finding_id, run_id, raw_artifact_sha256, "
                            "validation_state, human_publication_state, evidence_provenance, "
                            "contract_payload) VALUES "
                            "(:org, :finding_id, :run_id, :raw_artifact_sha256, "
                            ":validation_state, :human_publication_state, :evidence_provenance, "
                            "CAST(:contract_payload AS jsonb))"
                        ),
                        {
                            "org": organization_id,
                            **finding,
                            "contract_payload": json.dumps(finding, sort_keys=True),
                        },
                    )
                for error in error_rows:
                    connection.execute(
                        text(
                            "INSERT INTO tool_execution_errors "
                            "(organization_id, error_id, run_id, code, contract_payload) VALUES "
                            "(:org, :error_id, :run_id, :code, CAST(:contract_payload AS jsonb))"
                        ),
                        {
                            "org": organization_id,
                            **error,
                            "contract_payload": json.dumps(error, sort_keys=True),
                        },
                    )
        except IntegrityError as exc:
            raise SecurityToolEvidenceError(
                "security-tool evidence conflicts with persisted data"
            ) from exc

    def findings(self, *, organization_id: str, run_id: str) -> list[dict[str, Any]]:
        if not _ORG_ID.match(organization_id):
            raise SecurityToolEvidenceError("organization id is invalid")
        with self._engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        "SELECT contract_payload FROM security_tool_findings "
                        "WHERE organization_id = :org AND run_id = :run "
                        "ORDER BY finding_id"
                    ),
                    {"org": organization_id, "run": run_id},
                )
                .scalars()
                .all()
            )
        findings = [dict(row) for row in rows]
        for finding in findings:
            validate("tool_finding", finding)
        return findings
