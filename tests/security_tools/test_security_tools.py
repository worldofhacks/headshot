from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest
from sqlalchemy import Engine, text

from agentforge.security_tools import (
    GarakAdapter,
    GiskardAdapter,
    NormalizationContext,
    PromptfooAdapter,
    PyritAdapter,
    normalize_fixture_findings,
)
from agentforge.security_tools.process import run_bounded_tool
from agentforge.security_tools.repository import SecurityToolEvidenceRepository
from agentforge.security_tools.semgrep import normalize_semgrep
from agentforge.security_tools.zap import (
    ZAP_AMD64_DIGEST,
    ZAP_IMAGE,
    normalize_zap,
    passive_baseline_argv,
    validate_zap_origin,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "security_tools"
HEX64 = "a" * 64


def context(tool_name: str, *, evidence_provenance: str = "scan_only") -> NormalizationContext:
    return NormalizationContext(
        tool_name=tool_name,
        tool_version="fixture-1",
        configuration_sha256=HEX64,
        run_id="scan-run-1",
        run_nonce="0123456789abcdef",
        target_id="agentforge-source",
        surface_id="repository",
        scan_provenance="platform_source",
        observed_at="2026-07-21T12:00:00Z",
        artifact_locator=f"fixture://{tool_name}.json",
        evidence_provenance=evidence_provenance,
    )


@pytest.mark.parametrize(
    ("adapter", "tool", "payload"),
    [
        (
            GarakAdapter(),
            "garak",
            json.dumps(
                {
                    "entry_type": "attempt",
                    "status": 2,
                    "uuid": "a1",
                    "probe_classname": "dan.Dan_11_0",
                    "prompt": {"turns": [{"content": {"text": "synthetic garak candidate"}}]},
                }
            ).encode()
            + b"\n"
            + json.dumps(
                {
                    "entry_type": "eval",
                    "probe": "dan.Dan_11_0",
                    "detector": "dan.DAN",
                    "passed": 0,
                    "total_evaluated": 1,
                }
            ).encode()
            + b"\n",
        ),
        (
            PyritAdapter(),
            "pyrit",
            json.dumps(
                {
                    "converters": [
                        {
                            "name": "Base64Converter",
                            "result": {"output_text": "c3ludGhldGlj", "output_type": "text"},
                        }
                    ],
                    "attack_result": {"outcome": "undetermined"},
                }
            ).encode(),
        ),
        (
            GiskardAdapter(),
            "giskard",
            json.dumps(
                {
                    "scenarios": [
                        {
                            "name": "LLM01 prompt injection",
                            "tags": ["owasp:llm-top-10-2025:LLM01"],
                            "steps": [{"interacts": [{"inputs": "synthetic scenario"}]}],
                        }
                    ],
                    "scan_results": [],
                }
            ).encode(),
        ),
        (
            PromptfooAdapter(),
            "promptfoo",
            json.dumps(
                {
                    "results": {
                        "results": [
                            {
                                "success": True,
                                "testCase": {
                                    "vars": {"prompt": "synthetic promptfoo candidate"},
                                    "metadata": {
                                        "category": "prompt_injection",
                                        "technique": "direct override",
                                        "owasp_mappings": ["LLM01:2025"],
                                    },
                                },
                            }
                        ]
                    }
                }
            ).encode(),
        ),
    ],
)
def test_native_adapter_extracts_bounded_candidates(adapter, tool, payload) -> None:
    imported = adapter.import_artifact(payload, context(tool))

    assert adapter.interface_version == "2"
    assert len(imported.candidates) == 1
    assert imported.artifact_sha256 == hashlib.sha256(payload).hexdigest()
    assert imported.candidates[0].source_artifact_sha256 == imported.artifact_sha256
    assert len(imported.candidates[0].provenance_sha256) == 64
    assert all(
        finding["human_publication_state"] == "blocked_pending_human_approval"
        for finding in imported.findings
    )


def test_native_adapter_rejects_malformed_and_oversized_artifacts() -> None:
    with pytest.raises(ValueError, match="malformed"):
        GarakAdapter().import_artifact(b"{not-json}\n", context("garak"))
    with pytest.raises(ValueError, match="byte cap"):
        PyritAdapter().import_artifact(b"x" * (10 * 1024 * 1024 + 1), context("pyrit"))


def test_garak_deduplicates_candidate_content_and_never_imports_target_output() -> None:
    attempts = []
    for uuid in ("first", "second"):
        attempts.append(
            json.dumps(
                {
                    "entry_type": "attempt",
                    "status": 2,
                    "uuid": uuid,
                    "probe_classname": "dan.Dan_11_0",
                    "prompt": {"turns": [{"content": {"text": "reviewed synthetic input"}}]},
                    "outputs": ["HOSTILE_TARGET_OUTPUT_MUST_NOT_BECOME_INPUT"],
                }
            )
        )
    imported = GarakAdapter().import_artifact(
        ("\n".join(attempts) + "\n").encode(), context("garak")
    )
    assert len(imported.candidates) == 1
    assert imported.candidates[0].input_sequence == ("reviewed synthetic input",)


def test_simulated_artifact_covers_severities_false_positives_and_dispositions() -> None:
    raw = (FIXTURES / "simulated_scan.json").read_bytes()
    findings = normalize_fixture_findings(
        raw, context("simulator", evidence_provenance="simulated")
    )

    assert len(findings) >= 10
    assert {finding["severity"] for finding in findings} == {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }
    assert {finding["disposition"] for finding in findings} >= {
        "validate",
        "remediate",
        "defer",
        "document",
        "false_positive",
    }
    assert sum(finding["disposition"] == "false_positive" for finding in findings) >= 2
    assert {finding["evidence_provenance"] for finding in findings} == {"simulated"}


def test_simulated_triage_artifact_ingests_through_append_only_repository(
    migrated_db: Engine,
) -> None:
    raw = (FIXTURES / "simulated_scan.json").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    normalized = normalize_fixture_findings(
        raw,
        context("simulator", evidence_provenance="simulated"),
    )
    run = {
        "schema_version": "1",
        "run_id": "scan-run-1",
        "tool_name": "simulator",
        "tool_version": "fixture-1",
        "configuration_sha256": HEX64,
        "run_nonce": "0123456789abcdef",
        "target_id": "agentforge-source",
        "surface_id": "repository",
        "scan_provenance": "platform_source",
        "status": "completed",
        "started_at": "2026-07-21T12:00:00Z",
        "finished_at": "2026-07-21T12:00:01Z",
        "artifact_sha256": digest,
    }
    artifact = {
        "schema_version": "1",
        "artifact_id": "simulated-triage-artifact-20260721",
        "run_id": run["run_id"],
        "tool_name": run["tool_name"],
        "tool_version": run["tool_version"],
        "media_type": "application/json",
        "sha256": digest,
        "sanitized": True,
        "byte_length": len(raw),
        "created_at": "2026-07-21T12:00:01Z",
        "artifact_locator": "fixture://simulated_scan.json",
    }
    repository = SecurityToolEvidenceRepository(migrated_db)
    repository.ingest(
        organization_id="org_SecurityToolFixture",
        run=run,
        artifact=artifact,
        sanitized_artifact=raw,
        findings=normalized,
    )

    persisted = repository.findings(organization_id="org_SecurityToolFixture", run_id=run["run_id"])
    assert len(persisted) == 12
    assert {finding["evidence_provenance"] for finding in persisted} == {"simulated"}
    assert {finding["human_publication_state"] for finding in persisted} == {
        "blocked_pending_human_approval"
    }
    with pytest.raises(Exception, match="append-only"), migrated_db.begin() as connection:
        connection.execute(
            text(
                "UPDATE security_tool_findings SET validation_state = 'validated' "
                "WHERE organization_id = 'org_SecurityToolFixture'"
            )
        )


def test_duplicate_external_finding_is_rejected() -> None:
    raw = json.dumps(
        {
            "findings": [
                {
                    "id": "duplicate",
                    "severity": "low",
                    "confidence": 0.5,
                    "owasp_mappings": ["A01:2021"],
                    "summary": "first",
                },
                {
                    "id": "duplicate",
                    "severity": "low",
                    "confidence": 0.5,
                    "owasp_mappings": ["A01:2021"],
                    "summary": "second",
                },
            ]
        }
    ).encode()
    with pytest.raises(ValueError, match="duplicate"):
        normalize_fixture_findings(raw, context("simulator"))


def test_semgrep_parser_binds_normalized_finding_to_original_artifact() -> None:
    raw = json.dumps(
        {
            "results": [
                {
                    "check_id": "agentforge.python.rule",
                    "path": "src/example.py",
                    "start": {"line": 7},
                    "extra": {
                        "message": "unsafe construct",
                        "severity": "ERROR",
                        "metadata": {"owasp": ["A03:2021"], "confidence_score": 0.95},
                    },
                }
            ]
        }
    ).encode()
    findings = normalize_semgrep(raw, context("semgrep"))
    assert findings[0]["raw_artifact_sha256"] == hashlib.sha256(raw).hexdigest()


def test_bounded_subprocess_does_not_inherit_parent_secret(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CLERK_SECRET_KEY", "must-not-cross-boundary")
    result = run_bounded_tool(
        (
            sys.executable,
            "-c",
            "import os; print(os.environ.get('CLERK_SECRET_KEY', 'absent'))",
        ),
        cwd=tmp_path,
        allowed_env={"PATH": os.defpath},
        timeout_s=5,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == b"absent"
    assert b"must-not-cross-boundary" not in result.stderr


def test_bounded_subprocess_rejects_secret_environment_key(tmp_path) -> None:
    with pytest.raises(ValueError, match="not allowed"):
        run_bounded_tool(
            (sys.executable, "-c", "pass"),
            cwd=tmp_path,
            allowed_env={"API_TOKEN": "no"},
        )


def test_zap_scope_is_exact_passive_and_digest_pinned() -> None:
    origin = validate_zap_origin("http://127.0.0.1:8765", profile="local_fake")
    argv = passive_baseline_argv(origin, "zap.json")
    assert origin == "http://127.0.0.1:8765"
    assert ZAP_AMD64_DIGEST in ZAP_IMAGE
    assert "zap-baseline.py" in argv
    assert "zap-full-scan.py" not in argv
    assert "zap-api-scan.py" not in argv


def test_zap_output_has_deterministic_owasp_mapping_and_exact_origin_revalidation() -> None:
    raw = json.dumps(
        {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "40046",
                            "riskcode": "3",
                            "confidence": "3",
                            "alert": "Server Side Request Forgery",
                            "instances": [{"uri": "http://127.0.0.1:8765/api"}],
                        }
                    ]
                }
            ]
        }
    ).encode()
    zap_context = context("zap")
    findings = normalize_zap(raw, zap_context, approved_origin="http://127.0.0.1:8765")
    assert findings[0]["owasp_mappings"] == ["A10:2021"]
    assert findings[0]["raw_artifact_sha256"] == hashlib.sha256(raw).hexdigest()

    escaped = raw.replace(b"127.0.0.1:8765", b"example.com")
    with pytest.raises(ValueError, match="scope escape"):
        normalize_zap(escaped, zap_context, approved_origin="http://127.0.0.1:8765")


@pytest.mark.parametrize(
    "origin",
    [
        "https://clerk.example.com",
        "http://example.com",
        "http://127.0.0.1:8765/admin",
        "http://127.0.0.1:8765?next=https://example.com",
    ],
)
def test_zap_local_fake_scope_rejects_identity_remote_and_non_origin_urls(origin) -> None:
    with pytest.raises(ValueError):
        validate_zap_origin(origin, profile="local_fake")


def test_zap_live_target_requires_separate_exact_authorization() -> None:
    origin = "https://openemr.authorized.example"
    with pytest.raises(ValueError):
        validate_zap_origin(origin, profile="live_target", approved_origin=origin)
    assert (
        validate_zap_origin(
            origin,
            profile="live_target",
            approved_origin=origin,
            authorization_ref="authorization-record-123",
        )
        == origin
    )
