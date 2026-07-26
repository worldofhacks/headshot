from __future__ import annotations

import csv
import hashlib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_required_submission_packet_is_present_and_pre_release() -> None:
    required = (
        ROOT / "SUBMISSION.md",
        ROOT / "docs/evidence/ato/README.md",
        ROOT / "docs/evidence/ato/SAMPLE_INCIDENT_POSTMORTEM.md",
        ROOT / "docs/submission-artifacts/RELEASE_BINDING.md",
        ROOT / "docs/submission-artifacts/COST_INPUTS.md",
        ROOT / "docs/submission-artifacts/SOCIAL_POST_DRAFT.md",
    )
    assert all(path.is_file() for path in required)

    binding = (ROOT / "docs/submission-artifacts/RELEASE_BINDING.md").read_text()
    assert "Final release SHA" in binding
    assert "`pending`" in binding
    assert "f39e22722d3b4e256110ac5be5ce160a0ad654e4" in binding
    assert "is not the shipped SHA" in binding


def test_publication_prose_does_not_claim_autonomous_report_authorship() -> None:
    reports = sorted((ROOT / "docs/vulnerabilities").glob("AF-VULN-2026-0724-00[1-3]-*.md"))
    assert len(reports) == 3
    for report in reports:
        text = report.read_text()
        assert "Drafted autonomously" not in text
        assert "Human-authored" in text


def test_owasp_matrix_labels_mapping_not_demonstrated_coverage() -> None:
    text = (ROOT / "docs/evidence/OWASP_COVERAGE_MATRIX.md").read_text()
    assert "Mapped is not covered" in " ".join(text.split())
    assert "Mapped by authored seed?" in text
    assert "| Covered? |" not in text


def test_requirements_csv_status_totals_match_pre_release_summary() -> None:
    with (ROOT / "docs/requirements/REQUIREMENTS_MATRIX.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 72
    counts = Counter(row["status"] for row in rows)
    assert counts == {
        "complete": 21,
        "partial": 42,
        "missing": 2,
        "blocked": 7,
    }


def test_ato_manifest_matches_packet_bytes() -> None:
    manifest = ROOT / "docs/evidence/ato/manifest.sha256"
    entries = manifest.read_text().splitlines()
    assert len(entries) == 9

    for entry in entries:
        expected, relative_path = entry.split("  ", maxsplit=1)
        packet_file = ROOT / relative_path
        assert packet_file.is_file()
        assert hashlib.sha256(packet_file.read_bytes()).hexdigest() == expected


def test_final_hosted_campaign_calibration_chain_is_fail_closed() -> None:
    architecture = (ROOT / "ARCHITECTURE.md").read_text()
    demo = (ROOT / "docs/demo/MVP_DEMO_SCRIPT.md").read_text()
    requirements = (ROOT / "docs/requirements/REQUIREMENTS_MATRIX.csv").read_text()
    binding = (ROOT / "docs/submission-artifacts/RELEASE_BINDING.md").read_text()
    combined = "\n".join((architecture, demo, requirements, binding))

    for required in (
        "resource_id",
        "configuration_sha256",
        "OpenRouter",
        "Langfuse",
        "Judge identity/hash",
        "human-enable",
        "blocks campaign launch",
    ):
        assert required in combined

    forbidden = (
        "calibration failure must not block a campaign",
        "does not block the campaign",
        "advisory and does not block the campaign",
    )
    assert all(claim not in combined.lower() for claim in forbidden)


def test_every_finding_report_publication_is_human_gated() -> None:
    publication_sources = (
        ROOT / "AGENTS.md",
        ROOT / "CLAUDE.md",
        ROOT / "ARCHITECTURE.md",
        ROOT / "README.md",
        ROOT / "USERS.md",
        ROOT / "docs/defense/DEFENSE_SCRIPT.md",
        ROOT / "docs/demo/MVP_DEMO_SCRIPT.md",
        ROOT / "docs/evidence/ato/AUTHORIZATION_MODEL.md",
        ROOT / "docs/planning/ARCHITECTURE_DRAFT.md",
        ROOT / "docs/planning/PRESEARCH.md",
        ROOT / "docs/planning/red-team-gap-swarm/WP-19A-SECURITY-REPORTING.md",
        ROOT / "docs/planning/red-team-gap-swarm/WP-21D-LIVE-WEB-BURP.md",
        ROOT / "docs/requirements/REQUIREMENTS_MATRIX.md",
        ROOT / "docs/requirements/REQUIREMENTS_MATRIX.csv",
    )
    combined = "\n".join(path.read_text().lower() for path in publication_sources)

    assert "every finding/report" in combined
    assert "regardless of severity" in combined
    for critical_only in (
        "critical publish",
        "publish a critical",
        "publishing critical",
        "critical publication",
        "critical-severity finding",
    ):
        assert critical_only not in combined

    report_boundary = (ROOT / "docs/vulnerabilities/README.md").read_text()
    documentation_prompt = (ROOT / "src/agentforge/agents/prompts/v1/documentation.txt").read_text()
    assert "Every severity is draft-only and unpublished" in report_boundary
    assert "You must not publish or remediate." in documentation_prompt


def test_historical_trace_states_transcript_storage_boundary() -> None:
    trace = (ROOT / "docs/evidence/agent-trace.md").read_text()
    assert "Full transcripts persist in quarantined PostgreSQL evidence" in trace
    assert "excluded from the retained summary manifests and Langfuse projection" in trace
    assert "Raw payloads are never persisted" not in trace


def test_spoken_material_uses_current_models_and_orchestration() -> None:
    defense = (ROOT / "docs/defense/DEFENSE_SCRIPT.md").read_text()
    architecture = (ROOT / "ARCHITECTURE.md").read_text()
    handoff = (ROOT / "docs/planning/CLAUDE_CODE_HANDOFF.md").read_text()

    for stale in (
        "claude-sonnet",
        "local 24",
        "selected by measured calibration",
        "shares no model, no provider",
        "postgres pitr",
    ):
        assert stale not in defense.lower()
    assert "Pin the LangGraph" not in architecture
    assert "LangGraph checkpoints" not in architecture
    assert "Pin the LangGraph" not in handoff
    assert "LangGraph OSS engine + PostgresSaver" not in handoff
