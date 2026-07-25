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
