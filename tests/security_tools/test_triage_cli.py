from __future__ import annotations

import re
from pathlib import Path

from agentforge.security_tools.normalization import _DISPOSITIONS
from agentforge.security_tools.triage_cli import (
    SIMULATED_BANNER,
    main,
    render_report,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "security_tools" / "simulated_scan.json"

# Markdown table body rows look like: | sim-001 | critical | A01:2021 | 0.98 | remediate | … |
_ROW = re.compile(
    r"^\| (?P<id>[^|]+?) \| (?P<severity>[^|]+?) \| (?P<owasp>[^|]+?) \| "
    r"(?P<confidence>[^|]+?) \| (?P<disposition>[^|]+?) \| (?P<rationale>.+?) \|$"
)


def _table_rows(report: str) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for line in report.splitlines():
        match = _ROW.match(line)
        # Skip the header row and the |---| separator row.
        if match is None or match.group("id") in {"id"} or set(match.group("id")) == {"-"}:
            continue
        matches.append(match)
    return matches


def test_renderer_emits_at_least_ten_findings() -> None:
    rows = _table_rows(render_report(FIXTURE))
    assert len(rows) >= 10
    # Every row carries a real fixture id, a nonempty OWASP mapping, and a one-line rationale.
    for row in rows:
        assert row.group("id").strip()
        assert row.group("owasp").strip()
        assert row.group("rationale").strip()


def test_renderer_covers_all_four_severity_buckets() -> None:
    rows = _table_rows(render_report(FIXTURE))
    severities = {row.group("severity").strip() for row in rows}
    assert {"critical", "high", "medium", "low", "info"} <= severities


def test_every_row_carries_exactly_one_valid_disposition() -> None:
    rows = _table_rows(render_report(FIXTURE))
    dispositions = [row.group("disposition").strip() for row in rows]
    assert dispositions, "expected at least one triaged finding"
    for disposition in dispositions:
        assert disposition in _DISPOSITIONS


def test_report_includes_false_positive_disposition_with_justifications() -> None:
    report = render_report(FIXTURE)
    rows = _table_rows(report)
    false_positive_ids = [
        row.group("id").strip()
        for row in rows
        if row.group("disposition").strip() == "false_positive"
    ]
    assert len(false_positive_ids) >= 1
    # The dedicated section must justify each false positive by its fixture id, and the
    # justifications must be concrete (not the generic fallback line).
    assert "## False-positive justifications" in report
    for finding_id in false_positive_ids:
        assert re.search(rf"^- \*\*{re.escape(finding_id)}\*\* — .+", report, re.MULTILINE)
    assert report.count("- **sim-") >= 2


def test_simulated_banner_is_present() -> None:
    report = render_report(FIXTURE)
    assert SIMULATED_BANNER in report
    assert "SIMULATED SCAN" in report
    # It leads the document so no reader mistakes synthetic data for live target evidence.
    banner_index = report.index("SIMULATED SCAN")
    assert banner_index < report.index("| id |")


def test_main_prints_report_and_returns_zero(capsys) -> None:
    exit_code = main([str(FIXTURE)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert SIMULATED_BANNER in captured.out
    assert len(_table_rows(captured.out)) >= 10


def test_main_reports_missing_fixture_without_traceback(capsys, tmp_path) -> None:
    exit_code = main([str(tmp_path / "does-not-exist.json")])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "triage-error" in captured.err
