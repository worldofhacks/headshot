"""Reproducible renderer for the simulated 10+-finding triage exercise.

This CLI loads a simulated-scan interchange fixture, normalizes it through the *existing*
:func:`agentforge.security_tools.normalization.normalize_fixture_findings` (never a re-implemented
parser), and prints a human-readable markdown triage table. The output is always banner-marked as
``SIMULATED`` so it can never be mistaken for live target evidence: normalization pins the
``evidence_provenance`` and ``human_publication_state`` fields accordingly.

Regenerate the checked-in report with::

    python -m agentforge.security_tools.triage_cli \\
        tests/fixtures/security_tools/simulated_scan.json > docs/triage/SIMULATED_SCAN_TRIAGE.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agentforge.security_tools.normalization import (
    NormalizationContext,
    normalize_fixture_findings,
)

SIMULATED_BANNER = (
    "SIMULATED SCAN — triage exercise only. These findings are synthetic fixture data, "
    "NEVER real target evidence. Publication stays blocked pending human approval."
)

# One-line triage rationale per disposition. The renderer never invents a verdict: each rationale
# is keyed off the disposition the normalization layer already validated for the finding.
_DISPOSITION_RATIONALE = {
    "validate": (
        "Plausible exploit path; route to Judge for independent confirmation before action."
    ),
    "remediate": "High-confidence exploitable defect; open a fix and re-test after patch.",
    "defer": "Real but low-urgency hardening item; schedule behind higher-severity work.",
    "document": "Observation worth recording for coverage; no immediate exploit to chase.",
    "false_positive": "Scanner artifact refuted on review; reject so it cannot inflate the corpus.",
}

# Explicit false-positive justifications, keyed by the fixture's external finding id. Two synthetic
# findings in the simulated scan are deliberately marked false positive for the exercise.
_FALSE_POSITIVE_JUSTIFICATIONS: dict[str, str] = {
    "sim-010": (
        "Dependency flagged at confidence 0.15 against a version the pinned lockfile never ships; "
        "the vulnerable code path is not reachable in the target, so the alert is a false positive."
    ),
    "sim-012": (
        "Authentication observation duplicates an already-enforced control; manual review confirms "
        "the guard is present and the reported gap does not exist, so the alert is a false "
        "positive."
    ),
}


def _simulation_context() -> NormalizationContext:
    """Deterministic, network-free context marking every finding as simulated fixture data."""
    return NormalizationContext(
        tool_name="simulator",
        tool_version="fixture-1",
        configuration_sha256="0" * 64,
        run_id="simulated-triage-run",
        run_nonce="0123456789abcdef",
        target_id="agentforge-source",
        surface_id="repository",
        scan_provenance="platform_source",
        observed_at="2026-07-21T12:00:00Z",
        artifact_locator="fixture://simulated_scan.json",
        evidence_provenance="simulated",
    )


def _external_ids(raw: bytes) -> list[str]:
    """Read the fixture's external ids in order for display.

    ``normalize_fixture_findings`` hashes the external id into an opaque ``finding_id`` (it is not
    recoverable from the normalized payload), so the human-facing report reads the ids straight from
    the same source bytes. Order is preserved by both the parser and this pass, and duplicate ids
    are already rejected by normalization, so index-alignment is exact.
    """
    return [record["id"] for record in json.loads(raw)["findings"]]


def _rationale(finding: dict[str, Any]) -> str:
    return _DISPOSITION_RATIONALE[finding["disposition"]]


def render_triage_markdown(findings: list[dict[str, Any]], external_ids: list[str]) -> str:
    """Render the normalized findings as a banner-fronted markdown triage report."""
    lines: list[str] = []
    lines.append("# Simulated Scan Triage")
    lines.append("")
    lines.append(f"> **{SIMULATED_BANNER}**")
    lines.append("")
    lines.append(
        f"Reproduce with `python -m agentforge.security_tools.triage_cli "
        f"tests/fixtures/security_tools/simulated_scan.json`. "
        f"{len(findings)} findings normalized through the shared adapter parser "
        f"(`evidence_provenance=simulated`)."
    )
    lines.append("")
    lines.append("| id | severity | OWASP | confidence | disposition | rationale |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for external_id, finding in zip(external_ids, findings, strict=True):
        owasp = ", ".join(finding["owasp_mappings"])
        lines.append(
            f"| {external_id} "
            f"| {finding['severity']} "
            f"| {owasp} "
            f"| {finding['confidence']:.2f} "
            f"| {finding['disposition']} "
            f"| {_rationale(finding)} |"
        )
    lines.append("")
    lines.append("## False-positive justifications")
    lines.append("")
    for external_id, finding in zip(external_ids, findings, strict=True):
        if finding["disposition"] != "false_positive":
            continue
        justification = _FALSE_POSITIVE_JUSTIFICATIONS.get(
            external_id,
            "Refuted on manual review; the reported condition does not hold against the target.",
        )
        lines.append(f"- **{external_id}** — {justification}")
    lines.append("")
    return "\n".join(lines)


def render_report(fixture_path: Path) -> str:
    """Load ``fixture_path``, normalize via the existing parser, and render the markdown report."""
    raw = fixture_path.read_bytes()
    findings = normalize_fixture_findings(raw, _simulation_context())
    return render_triage_markdown(findings, _external_ids(raw))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agentforge.security_tools.triage_cli",
        description="Render a markdown triage table from a simulated-scan fixture.",
    )
    parser.add_argument(
        "fixture",
        type=Path,
        help="path to a simulated-scan interchange fixture (e.g. simulated_scan.json)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = render_report(args.fixture)
    except (OSError, ValueError) as exc:
        print(f"triage-error: {exc}", file=sys.stderr)
        return 1
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
