# WP-19A — Produce evidence-bound executive and technical reports

**Branch:** `rtg/wp19a-security-reporting`

**Model:** capable

**Depends on:** WP-09, WP-10, WP-11, WP-16A, WP-17

**Implements toward (live validation pending):** reporting portion of RT-06

Read finding/publication workflows, evidence status/coverage, workbench artifacts, the
human approval requirements, current report exports, and RT-06.

**Implementation writes only**

- `src/agentforge/reporting/__init__.py`
- `src/agentforge/reporting/security_report.py`
- `src/agentforge/reporting/templates/**`
- `src/agentforge/contracts/v1/security_report_manifest.json`
- `scripts/render_security_report_pdf.mjs`
- `docs/security/SECURITY_REPORTING.md`

**Test writes only**

- `tests/reporting/test_security_report.py`
- `tests/reporting/test_security_report_security.py`
- `tests/reporting/test_security_report_pdf.py`
- `tests/vectors/reporting/**`

## Required result

Create deterministic, content-addressed JSON plus self-contained static HTML executive and
technical report drafts. Implement a no-network PDF renderer using the repository's pinned,
already-installed Playwright/Chromium and the exact frozen HTML/manifest; strip unstable
metadata and bind the PDF hash. If the pinned browser is unavailable without a download,
keep PDF state `blocked_renderer_unavailable` rather than silently emitting another format.

The manifest binds release, organization, target/surface/corpus, authorization, run/
attempt, evidence, Judge, reviewer, finding, remediation, regression, tool/version/config,
coverage-stage, and generation-template hashes. Executive output summarizes scope,
limitations, risk, trends, and blockers. Technical output includes reproduction plans,
sanitized request/response diffs, trusted-oracle basis, affected surfaces, evidence chain,
and regression status. Simulation, passive/advisory results, indeterminate verdicts, and
unvalidated live artifacts retain explicit labels.

Render every target/tool/model/operator string as hostile text. Use no remote assets,
scripts, active content, Markdown trust, external URLs, or filesystem-relative escape.
Apply strict CSP, bounded tables/text/artifacts, secret/PHI redaction, stable ordering,
classification banners, and provenance footers. Reports are drafts only: a Critical
finding or remediation remains publication-blocked until the existing independent human
approval record covers the exact manifest hash.

Tests cover HTML/CSV/formula/URL injection, huge/recursive fields, missing/tampered
evidence, cross-org references, status escalation, redaction, deterministic rebuild,
approval-hash drift, partial/blocked coverage, and print/PDF-safe layout vectors. Direct-
validate the new schema; WP-19B owns final registry/package parity.

These rendering checks are non-evidentiary. A report may label a claim live/validated only
from independently approved WP-21 evidence, and WP-21D must exercise the deployed draft
workflow. Fixture/local layouts can never establish a reporting capability or security
result.

**Focused verifier**

```bash
python -m pytest tests/reporting/test_security_report.py tests/reporting/test_security_report_security.py tests/reporting/test_security_report_pdf.py -q
```

No publication, upload, email, deployment, browser/network fetch, or external renderer
installation.

**Handoff:** WP-20B/WP-20C expose authenticated draft generation/download; WP-22 verifies
report claims against authoritative evidence.
