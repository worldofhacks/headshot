# WP-22 — Final independent red-team capability audit

**Branch:** `rtg/wp22-final-independent-audit`

**Model:** capable

**Depends on:** WP-21 reconciliation, including blocker output from every live lane

**Closes:** no finding automatically—this prompt verifies closure

You are a read-only final auditor. Do not edit implementation, tests, migrations, raw
evidence, authorization, or prior review records.

You must be a different identity from every WP-01–20 implementer, WP-21 preflight author
and executor, campaign launcher/approver, Evidence Reviewer, Security Reviewer, Judge,
publisher, and remediator.

This audit consumes independently approved WP-21 live evidence. Local suites may be rerun
only as non-evidentiary implementation-quality checks. The auditor makes no external call
and cannot create, supplement, or repair evidence. Missing approved live evidence leaves the
affected item open, partial, rejected, or blocked.

Do not contact a target/provider/Clerk/Railway/OAST service, run a campaign or scan, start a
native tool/scanner/browser, resolve credentials, deploy, publish, remediate, or spend.

**Write only**

- `docs/security/RED_TEAMING_COVERAGE_REVIEW_FINAL.md`
- `.tdd-swarm/reports/RTG-WP22-final-audit.md`

## Required audit

Re-run all focused suites, `bash scripts/check.sh`, console test/build/policy/browser gates,
migration/DB-role tests, secret scan, evidence-status check, package/container checks where
available, and `git diff --check`. Label their output `IMPLEMENTATION_PRECHECK_ONLY`; none
may support a live or closure column.

Produce file:line/test/evidence traceability for every RT-01–RT-14 finding and verify:

1. no agent, tool, scanner, browser, OAST, or import path has alternate target egress, and
   the exact deployed private Railway process plus genuine pinned child has approved live
   operation/permit/physical-send/ledger parity before an operational label;
2. every request/retry/turn/frame/reconnect/scanner request receives a fresh persisted gate;
3. runtime DB roles enforce actual least privilege;
4. destination pinning, TLS identity, redirect denial, and delivery certainty compose;
5. lease recovery cannot duplicate ambiguous live work;
6. coverage stages never turn metadata, simulation, advisory output, or indeterminate
   verdicts into security success;
7. all six PRD categories and applicable LLM/Agentic risks have genuine B/I/R cases or
   reviewed N/A records;
8. trusted observations cannot be forged by target/model/scanner text;
9. mutation requires generation review plus a new target authorization;
10. LLM-native and static/CI tool status reflects pinned capability, artifact, and
    independent evidence;
11. Burp claims match literal behavior, including governed-analogue Proxy/Repeater labels,
    canonical-operation versus sanitized-preview separation, sitemap/auth workflows,
    Sequencer acquisition/statistics, report drafts, and explicit unsupported labels;
12. regressions use fresh attempts and right-reason oracles;
13. readiness/public routes/ownership/evidence status are truthful;
14. every live claim is backed by exact approved WP-21 evidence from the deployed release
    and authorized deployed target, never by a fixture/mock/cassette/fake/local substitute.

Audit that approved live artifacts exercised every safely authorized applicable case for
SSRF/DNS rebinding, redirect/Host/CRLF ambiguity, approval/corpus/surface substitution,
abort/lease races, role/pool contamination, parser bounds, Cartesian explosion, OAST
replay/storm controls, browser/local-network escape, hostile UI rendering, artifact
tampering, duplicate delivery, process-proxy bypass, and scanner/model authority escalation.
When a case lacked a safe exact live contract or separate authorization, leave it blocked;
do not fill the gap with a local adversarial test. Verify OAST could not activate without
the owner architecture decision and exact deployed domain evidence.

Classify each item:

- `CLOSED_LIVE_VALIDATED`;
- `IMPLEMENTED_LIVE_EVIDENCE_BLOCKED`;
- `LIVE_EVIDENCE_REJECTED`;
- `PARTIAL_LIVE_VALIDATION`;
- `OPEN`;
- `NOT_APPLICABLE_APPROVED`.

Missing external authorization is an honest blocker, not a test failure and not closure.
Only `CLOSED_LIVE_VALIDATED` and an exact human-approved `NOT_APPLICABLE_APPROVED` count as
closed. `IMPLEMENTED_LIVE_EVIDENCE_BLOCKED`, `LIVE_EVIDENCE_REJECTED`, and
`PARTIAL_LIVE_VALIDATION` are excluded from closed counts.
Any Critical/Important finding, skipped invariant, migration fork, false capability label,
unreviewed evidence, or fixture/local evidence substitution returns `DONE_WITH_CONCERNS` or
`BLOCKED`, never green or a full-validation release recommendation.

Return the README status contract, highest severity, closed/open counts, and one-line
release recommendation.
