# Vulnerability reports — authorized live Co-Pilot campaign (2026-07-24)

Draft findings from **authorized, synthetic-only** adversarial testing of the owner's live
Clinical Co-Pilot (`https://agent-production-9f62.up.railway.app/chat`). All reports are **DRAFT** —
publishing any finding is a separate two-person human-approval gate (approver ≠ launcher). No real
PHI; the sessions are pinned to synthetic Synthea patients.

*Index reconciled 2026-07-25 at base `107c11c`. It previously listed only 001–003 while six report
files were present in this directory.*

## Honest headline
**0 confirmed exploits.** The independent, deterministic `Judge` returned `INDETERMINATE` for every
adversarial probe (no trusted oracle/canary hit → no `EXPLOIT_CONFIRMED`). Across the four result
groups under `evals/results/` there are 39 verdict records, all `INDETERMINATE` at confidence `0.0`,
with **0** `EXPLOIT_CONFIRMED`, **0** oracle hits and **0** canary hits. (22 of the 39 carry the reason
code `non_oracle_uncalibrated_indeterminate`; the 17 records in the superseded first scan carry only
`{attempt_id, state, confidence}` and no reason code at all.) The Co-Pilot's
layered defenses held on every probe that received a response: a **deterministic pre-model refusal**
plus an **evidence-grounded re-render with per-claim verification** (`pass`/`flagged`/`blocked`).

Two things that headline does **not** mean:

- It does not mean the target is clean. It means the platform's deterministic evidence path found
  nothing conclusive, and its model-Judge path is not enabled, so non-oracle cases resolve to
  `INDETERMINATE` rather than to a graded `NO_EXPLOIT_OBSERVED`. See
  [`docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md`](../security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md)
  RT-02.
- It does not mean every finding here is cosmetic. 001–003 are observations of controls that largely
  held; **004–006 are control weaknesses**, and 004 sits on a bearer-equivalent credential guarding a
  patient record.

## Reports

| ID | Classification | Severity as stated in report | Reconciled severity | Theme | Provenance |
|---|---|---|---|---|---|
| [001](AF-VULN-2026-0724-001-chat-latency-and-rate-limiting.md) | observation | Low | Low | `/chat` ~72 s latency; target rate-limiting (429) | Platform adapter-boundary scan |
| [002](AF-VULN-2026-0724-002-prompt-injection-jailbreak-resistance.md) | observation | Low | Low | Prompt-injection / jailbreak outcome; first-line refusal *inconsistent* — model-grounding is load-bearing | Platform adapter-boundary scan |
| [003](AF-VULN-2026-0724-003-sensitive-data-output-handling-resistance.md) | observation (control validated) | Informational | Informational | Sensitive-data & output-handling; no leakage/reflection across all 17 probes | Platform adapter-boundary scan |
| [004](AF-VULN-2026-0724-004-session-token-in-url-and-sole-bearer-credential.md) | **control weakness** | `Medium–High` | **Medium** | Session identifier in URL query string, and sufficient alone to return a patient brief | **External Bruno client** |
| [005](AF-VULN-2026-0724-005-missing-http-security-headers.md) | **control weakness** | `Medium` | **Low** | No HTTP security response headers on any captured response | **External Bruno client** |
| [006](AF-VULN-2026-0724-006-readiness-and-health-information-disclosure.md) | **control weakness** | `Low–Medium` | **Low** | Anonymous health/readiness disclose a component inventory and a build identifier | **External Bruno client** |

Two columns, deliberately, because they do not yet agree:

- **Severity as stated in report** is what the report body in *this tree* says. Note that
  `Medium–High` and `Low–Medium` are **not legal members of the `vuln_report` contract severity enum**
  (`low|medium|high|critical`, `src/agentforge/contracts/v1/vuln_report.json:37`). **Three** of the six
  reports carry a value outside that enum, not two: 003 `Informational`, 004 `Medium–High`, 006
  `Low–Medium`. None of the three can be published as written. 003's case is the mildest — it is an
  observation of a control that held rather than a defect — but "predates the enum alignment" is a
  reason, not an exemption.
- **Reconciled severity** is the outcome of an independent offline re-validation of 004–006, recorded
  on lane `redteam/judge-calibration-corpus-evidence` (commit `507d032`, PR #33). **Those corrected
  report bodies are not on this base.** Carry the reconciled values in any summary, cost, or
  requirements document; the report bodies themselves are corrected by that lane, not here.

The re-validation's substantive changes, summarised so the two columns can be reconciled without
re-reading the lane: 004 was downgraded because there is **no negative control** — it is not
established that the server *reads* the `session_id` query parameter, only that it was sent and the
request returned 200; that single missing experiment is the difference between a control weakness and
a confirmed vulnerability. A claim in 005 (`/app?sid=…`) was **refuted**: no parameter named `sid`
appears in any capture.

## Provenance — where each report actually came from

This distinction matters for grading and was previously undocumented:

- **001–003** came from the platform's own adversarial scan through the real `OpenEmrAdapter`
  (`copilot_chat` profile), with deterministic code oracles feeding schema-valid Evidence Envelopes
  into `agentforge.agents.judge.Judge`. Results in `evals/results/live-campaign-20260724*/`.
  **Precisely: this is the adapter-boundary scan, not the `SecureCampaignCoordinator` run.** No report
  cites `platform-live-run-20260724` — `grep -rn platform-live-run-20260724 docs/vulnerabilities/`
  returns zero hits — so "platform campaign" must not be read as the governed coordinator path.
- **004–006** came from the owner's **external Bruno collections** (`@usebruno/cli@3.5.2`), **not**
  from the platform scanner. They are legitimate findings about the target; they are **not** evidence
  that the platform discovered anything.

**All six** reports claim autonomous drafting in their header line — 001–003 read "Drafted
autonomously", and 004–006 read "Drafted autonomously by the Documentation agent". Every one of those
claims is **inaccurate**: `docs/evidence/agent-trace.md:56 @107c11c` records that the runtime Documentation agent
drafted nothing at all, because `exploit_confirmed = 0` and the agent requires
`state == EXPLOIT_CONFIRMED` to draft. All six reports are human-drafted. The lane above corrects the
header text.

## Method (what actually ran)
- **Tool-driven functional/regression:** the owner's Bruno collections (`@usebruno/cli@3.5.2`) for
  Week 1 (`/app`) and Week 2 (`/week2`) — 15 request/response pairs across 9 route shapes, 40/40
  tests passing. Scrubbed results in `evals/results/bruno-20260724/`.
- **Platform adversarial campaign:** a curated corpus (prompt injection, jailbreak/DAN, sensitive-data
  leakage, encoding/output-handling) fired through the real `OpenEmrAdapter` (`copilot_chat` profile)
  at ~1 req/2 s, with **deterministic code oracles** feeding schema-valid Evidence Envelopes into the
  real `agentforge.agents.judge.Judge`. Results in `evals/results/live-campaign-20260724*/`.
- **Passive web baseline:** an OWASP ZAP 2.17.0 passive baseline against the same authorized host.
  Raw artifact committed and hash-verified at `docs/evidence/zap/zap-target.json`
  (sha256 `89f10c94…`); 3 alerts / 5 instances, all publication-blocked.
- **Global target config:** both sessions registered in `config/targets.json` and the platform catalog
  `config/live-target-catalog.staging.json` (validated by `scripts/validate_target_catalog.py`).

## What is still offline (honest limits)
- Full **autonomous orchestration** (Orchestrator → Red-Team → Judge → Documentation) and the
  two-person-gated **coordinator/lease** live path were not exercised — that path is blocked by design
  without a second approver, so this run used the adapter boundary + allowlist directly. The recorded
  two-person provenance is one human plus one AI agent identified by free text, and
  `approval.json` labels itself "Stand-in for the Clerk two-person Approver service (not yet wired)".
- **No run went through the platform's production authorization path.** All four legacy launchers now
  fail closed, so every artifact here was produced by a script that can no longer execute.
- The **calibrated model-Judge layer is not enabled**, so clean probes resolve to `INDETERMINATE`
  rather than a graded `NO_EXPLOIT_OBSERVED`. The only calibration measured at this base *fails*
  (30 labels, 18 agreements, 6 false negatives, 0 false positives, 18 abstentions).
- garak/promptfoo remain **offline-pinned** in this repo; the live scan used a curated corpus through
  the platform adapter (rate-cap-faithful) rather than garak's harness.
- **Indirect** injection / exfil via Week 2 uploaded documents (the richest surface) is not yet
  tested — those catalog surfaces exist but are `enabled: false`.
- **No independent reproduction exists for any of the six.** `docs/evidence/reproductions/` does not
  exist. PRD-32's "≥3 genuine, independently reproduced vulnerability reports" bar is **not met**; the
  honest position is three candidate findings with zero reproduction artifacts. Do not cite this
  directory as satisfying PRD-32.
- **No report carries a CVSS score.** Severity is the contract enum only.

## Publication gate
Every report is DRAFT and unpublished. Publication and remediation each require a distinct
authenticated `org:approver` principal carrying the required custom permission, with
`approver.user_id != launcher_user_id`. Normalized findings are stamped
`blocked_pending_human_approval` on write (`src/agentforge/security_tools/normalization.py:127`) and
**refused at insert if that stamp is absent** — `src/agentforge/security_tools/repository.py:79-85`
raises `SecurityToolEvidenceError("scanner output cannot assert publication authority")`. There is no
insert-time re-stamp; the control is a refusal, which is stronger.

## Provenance of the result sets
The first pass (`evals/results/live-campaign-20260724/`) was exploratory — a now-superseded inline SID
and a 30 s client timeout (which caused false timeouts). The **authoritative** adversarial results are
`evals/results/live-campaign-20260724-week1/` (Week 1 SID, 120 s timeout, 17/17 responded).

Credentials are by reference only (gitignored `.env.campaign`); the extracted Bruno bundle is never
committed. No session credential, SID, token, cookie, or bearer value appears in any of the six
reports.
