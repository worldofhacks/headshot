# Vulnerability reports — authorized synthetic Clinical Co-Pilot campaign (2026-07-24)

Draft findings from **authorized, synthetic-only** testing of the owner's live Clinical Co-Pilot.
The target host is referenced by name only; the authoritative allowlist entry lives in
`config/targets.json` and `config/live-target-catalog.*.json`. No real PHI — the sessions are pinned
to synthetic Synthea patients.

**Every report on this page is DRAFT and unpublished.** Publishing any finding, and any remediation,
is a separate two-person human-approval gate (approver ≠ launcher). See *Publication gate* below for
what is and is not actually enforced in code today.

## Honest headline

**0 confirmed exploits.** The independent deterministic `Judge` returned `INDETERMINATE` for every
adversarial probe — 17 distinct probes executed twice (34 attempts), no trusted oracle or canary hit,
so no `EXPLOIT_CONFIRMED` was reachable. Every finding below is a **control weakness** or an
**observation**, not a demonstrated exploit.

Two things that phrase does *not* mean:

- It does not mean the target is clean. It means the platform's deterministic evidence path found
  nothing conclusive, and its model-Judge path is not enabled, so non-oracle cases resolve to
  `INDETERMINATE` rather than to a graded `NO_EXPLOIT_OBSERVED`.
- It does not mean these findings are cosmetic. 004 in particular sits on a bearer-equivalent
  credential guarding a patient record.

## Reports

| ID | Classification | Severity | Theme | Provenance | Independently re-validated |
|---|---|---|---|---|---|
| [001](AF-VULN-2026-0724-001-chat-latency-and-rate-limiting.md) | observation | Low | `/chat` ~72 s latency; target rate-limiting (429) | Platform campaign | not re-validated |
| [002](AF-VULN-2026-0724-002-prompt-injection-jailbreak-resistance.md) | observation | Low | Prompt-injection / jailbreak outcome; first-line refusal inconsistent | Platform campaign | not re-validated |
| [003](AF-VULN-2026-0724-003-sensitive-data-output-handling-resistance.md) | observation (control validated) | Informational | Sensitive-data & output-handling resistance | Platform campaign | not re-validated |
| [004](AF-VULN-2026-0724-004-session-token-in-url-and-sole-bearer-credential.md) | **control weakness** | **Medium** | Session identifier in URL query string, and sufficient alone to return a patient brief | External Bruno client | ✅ 2026-07-24, offline |
| [005](AF-VULN-2026-0724-005-missing-http-security-headers.md) | **control weakness** | Low | No HTTP security response headers on any captured response | External Bruno client | ✅ 2026-07-24, offline |
| [006](AF-VULN-2026-0724-006-readiness-and-health-information-disclosure.md) | **control weakness** | Low | Anonymous health/readiness disclose a component inventory and a build identifier | External Bruno client | ✅ 2026-07-24, offline |

Severity uses the `vuln_report` contract enum (`low|medium|high|critical`). 003 predates that
alignment and still reads "Informational"; it is an observation of a control that held, not a defect.

## Provenance — where each report actually came from

This distinction matters and was previously undocumented:

- **001–003** came from the platform's own adversarial campaign through the real `OpenEmrAdapter`
  (`copilot_chat` profile), with deterministic code oracles feeding schema-valid Evidence Envelopes
  into `agentforge.agents.judge.Judge`. Results in `evals/results/live-campaign-20260724*/`.
- **004–006** came from the owner's **external Bruno collections** (`@usebruno/cli@3.5.2`), **not**
  from the platform scanner. They are legitimate findings about the target, but they are not
  evidence that the platform discovered anything.

## Independent validation of 004–006 (2026-07-24)

Each of 004, 005 and 006 was re-derived from a clean path by a reviewer who did **not** read the
report first, working only from the retained credential-scrubbed captures in
`evals/results/bruno-20260724/` (15 request/response pairs across 9 route shapes), then challenged by
a second adversarial reviewer. No network calls were made.

Outcome:

- **All three reproduce offline** and are re-classified as **control weaknesses**, not confirmed
  vulnerabilities. The corpus contains only positive cases — an authorized client presenting its own
  credential — so no access-control bypass is demonstrated anywhere.
- **004 was downgraded** from "Medium–High / open" on a specific argument: there is **no negative
  control**, so it is not established that the server *reads* the `session_id` query parameter at
  all — only that it was sent and the request returned 200. The server's own `status_url` hypermedia
  field carries no credential, which means the URL form is client-constructed. That single missing
  experiment is the difference between a control weakness and a confirmed vulnerability, and it is
  named as the first fix-validation step in the report.
- **A claim in 005 was refuted.** The URL form `/app?sid=…` appears in **no capture**; no parameter
  named `sid` exists anywhere in the corpus, and no request to either app path was captured. It has
  been removed.
- Roughly 15 corrections were applied per report, including severity values that were not legal
  contract enum members ("Medium–High", "Low–Medium"), an incomplete response-header union (12 names
  observed, 10 listed), and an OWASP primary mapping that asserted a bypass never demonstrated.

**No session credential, SID, token, cookie, or bearer value appears in any of the six reports.**
The one session reference in 004 was already `***REDACTED_SESSION***`. Live target URLs were removed
from 004/005/006 during validation — a vulnerability report circulates more widely than the repo and
should not carry a live endpoint. Two identifiers retained in the *captures* are flagged in the
reports so a reviewer does not mistake them for credentials: `x-copilot-request-id` (a 32-hex
per-response correlation id, superficially session-shaped) and the 40-hex build identifier in the
health payload, which is itself the subject of 006 and must not be copied into any circulated
artifact.

## Publication gate — what is actually enforced

Stated precisely, because the reports assert a two-person gate and the enforcement is uneven:

| Control | Status |
|---|---|
| Contract forbids a published state | ✅ `vuln_report.json` `publication_state` enum is `draft_unpublished` / `blocked_pending_human_approval` only |
| Critical severity forces `blocked_pending_human_approval` | ✅ `vuln_report.json` `allOf`; `agents/documentation/agent.py:122` |
| Database check constraint pins drafts | ✅ `storage/models.py:453-461` |
| Two-person rule on **campaign authorization** | ✅ `control_plane/store.py:732-734` raises on self-approval |
| Two-person rule on **finding approval** | ❌ **not enforced** — `control_plane/store.py:3457-3462` checks only the `org:findings:approve` permission and never compares approver to launcher. `require_distinct_approver` is hard-wired to `CAMPAIGN_AUTHORIZE` and is referenced only from tests |
| A "publish a finding" operation | ❌ none exists — `finding.published` is inserted as literal `false` and never updated anywhere in `src/` or `migrations/` |

So publication is currently blocked by *absence of a code path* rather than by a workflow, and the
approver-≠-launcher guarantee asserted in each report header is real for campaigns but **not yet
real for finding approval**. That gap is tracked in
`docs/evidence/red-team/CAPABILITY_STATUS.md`.

## Method

- **Tool-driven functional/regression:** owner's Bruno collections for Week 1 and Week 2. Scrubbed
  results in `evals/results/bruno-20260724/`.
- **Platform adversarial campaign:** curated corpus fired through the real `OpenEmrAdapter` at
  ~1 req/2 s with deterministic oracles and the real `Judge`.
- **Independent validation:** offline re-derivation from the retained captures only.

## Honest limits

- Full autonomous orchestration (Orchestrator → Red Team → Judge → Documentation) was **not**
  exercised; the captured run bypassed the Runner, and its `agents_exercised` has no `orchestrator`.
- The **calibrated model Judge is not enabled**, so clean probes resolve to `INDETERMINATE` rather
  than `NO_EXPLOIT_OBSERVED`.
- **Indirect injection / exfiltration via Week 2 uploaded documents** — the richest surface — is
  still untested; only the `POST /chat` surface has ever been exercised.
- **None of these six reports is an instance of the binding `VulnReport` contract**
  (`src/agentforge/contracts/v1/vuln_report.json`, 19 required fields). They are human-readable
  Markdown. No schema-valid `VulnReport` instance exists anywhere in the repo, because the
  Documentation Agent requires `EXPLOIT_CONFIRMED` and no verdict has ever reached that state.
- **No fix validation has been run** for any finding.
