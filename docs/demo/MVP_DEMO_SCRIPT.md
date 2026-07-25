# Headshot MVP demo script

**Length:** 4–5 minutes

**App:** https://web-staging-8e30.up.railway.app

## Before recording

1. Have the Operator and Approver credentials ready.
2. Sign in as **Operator**.
3. Do not show passwords, session IDs, or Railway variables.
4. Use the deployed Clinical Co-Pilot target and synthetic test data only.

## 0:00 — What Headshot does

**Open:** **Live**

> “Headshot tests the live AI agents for adversarial failures.
> This is the deployed control plane. The Web API, Postgres evidence
> store, private Runner, and Langfuse connection are operational.”

## 0:20 — Select the target

**Open:** **Targets**

1. Select **openemr-copilot** from the target registry.
2. Point out the deployed URL, enabled `chat` surface, live execution profile,
   configured server-side credential, and synthetic-data restriction.

> “I am selecting the deployed Clinical Co-Pilot and its versioned chat surface.
> Headshot can only dispatch to this exact allowlisted origin.”

## 0:45 — Configure the scan

In **Exact campaign authorization request**, use:

- Budget: **$1**
- Maximum attempts: **9**
- Target requests per second: **1**
- Run timeout: **900 seconds**
- Run nonce: leave the generated unique value

Click **Request exact campaign authorization**.

> “This scan covers nine cases across prompt injection, data exfiltration, and
> tool misuse. The request binds the target, surface, corpus, rate, timeout,
> budget, and one-time nonce.”

## 1:15 — Approve the exact scope

**Open:** **Approvals**

1. Select the newest **pending** request and show its operation hash and scope.
2. Sign out as Operator.
3. Sign in as **Approver**.
4. Return to **Approvals**, select the same request, and click
   **Approve exact scope**.

> “A different authenticated person must approve the exact scope. The requester
> cannot approve their own campaign, and changing any bound value invalidates
> the approval.”

## 1:55 — Launch the scan

1. Sign out as Approver.
2. Sign back in as **Operator**.
3. Open **Approvals** and select the approved request.
4. Click **Launch approved campaign**.
5. Open **Live** and point to the queued or running campaign.

> “The approved campaign is now queued for the private Runner. The Runner
> rechecks the authorization, destination, credential reference, synthetic-data
> policy, caps, and abort controls before sending any request.”

## 2:30 — Show attack coverage

**Open:** **Coverage**

> “The attack suite contains nine reproducible cases across three categories.
> Each case records its prompt, expected safe behavior, severity, exploitability,
> OWASP mappings, and regression criteria. The Red Team generates attacks and
> the independent Judge evaluates recorded evidence.”

## 3:00 — Show findings

**Open:** **Findings**

> “Headshot also **normalized** a live OWASP ZAP passive baseline against the authorized
> target. It recorded missing HSTS, missing X-Content-Type-Options, and cache-control
> review. These are publication-gated Low, Low, and Informational findings—not confirmed
> exploits. Alongside them sit six draft vulnerability reports; the highest is a control
> weakness on a session identifier carried in a URL query string. Reports 004–006 include
> offline re-derivations over retained captures, but all six remain DRAFT and unpublished,
> with no independent attestation or separately recorded reproduction artifact. PRD-32
> remains incomplete.”

*Severity, precisely:* PR #48 merged at `a67ac1e`, replacing closed, unmerged PR #33. In this tree,
004 is **`medium`** and 005/006 are **`low`**, all legal `vuln_report` enum values. All three came
from the owner's external Bruno captures, not the platform scanner. Their embedded derivations are
checkable, but the claimed independent/blinded/no-network review process has no repository
attestation or separate run artifact. Do not call 004 “Medium–High” or say its correction is unmerged.

*Wording note:* say **normalized**, not "ingested". Nothing in the repository ingests the committed
ZAP artifact into Postgres — the only `SecurityToolEvidenceRepository.ingest` calls are in tests. And
name the six AF-VULN drafts: this beat previously presented the three ZAP records as the whole
findings set, which understates the `medium` finding a reviewer will ask about.

## 3:30 — Show observability and cost

**Open:** **Traces**, then **Costs**

> “Every physical request has a correlation trace, measured latency, status, and
> Langfuse export state.”

*Do not read the old cost line* ("nine-request campaign cost nine cents, averaged one cent per
request, ~321 seconds"). Two problems, both verified 2026-07-25: only **five** attempt manifests are
committed, not nine; and **no cost value is recorded in any result artifact** — the attempt manifests
have no cost field. The per-request figure came from a configured constant in the outbound telemetry
layer, which is an accounting cap, not a measurement. If asked about cost, say the caps: `$1.00`
budget, 40 attempts, 60 physical requests, 0.5 req/s, 1800 s
for the retained 2026-07-24 run — and that measured spend is unrecorded. For the prepared
100-case release envelope, the current reviewed caps are a `$50` hard reservation, 130 attempts,
100 logical cases, 121 physical requests, 0.5 req/s, 3600 s, and zero retries
(`docs/evidence/authorization-requests/caps.json`); the `$50` ceiling is not reported as spend.

## 4:05 — Close

> “Headshot meets the MVP requirements: a live deployed target, a structured
> threat model, a reproducible three-category attack suite, and a defensible
> multi-agent architecture with evidence, cost tracking, and human approval.”

## If time is short

Show **Targets → Approvals → Live → Coverage → Findings → Costs**. Never claim
that an exploit was confirmed. Say that the current scan produced
publication-gated evidence and fail-closed verdicts.
