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

> “Headshot also ingested a live OWASP ZAP passive baseline. It recorded missing
> HSTS, missing X-Content-Type-Options, and cache-control review. These are
> publication-gated Low, Low, and Informational findings—not confirmed exploits.”

## 3:30 — Show observability and cost

**Open:** **Traces**, then **Costs**

> “Every physical request has a correlation trace, measured latency, status, and
> Langfuse export state. The completed nine-request campaign cost nine cents,
> averaged one cent per request, and took about 321 seconds.”

## 4:05 — Close

> “Headshot meets the MVP requirements: a live deployed target, a structured
> threat model, a reproducible three-category attack suite, and a defensible
> multi-agent architecture with evidence, cost tracking, and human approval.”

## If time is short

Show **Targets → Approvals → Live → Coverage → Findings → Costs**. Never claim
that an exploit was confirmed. Say that the current scan produced
publication-gated evidence and fail-closed verdicts.
