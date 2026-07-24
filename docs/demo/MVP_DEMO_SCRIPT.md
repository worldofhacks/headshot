# Headshot final demo script

**Target length:** 3–5 minutes

**Recording status:** blocked until the exact final staging release and authorized campaign exist

**Staging shell:** <https://web-staging-8e30.up.railway.app>

This is a recording checklist, not evidence that the newest code is deployed. Do not record against
the currently audited older release (`23490ea`, schema `0013`). Replace no values by hand: show the
identities and measurements returned by the final UI/API and linked evidence.

## Before recording

Stop rather than record if any prerequisite is missing:

1. GitHub Actions is green for the exact commit shown by Railway Web, Runner, and Scheduler.
2. Railway reports the same source commit and the database reports the single packaged Alembic head.
3. The normal Web/API workflow has a persisted, unexpired exact-scope authorization for the security
   owner's frozen corpus hash and Judge/configuration identity.
4. The target, allowlist, synthetic-data assertion/attestation, budget, logical and physical request
   caps, rate, timeout, retry policy, nonce, and abort control are visible and correct.
5. A distinct Operator and Approver are available. Never show passwords, bearer/session values,
   organization IDs, target SIDs, provider credentials, or Langfuse keys.
6. The campaign has completed and `scripts/verify_langfuse_campaign.py` has reconciled PostgreSQL with
   Langfuse Cloud. Keep only the redacted query-back artifact.
7. The demo-video URL is not yet present in this repository; attach the actual URL after recording.

## 0:00–0:30 — Release and trust boundary

**Open:** release/status view, then **Targets**.

Show the exact commit, migration revision, environment, public Web URL, and the authorized external
target. State the values visible on screen.

> “Headshot is a Railway-hosted adversarial evaluation control plane. Only Web is public; Runner,
> Scheduler, and PostgreSQL are private. The target is external, and a healthy target does not
> authorize a campaign.”

## 0:30–1:15 — Exact authorization

**Open:** the completed campaign's authorization detail.

Show the target/surface versions, literal host/allowlist, synthetic-only controls, frozen corpus ID and
SHA-256, hosted configuration/Judge identity, caps, rate, timeout, nonce, operation hash, and distinct
launcher/approver IDs in redacted form.

> “Authentication permits a user to request an operation; it never authorizes target traffic. This
> immutable operation hash binds every dispatch-relevant value. A different Approver authorized this
> exact scope, and the Runner rechecked it before execution.”

Do not repeat the approval live unless a separate campaign is explicitly authorized for the recording.

## 1:15–2:15 — Real ordered execution

**Open:** **Live** or **Birdseye** for the authorized run.

Show persisted events in order:

1. Orchestrator execution;
2. Red Team case selection/generation lineage;
3. trusted Policy Gateway and recorded physical target request;
4. independent Judge verdict with deterministic-oracle status;
5. Documentation execution only where a finding produced a draft report.

> “These are persisted executions, not optimistic UI nodes. PostgreSQL records role order, parent
> campaign/run/attempt IDs, provider and returned model, latency, usage, retries, errors, and actual
> cost where the provider supplied it. Deterministic evidence remains decisive; an uncalibrated model
> assessment is advisory and does not block the campaign.”

If the hosted Red Team was not part of the final composed run, say so. Do not call a deterministic
seed-selection execution a hosted generation.

## 2:15–3:00 — Findings, reports, and regression status

**Open:** **Findings**, one evidence chain, and the linked draft report.

Show the attempt/result/verdict/finding/report lineage and human publication state. Use only synthetic,
redacted evidence.

> “The Red Team cannot author evidence or judge itself. The recorder's content-addressed result feeds
> the independent Judge. Documentation drafts only from validated findings, and critical publication
> remains human-gated.”

State the actual campaign totals and verdict states. Do not present scanner-only, simulated,
`NOT_EXECUTED`, `INDETERMINATE`, or `ERROR` rows as confirmed exploits. Describe regression as planned,
admitted, replayed, or live-verified exactly as the stored state shows.

## 3:00–4:00 — Langfuse and cost reconciliation

**Open:** **Traces/Agents** and **Costs**, then the redacted query-back summary.

Show the shared campaign trace, native agent/generation parentage, same-attempt target-request child,
provider/model identity, tokens, latency, retries, errors, and cost. Reconcile the displayed Langfuse
counts and totals to PostgreSQL.

> “PostgreSQL is the system of record. An SDK flush is not proof of delivery; Headshot marks export
> verified only after paged Langfuse query-back reconciles the exact observations. Missing usage or
> provider-estimated cost remains visibly missing or estimated.”

Read the actual campaign cost and timing from the verified evidence. Do not reuse the obsolete
“nine cents” or “321 seconds” narration.

## 4:00–4:30 — Close

> “This run demonstrates one bounded, synthetic-only, separately authorized campaign through the real
> UI/API, private execution plane, independent deterministic-oracle-first Judge, persisted evidence,
> gated reporting, and Langfuse query-back. The submission distinguishes source implementation from
> what this exact release and campaign proved.”

End on the submission index, which must contain the actual repository, deployed app, threat model,
users, architecture, frozen corpus/results, vulnerability index, cost analysis, demo, and social-post
links. If either publication URL is unavailable, leave it explicitly pending; never invent one.
