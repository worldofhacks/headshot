# Headshot final demo script

**Target length:** 3–5 minutes

**Recording status:** blocked until the exact final staging release and authorized campaign exist

**Staging shell:** <https://web-staging-8e30.up.railway.app>

This is an executable recording checklist, not evidence that the newest code is deployed. The currently
audited Railway release is still `23490ea` at database revision `0013`; the moving candidate has one
source migration head at `0018`. Do not record the candidate narrative against the older release, use
fake/demo authentication, substitute a default corpus, or fill any evidence field by hand.

## Before recording: create the real evidence

Stop if any prerequisite is missing:

1. Save the final release, push its identical commit to GitHub and the GitLab mirror, and wait for
   authoritative GitHub Actions to pass. Deploy that exact saved release to **staging** and migrate its
   database through the single `0018` head. Confirm Railway Web, Runner, and Scheduler expose the same
   commit; only Web may be public.
2. Load the security owner's exact **frozen 100-case corpus**. Record its corpus ID and SHA-256; do not
   generate, expand, or substitute a corpus for the demo. Candidate source admits the exact
   400-call four-role envelope only with **zero provider retries** and refuses the 800-call
   retry-expanded shape. This source is not deployed and no final 100-case configuration exists.
   The default Red-Team input policy is also below current canonical encoded requests and now
   correctly refuses before any provider side effect. Do not launch until the frozen request shapes
   produce a new policy hash and the exact role/global token, USD, rate, timeout, and call ceilings
   are staged, catalog-preflighted, and bound into a fresh authorization.
3. Stage the exact configuration and verify its immutable identities:

   | Role | Requested model | Exact upstream route |
   |---|---|---|
   | Orchestrator | `anthropic/claude-opus-4.8` | `amazon-bedrock/eu-west-1` |
   | Red Team | `qwen/qwen3.5-397b-a17b` | `atlas-cloud/fp8` |
   | Judge | `google/gemini-2.5-pro` | `google-vertex/global` |
   | Documentation | `openai/gpt-5.4` | `azure/eu` |

4. Through the normal UI/API, sign in to the exact Headshot Organization as a real Operator. On
   **Targets**, click **Request exact campaign authorization** only after checking the exact
   target/surface/version, literal destination and allowlist, synthetic-data assertion and attestation,
   corpus hash, configuration/Judge identity, budget, logical and physical request caps, zero target
   retries, rate, timeout, expiry, nonce, and abort control.
5. Sign in separately as a different real Approver. On **Approvals**, inspect the operation hash and click
   **Approve exact scope**. Return as the Operator and click **Launch approved campaign**. Authentication
   and role labels alone never authorize target traffic.
6. Let that exact campaign finish. Do not replace failures or delayed UI state with fixtures. Run
   `scripts/verify_langfuse_campaign.py` against the campaign and retain only its redacted query-back
   artifact. PostgreSQL and Langfuse must reconcile before recording.
7. Have the actual demo-video and social-post URLs ready for the submission index after publication. No
   such URLs are currently available in the repository; never invent them.

Never show passwords, bearer/session values, Organization IDs, target SIDs, provider credentials, secret
references that reveal account structure, or Langfuse keys.

## 0:00–0:30 — Release and trust boundary

**Open:** release/status view, then **Targets**.

Show the final commit, migration `0018`, staging environment, public Web URL, private-service status, and
the authorized external target. Read the actual values on screen.

> “Headshot is a Railway-hosted adversarial evaluation control plane. Only Web is public; Runner,
> Scheduler, and PostgreSQL are private. The target is external, and target health or a signed-in user
> does not authorize a campaign.”

## 0:30–1:10 — Exact human authorization

**Open:** **Approvals** and select the completed campaign's authorization.

Show the target and surface versions, literal allowlisted host, synthetic-only controls, frozen 100-case
corpus ID/SHA-256, hosted configuration and Judge identities, caps, rate, timeout/expiry, nonce, operation
hash, and distinct launcher/approver identities in redacted form.

> “A real Operator requested this immutable scope and a different real Approver authorized it. The
> operation hash binds every dispatch-relevant value. The Runner rechecked the exact grant before every
> physical target request.”

Do not reenact an approval with the same identity or create a second run unless that second operation has
its own explicit authorization.

## 1:10–2:15 — Ordered four-agent execution

**Open:** **Live → Birdseye**, then select one attempt with complete lineage.

Show persisted events in exact order:

1. Orchestrator — requested `anthropic/claude-opus-4.8`, route
   `amazon-bedrock/eu-west-1`;
2. Red Team — requested `qwen/qwen3.5-397b-a17b`, route `atlas-cloud/fp8`;
3. the trusted Policy Gateway and physical target request for the byte-exact frozen seed;
4. Judge — requested `google/gemini-2.5-pro`, route `google-vertex/global`, with its deterministic
   oracle/canary fields;
5. Documentation — requested `openai/gpt-5.4`, route `azure/eu`, only if the Judge produced a validated
   finding eligible for a draft report.

> “These are persisted executions, not optimistic UI nodes. The hosted Red Team made one real traced
> generation for this frozen seed, but its output was unreviewed. Headshot stored only its hash and
> quarantine disposition, discarded the generated text, and dispatched the byte-exact authorized seed.
> A provider, trace, or budget failure would have stopped the run before target dispatch.”

> “The owner’s calibration passed its documented thresholds for different captured provider identities,
> but it is not human-enabled and does not match these exact routes. This model Judge is therefore
> advisory. Deterministic-oracle precedence is decisive, and a calibration mismatch does not block the
> campaign.”

If Documentation did not run because there was no validated finding, show that conditional state. Do not
invent a Documentation event to make the diagram look complete.

## 2:15–3:00 — Evidence, findings, and reports

**Open:** **Coverage & Regression**, **Findings**, and one evidence chain.

Show the attempt/result/verdict/finding/report lineage and publication state. Read the actual campaign
case, physical-request, verdict, finding, and draft-report totals.

> “The Red Team cannot author evidence or judge itself. The recorder’s content-addressed result feeds
> the independent Judge. Documentation consumes validated findings only, and critical publication and
> remediation remain separately human-gated.”

Use only synthetic, redacted evidence. Never present scanner-only, simulated, `NOT_EXECUTED`,
`INDETERMINATE`, or `ERROR` rows as confirmed exploits. Describe regression as planned, admitted,
replayed, or live-verified only when the stored state supports that word. Link the owner-maintained
[`../vulnerabilities/README.md`](../vulnerabilities/README.md) without changing its conclusions.

## 3:00–4:00 — Langfuse and cost reconciliation

**Open:** **Traces**, **Agents**, **Costs**, and the redacted query-back artifact.

Show the campaign trace; AGENT observations; one `provider.openrouter.attempt` GENERATION for every
physical provider invocation; same-attempt target request; configured and returned provider/model;
latency; input/output tokens; retries; errors; and actual cost where supplied. Show parent
campaign/run/attempt IDs in redacted form and reconcile role/call/token/cost totals to PostgreSQL.

> “PostgreSQL is the system of record. An SDK flush is not delivery proof. Headshot marks observations
> verified only after paged Langfuse Cloud query-back matches the durable execution and provider-event
> ledgers. Missing usage remains missing, and provider-estimated values remain labeled estimated.”

Read actual totals from the reconciled artifact. Do not reuse historical “nine cents,” “321 seconds,”
or any local/simulated measurement.

## 4:00–4:30 — Close

> “This exact staging release completed one bounded, synthetic-only, separately authorized frozen
> 100-case campaign through the real UI/API. It proves ordered four-agent lineage, deterministic-first
> judging, persisted evidence, gated reporting, and Langfuse query-back for this release and no other.”

End on the submission index with real links to the repository, deployed app, threat model, users,
architecture, frozen corpus/results, vulnerability index, cost analysis, demo, and social post. If either
publication URL is unavailable, leave it explicitly pending.
