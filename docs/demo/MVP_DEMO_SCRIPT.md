# Headshot staging demo and acceptance script

**Updated:** 2026-07-26

**Staging:** `https://web-staging-8e30.up.railway.app`

**Current state:** [`../CURRENT_STATE.md`](../CURRENT_STATE.md)

This script is for a truthful product demonstration. It does not authorize a deployment or campaign.
Until the reliability gates in `PLAN.md` are deployed, show the retained staging run and describe its
failure honestly instead of launching another batch that is expected to fail on one provider-format
error.

## Pre-demo safety check

- Use synthetic test data only.
- Never show Clerk tokens, target sessions, Railway variables, provider keys, or raw credentials.
- Confirm Web, Runner, and Scheduler are on one release and policy digest.
- Confirm PostgreSQL is at the packaged sole head (`0025` in the current release).
- Confirm `/health`, `/ready`, protected-route denial, and private worker heartbeats.
- Confirm production remains out of scope while it is release-skewed.
- For any live run, confirm the exact target/surface/version, workload, target-turn caps, hosted
  configuration, generation policy, credential generation/lease, canaries, and two-person approval.
- Do not launch while a deploy/restart is in flight.

## 0:00 — Platform and trust boundaries

Open **Overview/Live**.

> “Headshot is a Railway-hosted multi-agent control plane for adversarially evaluating a live AI
> system. React and FastAPI form the public authenticated Web service. PostgreSQL is the authority and
> durable queue. Runner and Scheduler are private. Model calls use exact OpenRouter routes, and only
> the Policy Gateway can call the allowlisted target.”

Point out that Clerk authenticates humans but does not itself authorize a live campaign.

## 0:35 — Target and workload

Open **Targets**, then **Coverage**.

> “The target is the externally deployed OpenEMR Clinical Co-Pilot. This repository contains no
> target code. The frozen suite has 100 reviewed cases and 121 target turns across six threat
> categories. It is split into exact 34/33/33 campaign shards with 41/40/40 target turns and zero
> target retries.”

Select `headshot-live-100-batch-01` for a future accepted run. Do not hand-edit its case/turn counts;
the request must exactly match the immutable workload.

## 1:10 — Human authorization

Open **Approvals**.

1. As an Operator, create the exact campaign request.
2. Show the bound target, surface, workload digest, credential generation, caps, policy/configuration
   digests, expiry, and nonce.
3. Sign out.
4. Sign in as a different Approver in the exact Headshot Clerk Organization.
5. Approve that unchanged request.
6. Sign back in as the Operator before launch.

> “The server derives both identities from verified Clerk session claims. The launcher cannot approve
> their own request. Any release, policy, configuration, target, workload, cap, credential, or expiry
> change requires a fresh request.”

If a genuine two-user Clerk acceptance has not been captured for this environment, say so and do not
claim this step is proven by a missing-token `401`.

## 2:00 — Multi-agent execution

Open **Agents** and **Traces**.

> “For each case, the Orchestrator makes a bounded decision. The Runner creates the durable attempt
> before the hosted Red Team selects from the exact approved corpus. The Policy Gateway sends the
> immutable target turns. The independent Judge receives bounded evidence, and deterministic
> oracle/canary evidence takes precedence. Documentation runs only after a trusted confirmed finding.”

Clarify that the Red Team has a large 32k-input/8k-output/8k-reasoning, 180-second per-call envelope;
the last run observed a 65.9-second Red Team response. Novel generated attacks remain quarantined and
require review and reauthorization.

## 2:45 — Latest run, without spin

Open run `50da57b037d44b3c93a10e4c2edf61a8`.

> “This run proved the lineage repair: 12 attempts, 36 provider calls, and 16 target calls were
> recorded without a post-hoc attempt-binding conflict. Eleven cases reached verdicts. One Gemini
> Judge response was HTTP 200 but schema-invalid, and because this configuration authorized zero
> retries and the Runner had batch-level failure semantics, the whole 34-case shard stopped.”

The 11 verdicts are `INDETERMINATE`. Say “no deterministic exploit was confirmed,” not “the target
defended all attacks.” One target response was HTTP `422`; a recorded transport response is not an
application success.

## 3:25 — Evidence, Langfuse, and cost

Open **Costs** and **Traces**.

> “PostgreSQL is the source of truth. The run measured `$0.60731395` across 36 provider calls and
> recorded `$0.16` of configured target-call accounting. Provider cost is measured; the target figure
> is not an invoice. The current straight-line 100-case operational baseline is about `$6.27`, before
> platform hosting, retries, Documentation, and fixed costs.”

> “Langfuse is a fail-soft sanitized projection. For this failed run, all 52 logical agent/target
> deliveries remain queued and the current verifier cannot query-back a failed campaign. A flush is
> not proof of remote delivery; that gap is tracked as release-blocking observability work.”

## 4:05 — Close

> “The platform has real authenticated control-plane, hosted-agent, live-target, evidence, and cost
> execution. The remaining work is reliability rather than a hidden scaffold: bounded structured
> retry, case-local errors, exact-once resume, failed-run Langfuse reconciliation, exact Judge
> calibration, and production release parity.”

Never claim a full 34- or 100-case campaign completed until the authoritative terminal evidence says
it did. Never claim a vulnerability was autonomously documented unless a trusted confirmation and a
durable Documentation execution exist.
