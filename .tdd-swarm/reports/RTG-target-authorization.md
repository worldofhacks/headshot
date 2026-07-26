# Tracked target authorization — Clinical Co-Pilot live synthetic deployment

**Recorded by:** RTG orchestrator, from owner-provided authorization (session answer).
**Purpose:** the durable, SID-free `<AUTHORIZATION_ARTIFACT>` the swarm's WP-21A preflight and
WP-21B–E live executors consume. This file is authorization **metadata only**.

> **SECRETS BOUNDARY — read first.** The two per-week **SIDs are bearer credentials for
> synthetic patients.** They live ONLY in the out-of-repo bundle
> (`.../claude-adversarial-run/adversarial-smart-bruno-2026-07-24/**/environments/Runtime.bru`
> and that bundle's `README.md`). They are **never** written into this repository, this file,
> any report, any log, or any commit. Do not publish the bundle. Any evidence artifact produced
> later must be SID-redacted before it enters version control.

## Owner authorization (verbatim scope, secrets removed)

- **Grant:** bounded adversarial and regression testing against the owner's **synthetic-data**
  Clinical Co-Pilot deployment.
- **Live target (base API):** `https://agent-production-9f62.up.railway.app`
- **Authorized surfaces / "the 2 targets":**
  - **Week 1 app:** `/app` — liveness, readiness, anonymous guideline retrieval, authenticated
    patient-pinned cited chat.
  - **Week 2 app:** `/week2` — liveness, readiness, synthetic lab upload, bounded processing
    polling, grounded extraction reporting, PNG preview, source/artifact digest verification,
    anonymous guideline retrieval, authenticated cited chat, synthetic intake upload, permanent
    duplicate handling (ships 2 synthetic PDF fixtures).
  - **Chat endpoint:** `POST /chat` with body `{session_id, message}` (matches the existing
    `src/agentforge/target/openemr_adapter.py` adapter shape).
- **Credentials:** one SID per week, each a bearer credential pinned to one synthetic patient;
  callers on a SID share the patient pin, inactivity window, and turn budget. **Values stored
  out-of-repo only** (see secrets boundary).

## Hard rules (owner-imposed; enforce in every live lane)

- **Synthetic patient data only.** No real PHI, ever.
- **No** infrastructure change, credential rotation, OAuth-client registration, record deletion,
  or denial-of-service / load testing.
- Week 2's bundled **synthetic** document uploads are authorized.
- **≤ 3 concurrent workers** (matches the swarm's concurrency cap).
- Never print SIDs in logs/reports/screenshots/command history/source control; never commit or
  upload the bundle.

## Session policy

- Idle timeout: **72 h** (259,200 s). Shared chat limit: **1,000 turns / session**.
- Sessions are durable (survive agent restarts and OAuth access-token refresh); multiple agents
  may share a SID; each SID stays pinned to its original synthetic patient.

## Bundle location (out-of-repo — never copied in)

- Archive: `<home>/.codex/visualizations/2026/07/24/019f94f8-2413-7682-bf59-72ea46b6dad8/adversarial-smart-bruno-2026-07-24.zip`
- Extracted root: `<external-bundle-root>/claude-adversarial-run/adversarial-smart-bruno-2026-07-24`
- Week 1 collection / env: `week1/bruno` · `week1/bruno/environments/Runtime.bru`
- Week 2 collection / env: `week2/bruno` · `week2/bruno/environments/Runtime.bru`
- Report output dir: `<external-bundle-root>/claude-adversarial-run/reports`
- Independent harness (Bruno CLI): `npx --yes @usebruno/cli@3.5.2 run --env Runtime --bail`

## How this maps to the swarm's live-evidence law (honest boundaries)

- ✅ Satisfies the **owner-authorized deployed live target URL + surfaces + provisioned test
  principals + synthetic-only** requirement for **target-behavior** claims.
- ⚠️ The Bruno CLI is an **independent** harness, not the AgentForge **production code path**.
  Bruno runs can corroborate target behavior and seed regression, but WP-21 "operational /
  demonstrated" claims still require the **deployed AgentForge Railway release** to attack this
  target **through its own Policy Gateway / adapter / Recorder / independent Judge**.
- ❌ Does **not** by itself satisfy the rest of the WP-21A surface: exact deployed **AgentForge
  platform** Railway SHA, dual-remote/CI-green for that SHA, Headshot/Clerk controls, a
  **separate** two-person approver identity (launcher ≠ approver), platform spend budgets / rate
  caps / abort wiring, and observation points. Those remain required before any live lane runs.

## Pre-existing repo references to this target (already partially wired)

`README.md`, `docs/evidence/zap/{AUTHORIZATION.md,README.md,zap-target.json}`,
`evals/results/live-campaign-20260724/{summary.json,responses.jsonl}`,
`docs/vulnerabilities/AF-VULN-2026-0724-00{1,2,3}-*.md`, `scripts/live_probe.py`,
`console/vite.config.ts`. A legacy summary for `aceddc4…` claims 9×HTTP-200 / 9 evidence /
9 `INDETERMINATE` against this target. Its `$0.09` statement is unsupported by a retained billing
or immutable request-cost manifest and must not be used as measured cost.
