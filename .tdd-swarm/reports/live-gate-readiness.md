# Live-gate readiness audit — zero-call

- Audit time: 2026-07-24 (America/New_York)
- Audit mode: read-only repository and Railway metadata inspection; safe public Web probes only.
- Deliberately not performed: target, model/provider, Clerk-admin, database, approval, campaign,
  deployment, or credential/session calls. No secret values, session values, target responses,
  canaries, or PHI were read, written, or recorded.
- Overall decision: **BLOCKED — do not dispatch a target or provider call.**

## Evidence and scope

The evidence basis is `AGENTS.md`, `CLAUDE.md`, tickets `T-F03b`, `T-F04b`, `T-F05b`, `T-F06b`,
`T-F07b`, and `T-F10a`, `docs/target/READINESS.md`, `docs/deployment/RAILWAY.md`, campaign/Runner
authorization and lease code, and the presence-only preflight script.

Repository authorization/evidence paths are absent: `docs/evidence/authorizations/`,
`docs/evidence/live/`, `docs/evidence/regression/`, `docs/evidence/release/`,
`docs/performance/live/`, `evals/results/calibration/`, `evals/results/red-team/`, and
`evals/results/live/`. This proves no repository-held evidence; it does **not** assert the state of
protected Railway Postgres records, which this audit did not query.

`docs/target/READINESS.md` is still authoritative that all outstanding external observations block
the campaign. In particular, target-issued/idle session lifetime, exact expiry behavior,
cookie/history behavior, and target transport ceilings remain unmeasured. Health and authentication
probes are not target authorization.

## Staging status

| Gate / requirement | Observed status | Decision / reason |
|---|---|---|
| Exact target/surface catalog | Runner has one parseable catalog entry. Its structural controls report staging environment, OpenEMR/session mode, synthetic-only, synthetic attestation, canary reference, formatted ownership reference, a surface, positive budget/attempt/rate/timeout caps, and redirect denial. Values were suppressed. | **Configuration present, not campaign-authorized.** A catalog ownership reference is not a per-run authorization. |
| Exact corpus and campaign authorization | No `campaign.json` or live manifest; T-F05b requires the exact current release, target/surface, corpus, provider-policy, caps, session generation, expiry, launcher, and distinct approver. | **BLOCKED.** No audited exact-scope approval or current-SHA campaign manifest. |
| SMART session lease / credential generation | Runner has one parseable credential-binding entry, but `AGENTFORGE_SESSION_LEASES_JSON` is absent. Code requires generation/expiry/value-digest metadata to cover the bounded campaign window for a session target. | **BLOCKED.** Credential binding alone cannot prove generation, expiry, digest, or lease coverage. |
| Synthetic data and canary | The live catalog structurally requires synthetic-only data, attestation, and a canary reference. The legacy local presence-only script reports no legacy canary; it is not staging authority. | **Partially configured, operational evidence absent.** No approved run proves the exact corpus/canary binding or redaction. |
| Provider settings | Staging Runner has neither `HEADSHOT_RED_TEAM_PROVIDER` nor `HEADSHOT_RED_TEAM_MODEL`, and no expected hosted-provider key (`OPENROUTER_API_KEY`, `TOGETHER_API_KEY`, or `ANTHROPIC_API_KEY`) is present. Runner Langfuse and per-call-cost settings are present, but they are not model authorization. | **BLOCKED** for T-F03b/T-F04b and any hosted-provider campaign. |
| Spend caps / rate / timeout / abort | The target catalog has positive structural caps; Runner has the per-call-cost setting. Code is fail-closed for caps and hard abort. No exact campaign authorization, current recorder evidence, or live cap/abort trace exists. | **Not sufficient to run.** Controls exist, but no authorized operational proof. |
| Launcher versus approver | Source and migrations persist launcher/approver identities and reject self-approval. Protected routes require auth; unauthenticated `GET /api/v1/campaigns`, `/approvals`, `/targets`, and `/events` each returned `401` (bodies discarded). | **Code/probe evidence only. BLOCKED** until two real Headshot users with the exact assigned permissions complete a secret-safe staging approval trace. |
| Web health/readiness | Staging `GET /health` = `200`; `GET /ready` = `200` (bodies discarded). | **PASS for Web probe only.** It says nothing about target/provider readiness. |
| Runner/Scheduler/Postgres health | Railway reports SUCCESS deployments and RUNNING instances for Runner, Scheduler, and Postgres. No private service exposes a public domain. | **Process status only.** Runner/Scheduler application readiness and schema evidence were not available from a safe public probe. |
| Only-Web-public topology | Railway domain inventory shows one public staging domain on Web and none on Runner, Scheduler, or Postgres. An extra private `headshot` service also exists; its purpose/release lineage was not established. | **Public-domain condition passes; inventory reconciliation remains required.** |
| Staging/production DB isolation | Railway reports distinct Postgres service instances, but the same Postgres service ID **and the same volume ID** in both Staging and production. | **BLOCKED / isolation violation.** This contradicts the required separate databases/volumes and must be corrected before any live work. |
| Deployed SHA | Worktree HEAD is `6fcfa0c80c80a81bafc788b1878a8477b7d52fd6`; the deployed legacy service records `23490ea9846bffcf36168b58f2c36edeceabb8df`, an ancestor of HEAD. Web/Runner/Scheduler Railway metadata does not record a commit hash. Local `origin/main` and `gitlab/main` refs both resolve to `23490…`; no CI query was made. | **BLOCKED.** No current, all-service deployed-SHA/CI/release manifest can be proven. |
| Separate 100-case workload | T-F07b authorization and output paths are absent. Current Runner corpus constants are 9 (MVP) and 14 (full scan), not 100. Requirements matrix marks OPT-17 missing and OPT-18 blocked. | **BLOCKED.** No separately authorized 100-case staging workload exists. |

## Required human actions — safe order

1. **Repair staging isolation before any campaign work.** Provision a dedicated staging Postgres
   database/volume and distinct staging bindings; migrate through the approved Web pre-deploy path.
   Then retain secret-free proof that staging and production volume/database, Clerk organization,
   origins, target credentials, and other sealed references differ.
2. **Make a coherent, immutable staging release.** Select the intended reviewed commit, deploy that
   same commit to Web, Runner, and Scheduler, record all three deployment IDs/commit SHA/schema
   revision, and collect `/health`, `/ready`, private-domain inventory, and CI evidence. Do not claim
   current SHA until all are recorded; reconcile the extra private `headshot` service.
3. **Provision the target session safely on Runner only.** Using the reviewed synthetic patient,
   create a new immutable session generation and matching credential binding plus non-secret lease
   metadata (generation, absolute expiry, digest). Verify the lease covers the lesser of exact
   authorization expiry and approved run timeout. Do not paste the session/canary into tickets,
   logs, evidence, or this report.
4. **Restore provider preflight only under an owner-approved spend envelope.** The owner must supply
   valid, expiring, capped `judge-calibration.json` and `red-team-eval.json` artifacts for T-F03b
   and T-F04b, then provision the selected Runner provider/model and scoped key. Run their
   mechanical zero-call preflights first; if valid, retain reviewed provider evidence before a
   target campaign.
5. **Obtain a distinct target-load authorization, separately.** An authenticated Operator submits
   an exact staging campaign scope binding the deployed SHA, catalog target/surface, full corpus
   hash, provider-policy hashes, caps, session generation, run nonce, expiry, and synthetic/canary
   references. A different authenticated Headshot Approver with `org:campaign:authorize` approves
   that exact request. Record the secret-free request/decision/launch trace and verify wrong-org,
   missing-permission, and self-approval denial through a safe harness.
6. **Only after Steps 1–5, perform T-F05b's bounded staging campaign.** It must create the reviewed
   current-SHA manifest and evidence, including physical-request/recorder count equality and
   redaction checks. T-F06b replay requires its own still-valid scope or replay authorization.
7. **Authorize load separately; do not reuse campaign or spend approval.** For T-F07b, the owner
   supplies `live-stress.json` binding exactly 100 cases, the staging target, rate/concurrency/
   timeout/USD caps, monitor, abort owner, lease, launcher, and distinct approver. Run its
   zero-call preflight; only then may the authorized stress execution be considered.

## Authorization boundary: do not conflate these approvals

| Approval | Authorizes | Does **not** authorize |
|---|---|---|
| Owner spending approval (T-F03b/T-F04b) | Bounded provider/model evaluation calls, provider identity, maximum calls/USD, expiry, and reviewed thresholds. | Any target traffic, campaign launch, session use, or 100-case load. |
| Exact target campaign authorization (T-F05b) | One expiring, nonce-bound staging target/corpus/provider-policy/caps/session scope, launched by one user and approved by a different user. | Provider spend beyond its own approval, a changed SHA/corpus/session/cap, regression replay, or stress load. |
| Separate stress authorization (T-F07b) | Exactly 100 authorized staging cases and its own load caps, monitor, abort owner, lease, launcher, and distinct approver. | Reuse of a normal campaign approval or an inferred target limit. |

## Safe checks actually executed

- Railway read-only status/domain metadata and variable **presence/aggregate validation only**;
  raw values were suppressed in-process and never recorded.
- Public staging Web status-only probes: `/health` `200`, `/ready` `200`, and four protected
  `/api/v1/*` routes `401` without a token. Response bodies were discarded.
- `scripts/preflight_status.py` executed locally in presence-only mode. It reported structural
  blockers (no legacy canary and no verifiable approval); it is not evidence of deployed staging
  configuration and did not make a network call.

No target, model, provider, database, Clerk-admin, campaign, approval, deployment, or remediation
action was performed during this audit.
