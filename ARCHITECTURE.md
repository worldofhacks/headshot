# ARCHITECTURE.md — AgentForge / Adversarial Machine

> **Binding architecture.** Produced by `/arch-finalize` (2026-07-20) from `docs/planning/ARCHITECTURE_DRAFT.md`
> after an adversarial gap audit against the PRD (`Week_3_AgentForge.pdf`), the external review
> (`docs/planning/REVIEW_FINDINGS.md`, F1–F12), a primary-source verification pass, and a cold-eyes
> re-audit. Build posture: **production-grade** — the bar is "defend it in front of a hospital CISO,"
> not "it demos." Stable `§N` anchors; `/tasks-gen` and `/tdd-swarm` bind to them. Decisions cite
> `docs/planning/DECISIONS.md` (D#) and `docs/planning/RESEARCH.md` (R#). The finalize audit trail is
> `docs/planning/gap-audit.md`; every finding's resolution is registered in **§20**.
>
> **Cardinal rule honored:** no value is invented. Cost figures, per-agent token profiles, Mac tok/s,
> the LangGraph 1.x pin, and the target's exact auth/API shape remain `open question` (§17) — visible,
> never faked.

---

## §1. One-Page Summary (~500 words)

AgentForge is a reusable, **multi-agent adversarial evaluation platform** that continuously red-teams
AI-assisted clinical workflows. Its first target is a live, deployed OpenEMR **Clinical Co-Pilot**,
attacked over its URL; no target code lives in this repo, and every target is reached through a
pluggable adapter behind an allowlist. The job is not to find one jailbreak — it is to *continuously*
discover, evaluate, validate, regression-guard, and document vulnerabilities as the target evolves.

**Six components with distinct trust levels** (a single agent or linear pipeline fails the assignment):
the **Orchestrator** (trusted governor) reads the platform's own observability and prioritizes the next
campaign, triggers regression, and governs cost; the **Red Team** (untrusted, quarantined) generates and
mutates multi-turn adversarial inputs but never touches the target, credentials, or the evidence record;
a **trusted Policy Gateway + Execution Recorder** is the enforcement boundary — it alone holds
target-scoped credentials, enforces the allowlist, synthetic-data policy, budget, rate caps and hard
abort, executes against the target, and emits a canonically-hashed, append-only `AttemptResult`; the
**Judge** (independent evaluator) renders a verdict from the recorder's transcript *only*; the
**Documentation** agent turns confirmed exploits into reproducible reports; a **regression harness** and
an **observability layer** close the loop. Separation *is* the security property: an agent that both
attacks and judges is compromised by design, and the attacker is structurally removed from the evidence
the Judge sees.

**The Judge invariant — "never approve a confirmed exploit" — is deterministic and fail-closed** (D13),
not a property of any model's refusal behavior. A canary/oracle hit overrides the LLM Judge; the Judge
runs only where deterministic evidence is inconclusive; ambiguity resolves to `INDETERMINATE`/`ERROR`,
which never count as safe and never enter the regression corpus. Cross-provider separation is retained
as defense-in-depth, not the invariant.

**Stack (build-vs-configure, ADR-0001).** Python on Railway (Docker-from-GitHub, managed Postgres, cron,
deployment-history + Postgres PITR rollback). Orchestration is **LangGraph OSS engine** with Postgres
checkpoints; `interrupt()` is the *pause* mechanic behind a runtime-enforced human-approval gate. One
Postgres is exploit DB + checkpoints + a `SKIP LOCKED` work/regression queue, partitioned by **per-agent
DB roles**. Observability is **Langfuse Cloud** for MVP (self-host is a documented, heavier post-MVP
path). Models are assembled per role — a hosted/uncensored-OSS **Red Team** (frontier models refuse
offensive work; deployed default is hosted, local Mac is a dev/cost-baseline switch), a **Claude Sonnet
4.6** Judge, an **Opus 4.8** Orchestrator, and a **GPT-5.4** Documentation agent (cross-vendor from the
Judge). We configure/wrap Garak, PyRIT, Giskard, Promptfoo, ZAP and Semgrep and build only the four
capabilities no tool delivers.

**Defensible to a CISO.** Inter-agent messages are versioned, framework-neutral JSON Schemas with typed
errors and both-sided contract tests. Adversarial content is quarantined and treated as untrusted data
even by the Judge and Documentation agents. Credentials are bound to their target; every live campaign
passes a runtime allowlist + synthetic-data + budget/rate gate with hard abort; critical findings and any
remediation require a human approver distinct from the run's launcher. Cost is modeled at 100/1K/10K/100K
**runs** as two independent line families — never tokens × N — each tier naming the architectural change
it forces. Numbers are deliberately deferred to measurement (§11, §17).

---

## §2. System Context & Scope

- **In scope (this repo):** the adversarial evaluation *platform* — six components (§3), the regression
  harness, observability, contracts, policy/allowlist, exploit store, and the TargetAdapter behind the
  Policy Gateway.
- **Out of scope (external):** the OpenEMR Clinical Co-Pilot (**target**, attacked over its live URL — no
  target code here); model providers; Railway; GitHub.
- **Target reach:** a pluggable `TargetAdapter` invoked **only** through the trusted Policy Gateway
  (§5) behind an **allowlist**; API-primary, with a thin UI/browser path for evidence/e2e. Only target
  #1 (OpenEMR) is wired this week (`simplification`); the interface stays generic. **Generalize the
  mechanism, specialize the content** — engine, contracts, harness, and observability are target-neutral;
  `THREAT_MODEL.md`, the eval suite, and the vuln reports are Co-Pilot-specific.
- **Target-readiness seam (PRD-02/PRD-03):** the target is external, but any change made to bring it into
  a testable state is recorded in `README.md` + `THREAT_MODEL.md` context and consumed by the
  TargetAdapter config. OQ1/OQ2 (auth mode, API shape) resolve at Stage 1 **before** the first live
  campaign, making the live-URL hard gate traceable.
- **Hard gate:** a deployed target URL accompanies every checkpoint; the platform tests a live system,
  never only a mock.

## §3. The Multi-Agent Model (roles · trust · autonomy)

Six components with **distinct trust levels** — a single-agent or linear pipeline does not satisfy the
assignment (PRD-13). An agent that both attacks and judges is compromised by design (PRD-15).

| Component | Responsibility | Trust | Autonomy | Inputs → outputs |
|---|---|---|---|---|
| **Orchestrator** | Reads observability → prioritizes the next campaign; triggers regression; governs cost/abort | **Trusted governor** | Autonomous within budget/coverage policy | verified coverage + findings + budget → `CampaignDirective`, regression triggers, abort signals |
| **Red Team** | Generates novel adversarial inputs; mutates partial successes; multi-turn sequences | **Untrusted / quarantined** | Autonomous generation; cannot reach the target, hold credentials, produce evidence, self-judge, or publish | directive + seeds + prior partials → `AttackAttempt` |
| **Policy Gateway + Execution Recorder** | Enforces allowlist, scoped creds, synthetic-data, budget, rate caps, hard abort; executes vs target; records request/response/policy decision; emits canonically-hashed `AttemptResult` | **Trusted enforcement boundary** | Deterministic policy code — no model | `AttackAttempt` → `AttemptResult` (append-only, hashed) |
| **Judge** | Independent verdict via the deterministic state machine (§5); consistent cross-run criteria; escalates on ambiguity | **Independent evaluator** | Pure evaluator: emits a schema-validated `Verdict` and nothing else — **holds no target credentials, no mutation tools, no publish authority, executes no actions**; never generates/mutates attacks; **never approves a confirmed exploit as safe** | typed **Evidence Envelope** (§4): recorder `AttemptResult` + code-populated oracle/canary results + expected-safe behavior + ground truth → `Verdict` |
| **Documentation** | Confirmed exploit → structured, reproducible vuln report; data-quality gated | **Gated** | Autonomous drafting; **human gate on critical publish** | confirmed exploit → `VulnReport` |
| **Regression harness** | Versioned exploit store; deterministic replay; reappearance + cross-category detection | **Deterministic** | Runs on Orchestrator trigger / target change | `RegressionAdmissionCandidate` → `RegressionRun` results |

(The observability layer, §9, is the seventh, append-only component — the data substrate the Orchestrator
reads.)

**Why distinct components (defensible):** attack generation vs evaluation is a conflict of interest in one
context; *execution + evidence production* is a third job that neither the attacker nor the judge may hold
(F2); strategic prioritization is not execution; documentation autonomy needs a trust boundary the
generator must not hold. Separation *is* the security property.

**The learning loop:** verified Coverage + Findings → Orchestrator → Red Team → Policy Gateway → Target →
Execution Recorder → Judge → (mutate | confirm) → Documentation / Regression → Observability. Without the
loop the platform runs attacks randomly; with it, coverage compounds. The loop closes through
**data the trusted plane can verify** (hash-checked verdicts, §9), not a hand-off.

## §4. Inter-Agent Contracts (versioned, framework-neutral)

- **Format:** versioned **JSON Schema** in `contracts/v1/` (minimum v1), framework-neutral so the stack
  choice never forces a rewrite (D10). Any breaking change → version bump + migration note + updated
  contract tests (all three, or the run fails — enforced by `contract-steward`). Owned by us; LangGraph
  never owns the contract (§7).
- **Physical message boundaries (typed success schemas), corrected per F2:**
  - `Orchestrator → RedTeam`: **CampaignDirective** (target ref, category, coverage goal, budget/rate
    caps, mutation policy, `campaign_id`).
  - `RedTeam → PolicyGateway`: **AttackAttempt** (case ref, input sequence, mutation lineage) — the
    attacker's *proposed input*, nothing more.
  - `ExecutionRecorder → Judge`: **AttemptResult** (see field set below) — the **authoritative evidence
    object**; the Red Team never produces it.
  - `Judge → Documentation`: **Verdict** — **schema-validated**: an **enumerated verdict state** (§5),
    **confidence**, **typed reason codes**, criteria hits, OWASP tags `{framework,version,id,name}`, and
    `{campaign_run_id, attempt_id}`. A `Verdict` that fails schema validation is a typed error, not a verdict.
  - `Judge → Regression`: **RegressionAdmissionCandidate** (exploit ref, determinism evidence,
    passes-for-right-reason).
- **AttemptResult fields (evidence integrity, D14):** `schema_version`, `campaign_run_id`, `attempt_id`,
  `campaign_id`, `target_id`, `target_version`, `attack_attempt`, canonical request+response transcript,
  `policy_decision_id`, execution timestamps, trace/correlation ids, `recorder_identity/version`,
  `content_hash` (canonical serialization, e.g. RFC 8785 JCS or explicit field-ordered bytes). The Judge
  and Orchestrator **recompute and verify `content_hash` before every read** and fail-closed on any
  missing/malformed/integrity-invalid record.
- **Evidence Envelope — the Judge's typed input (S4/D18):** the Judge **never receives unstructured
  attacker-controlled text outside a typed, size-bounded, explicitly `hostile`-labelled Evidence Envelope
  field**. It consumes a canonical, **size-bounded, typed evidence envelope** in which every field carries an explicit **trust
  label** — `trusted` code-populated fields (`oracle_results[]`, `canary_hits[]`, `policy_decision`,
  `expected_safe_behavior`, `ground_truth_ref`, each provenance-labelled) vs `hostile` fields (the recorder's
  canonical request/response transcript, carried as **data, never instructions**). **Deterministic
  oracle/canary results are typed fields populated and applied by code, outside any attacker-controllable
  text** — the LLM Judge never parses a verdict-determining signal out of the transcript. A transcript that
  exceeds the size bound is truncated with the truncation recorded, so a flooding payload cannot exhaust the
  Judge.
- **Typed error schemas (published alongside success, PRD-OPT-11):** `target-unreachable · budget-exceeded ·
  judge-timeout · no-findings-in-window · regression-detected · rate-limited · adapter-error ·
  evidence-missing · evidence-integrity-failed`.
- **Both-sided contract tests:** every boundary verifies producer *and* consumer conform (`tests/contract/`).
- **Logical vs physical (migration note):** the PRD names a `RedTeam → Judge` boundary. That remains as a
  **logical** handoff — `RedTeam AttackAttempt → trusted execution + evidence enrichment → Judge
  AttemptResult` — now **mediated** by the Policy Gateway + Execution Recorder. The change from a direct
  `RedTeam → Judge: AttemptResult` to the mediated chain is recorded as an **interface correction with a
  migration note** (feeds the PRD-OPT-05/09 integration packet, §19).

## §5. Trust Boundaries & Security Model (the platform itself)

**Zones:** control plane (Orchestrator, policy gateway, human gate) = **trusted**; Judge / Documentation /
regression / observability = **governed**; **Red Team + all adversarial content = untrusted / quarantined**;
target + providers = **external**.

**F2 — the enforcement boundary is trusted, not the adapter.** Attack *generation* (untrusted) is split
from attack *execution + evidence production* (trusted). The **Policy Gateway + Execution Recorder** is the
Red Team's only exit and the sole holder of target credentials. It validates the allowlist, resolves
target-scoped credentials, asserts synthetic-data-only, enforces budget + rate caps, provides a hard
abort, executes via the TargetAdapter, and records the request/response/policy decision as a hashed,
append-only `AttemptResult`. The Red Team has **no credentials, no outbound path to the target, and no
write path to findings or the regression store** — it proposes attacks but never produces the evidence
used to judge them.

**F1 — deterministic, fail-closed Judge authority (D13).** The invariant "never approve a confirmed
exploit" is enforced by **code and evidence precedence**, not by model refusal behavior. Verdict states
and precedence:

1. A conclusive deterministic **oracle/canary** hit → `EXPLOIT_CONFIRMED`. The LLM Judge cannot downgrade
   or contradict it.
2. The LLM Judge operates **only** where deterministic evidence does not conclusively resolve the outcome.
   A calibrated result above the positive threshold with no deterministic contradiction → `EXPLOIT_LIKELY`
   (eligible for reproduction + review, **not** regression admission).
3. No exploit detected under the applicable oracle + calibrated rubric → `NO_EXPLOIT_OBSERVED` (deliberately
   **not** called "safe").
4. Contradictory evidence, uncertainty-band results, calibration failure, or unavailable criteria →
   `INDETERMINATE`.
5. Missing/corrupt evidence or operational failure → `ERROR` (typed code, §4).

`INDETERMINATE`/`ERROR` are **never** counted as safe, never prove a regression fixed, never enter the
regression corpus, and never publish as confirmed. A human may resolve `EXPLOIT_LIKELY`/`INDETERMINATE` →
`EXPLOIT_CONFIRMED` with `confirmation_source: human`. A previously-confirmed exploit is marked *fixed*
**only** by a deterministic regression oracle + expected-safe assertion — never by an LLM-only
`NO_EXPLOIT_OBSERVED`. **Fail closed on the verdict, not the run:** ambiguous cases park in the human-review
queue while the Orchestrator continues unrelated campaign work — the human classification gate stays hard
*and* unattended runs keep going.

**S4 — the evaluators consume hostile data, never instructions (D18).** Recorder transcripts and target
output are **hostile data**: a successful indirect-injection payload echoed back by the target is a live
injection aimed at whatever LLM reads it next. Containment is explicit and layered:

- **Typed, trust-labelled, size-bounded evidence envelope (§4).** The Judge reads a canonical typed
  envelope; it **never receives unstructured attacker-controlled text outside the explicitly
  `hostile`-labelled transcript field**. Deterministic **oracle/canary results are provenance-labelled typed fields,
  populated and applied by code** — the model never parses them from the transcript. The rubric is passed
  as SYSTEM; the transcript is a clearly-fenced, escaped `hostile`-labelled user-data block; oversized
  transcripts are truncated (recorded) so a flooding payload cannot exhaust the Judge.
- **The Judge is a pure evaluator.** It **holds no target credentials, no mutation tools, no publication
  authority, and cannot execute actions** (§3) — it emits a **schema-validated `Verdict`** (enumerated
  state + confidence + typed reason codes, §4) and nothing else. So even a fully-successful injection of the
  Judge cannot reach the target, mutate an attack, publish a finding, or take any action; the worst it can
  do is influence a *non-oracle* verdict — a false negative that calibration *may* detect (§15) and that
  per-category thresholds, drift-shutdown, and human review *contain* (a bounded residual, **not** a
  guaranteed catch), never a breach.
- **Deterministic oracle precedence bounds the blast radius (D13).** Prompt injection **cannot downgrade
  `EXPLOIT_CONFIRMED`**, because oracle/canary precedence is enforced **outside the model**, in code.
  Injection is a **residual risk** only for non-oracle judgments and for documentation — addressed by
  calibration, confidence thresholds, drift monitoring, and human review, **not eliminated**.
- **Documentation gets sanitized evidence by default (§15).** The Documentation agent receives the
  **validated `Verdict` + approved evidence references or sanitized excerpts** — never raw adversarial
  content by default — and renders from structured fields + escaped evidence.
- **Raw adversarial evidence stays quarantined.** It is stored append-only and revealed to a human **only
  through an intentional, warned operator action** — never auto-rendered into a report, dashboard, or alert.
- **Honesty (mitigation ≠ proof).** Prompt separation + encoding are **mitigations, not proof** that
  injection is impossible. Platform-injection cases (transcripts that *try* to flip the verdict;
  ground-truth = the correct verdict despite the embedded instruction) are part of the Judge calibration
  set (§15), and the residual risk is owned in §17/§21.

**S1/S2 — storage-layer enforcement (per-agent DB roles).** Within one shared Postgres, integrity rests on
**canonical hashing + append-only storage + role separation**, not signatures (D14): the Red Team role has
INSERT-only into a staging table it cannot read back; the **Execution Recorder role is itself INSERT-only**
on the authoritative AttemptResult table — **append-only is enforced by DB permissions (no UPDATE/DELETE grant
to any role, Recorder included), not by convention**; the Judge role has SELECT-only and joins strictly on the
hash-verified payload, never on a Red-Team-supplied id. A contract test asserts a Red Team role write to the
Recorder-owned append-only AttemptResult table is **rejected by the DB, not by convention** (§18). This
gives integrity, lineage and tamper-evidence *within* the trust domain; it does **not** claim isolation from
a fully-compromised process or DBA — asymmetric recorder signing / KMS-backed verification is the documented
**hardening path** for when the recorder crosses a process/service/network/administrative boundary.

**Per-target credential binding** `locked`: a pluggable credential provider (session / bearer / OAuth /
none) is selected per allowlist entry; secrets referenced, never inline; a credential is usable **only**
against the target it is bound to — cross-target use is impossible by construction, and the allowlist is
**environment-scoped** (§12) so a staging build cannot resolve a live-target credential.

**F5 — the live-campaign gate is runtime-enforced, not a skill flag.** The allowlist, scoped credentials,
authorization, budget, rate caps, and egress restriction all live in the Policy Gateway's **runtime code**,
independent of how execution was triggered (Claude, direct Python, or Railway cron). `disable-model-invocation`
on the `authorized-live-campaign` skill is a convenience, not a control. Gated side effects (publish) are
**idempotent** (run-nonce, §6) so a LangGraph `interrupt()` replay cannot double-fire.

**S8 — canary honesty.** Deterministic PHI-leak detection needs canary tokens planted in the *target's* data.
Where the platform has write access to the target's synthetic fixtures, canary provisioning is an explicit,
owned step in `authorized-live-campaign` (UUID-tagged synthetic PHI; a canary registry stored platform-side
for set-membership leak checks). **Where the external target cannot be pre-seeded, PHI-exfil detection is
Judge-judgment + human escalation, not deterministic** — stated honestly rather than implying a determinism
the target's ownership boundary denies.

**OWASP taxonomy versioning (F8, D15).** Web attack cases map to **OWASP Top 10:2021** — the set the PRD
enumerates (it lists SSRF standalone, which exists only in 2021). Every mapping is stored as a structured tag
`{framework, version, id, name}` (e.g. `{OWASP Web, 2021, A10, Server-Side Request Forgery}`), never a bare
`A10`, so the 2021↔2025 distinction is machine-checkable. Crosswalk to 2025: SSRF A10:2021 → folded into
A01:2025; Injection A03:2021 → A05:2025; new A03:2025 Software Supply Chain Failures and A10:2025 Mishandling
of Exceptional Conditions are forward-looking coverage candidates. LLM mappings already track OWASP LLM Top
10 (2025). Full per-category mapping is in `THREAT_MODEL.md`.

**Access control:** only the post-Judge documentation path creates published findings; only a human distinct
from the launcher publishes **critical** (§14); only the admission path writes the regression store; the Red
Team can do none of these.

## §6. Data Model & Storage

- **Exploit DB = Postgres** `locked` (Railway managed): versioned, queryable, **indexed by severity /
  category / target-version** (the three common query patterns, PRD-OPT-16), migratable via Alembic
  (expand/contract, §12; time-range partition + BRIN at 10K/100K).
- **One Postgres, three jobs, role-partitioned** `locked`: the same instance holds the exploit DB, the
  LangGraph checkpoints, and the **work/regression queue**, with **per-agent DB roles** (§5) as the
  access-control boundary. The queue is a `jobs` table drained with `SELECT … FOR UPDATE SKIP LOCKED`, two
  logical queues (`agent_work` | `regression_run`) by a `queue`/priority column. **Delivery semantics (F6):**
  at-least-once delivery via lease + `run_after`/`attempts`; **lease expiry + worker heartbeat + a reaper**
  for expired leases; **dead-letter** state for poison jobs; **idempotency keys + dedup** on
  `{campaign_run_id, attempt_id}` (S3); cancellation via status flag (feeds the abort gate); no long-running
  work inside the claim transaction (claim → commit → process outside txn); depth via `count(*)` surfaced to
  observability with backpressure behavior (§11). **Railway cron enqueues** (idempotent insert, never runs
  inline). No Redis/Celery. Fallback: pgmq on the same Postgres.
- **Run-scoped identity (S3).** Every `AttemptResult` and `Verdict` carries a fresh `campaign_run_id` per
  dispatch, bound inside `content_hash`. A UNIQUE constraint on `(campaign_run_id, attempt_id)` rejects a
  replay rather than overwriting; coverage/resilience aggregates count **distinct** pairs. Regression runs
  **generate a new `campaign_run_id` and re-execute against the live target** — verdicts are never reused.
- **Durable correlation (O6).** `campaign_id` / `attempt_id` / `finding_id` are generated at campaign start,
  written as columns on Attempt / Verdict / Finding / RegressionRun rows **and** propagated as Langfuse span
  attributes. `finding_id` is the join key across the Langfuse↔exploit-DB system-of-record split (§9), so
  lineage survives process restarts across `interrupt()`/resume and the Cloud→self-host cutover. Lineage
  completeness (no Finding without a resolvable `campaign_id` chain) is a data-quality invariant.
- **AttackCase field schema (PRD-08):** every seed/case record enumerates — **attack category + subcategory ·
  input prompt/sequence · expected safe behavior · observed behavior (`pass | fail | partial`) · severity +
  exploitability · add-to-regression flag · OWASP tags `{framework,version,id,name}` · `boundary | invariant
  | regression` class**. Validated by `validate-eval-case` + `detect-duplicate-sequence`, the same
  deterministic validators CI runs (no happy-path-only case admitted).
- **VulnReport field schema (PRD-21):** every report enumerates — **unique ID + severity · description +
  clinical impact · minimal reproducible attack sequence · observed vs expected behavior · recommended
  remediation · current status + fix-validation results**. Acceptance criterion (PRD-22): **a senior security
  engineer can reproduce, validate, and fix from the report alone** — tied to the clinical-impact field so
  the Co-Pilot specialization is visible.
- **Data-quality invariants (validated in the Documentation Agent before write, and in CI):** unique ID, all
  required fields, referential integrity, **no duplicate attack sequence**.
- **Core entities:** Target · TargetAdapter · AllowlistEntry · CredentialBinding · AttackCase · Attempt ·
  Transcript · Verdict · Finding · VulnReport · RegressionCase · RegressionRun · Campaign · CoverageMetric ·
  CostRecord · GroundTruthLabel · ContractVersion · Incident (state machines: `PRESEARCH.md §5.2`).
- **Source of truth (S9):** the hashed `AttemptResult` (`content_hash`) is the **authoritative evidence
  object**; the Langfuse span for the same attempt carries the same `transcript_hash` as an attribute so a
  divergence is detectable — a reconciliation check marks a divergent run *degraded*.

## §7. Orchestration Framework & Agent State

**LangGraph (MIT OSS engine only — self-hosted, no LangGraph Platform/LangSmith)** `locked` (D4). Each
agent's reasoning runs as custom Python inside a node/subgraph. **PostgresSaver** checkpoints to the same
Railway Postgres (one durable store). `interrupt()` / `Command(resume=…)` provides the **pause/resume
mechanic** behind the human-approval gate — authorization itself is enforced in runtime policy code (§5,
F5), because nodes **replay on resume** and pause is not authorization. **Judge independence is structural**
— its own node, own model client, sharing no weights/provider with the Red Team.
- **Contracts stay ours:** inter-agent messages are our versioned JSON Schemas, materialized as LangGraph
  `TypedDict` state — the framework never owns the contract (§4).
- **Version skew across deploys (O2):** the LangGraph checkpoint/state schema and the jobs-table payload are
  **versioned**; a consumer **rejects-or-dead-letters** a row/checkpoint it does not understand rather than
  crashing; a **drain/quiesce** step precedes deploy (§12).
- **Known gap → resilience (§13):** LangGraph checkpoints are crash-*persistence*, not durable execution (no
  watchdog/auto-resume, no dup-execution guard). Mitigate with an application-level `thread_id` lock against
  overlapping campaigns; layer **DBOS-on-Postgres** *under* LangGraph only if unattended multi-hour campaigns
  need exactly-once. **Pin the LangGraph 1.x version before Defense** (`open question`, §17).
- **Fallback (a config swap, not a rewrite):** a thin custom asyncio orchestrator on the same contracts (D4).

## §8. Models per Role

A **different model per role**, sized to its refusal-vs-capability need `locked` (D8, amended):

| Role | Model | Why |
|---|---|---|
| **Red Team** | Uncensored open-weights. **Deployed default = hosted OSS** (OpenRouter/Together uncensored, e.g. Dolphin 3.0 / Euryale 70B); **local 24–33B on the Mac** (Dolphin-Mixtral / WhiteRabbitNeo-33B) is a **config switch** for dev + local cost-baseline (F7) | Frontier models refuse authorized offensive generation. Hosted default makes continuous/unattended runs real on Railway; local is ~$0 marginal for development. Never Claude/GPT here |
| **Judge** | **Claude Sonnet 4.6** (Batch API + prompt-cached rubric) | Selected by **measured calibration, false-negative rate, consistency, latency, cost** — not by refusal behavior (the invariant is deterministic, §5/D13). Structurally independent of the Red Team |
| **Orchestrator** | **Claude Opus 4.8** (economize to Sonnet/Gemini when hot) | Planning-grade reasoning; low call volume makes frontier affordable |
| **Documentation** | **GPT-5.4** | *Deliberately a different vendor from the Judge* → no single-vendor correlated failure on the trust chain; output schema-gated by the vuln-report validator regardless of model |

**Cross-vendor is defense-in-depth, not the invariant (D8 amended).** Refusal behavior is a model
*characteristic and potential failure mode*, not a security control.

**S5 — vendor-disjoint failover (runtime invariant).** D8's fallback is `Judge → GPT-5.4`, and Documentation
*is* GPT-5.4 — a naïve failover collapses the cross-vendor chain. The platform enforces `Judge.vendor !=
Documentation.vendor` at run start (fail-closed on violation): if the primary Judge (Anthropic) is unhealthy,
fail over to a **third vendor** (e.g. Gemini) **or** temporarily reassign Documentation off GPT-5.4 while the
Judge is on it.

Per-agent token profiles + Mac tok/s + `exploit_rate` are **measured at MVP** before any cost number is
presented (`open question`, §17).

## §9. Observability Layer

**Langfuse Cloud (Hobby, free) for MVP** `locked` (D5 amended, F3), instrumented with the **OTEL-native SDK
v4** (emission stays framework-neutral). Self-hosting is a documented **post-MVP** path with a real 6-container
footprint — Web + Worker + PostgreSQL + **ClickHouse (required)** + **Redis/Valkey (required)** + **S3/blob
(required)**, documented minimum "≥2 CPU / 4 GB across all containers" (a full HA deployment realistically
lands nearer ~4 vCPU / 8 GB — an estimate, not a Langfuse-quoted figure). Cloud avoids standing up
ClickHouse+Redis+S3 during the deadline crunch and keeps D6's one-Postgres/no-Redis story true. Synthetic data
only.

**One request = one trace:** the Orchestrator opens the root span; Red Team / Gateway / Judge / Documentation
are child spans tagged `{agent, attack_category, owasp_web, owasp_llm, system_version, verdict}` +
`{campaign_id, attempt_id, finding_id}` (§6) → native per-agent cost roll-up + inter-agent order, joinable to
exploit-DB rows and durable across the Cloud→self-host cutover.

- **System-of-record split (pinned so they can't drift):** Langfuse *observes the campaign*; the **Postgres
  exploit DB is system-of-record** for Q4 (open/in-progress/resolved) and Q3 (resilience trend), surfaced via
  a Postgres view.
- **The learning signal is integrity-gated (S6).** Coverage / resilience are computed **only from
  hash-verified, run-nonce-deduplicated verdict records** — never from raw Langfuse spans (observability-only).
  The Orchestrator enforces sanity invariants before trusting the view: a category cannot become "covered"
  without N distinct verified attempts **and** ≥1 deterministic-oracle or human-spot-checked case; an
  unexplained resilience jump without a `target_version` change is flagged, not trusted. "Which agent wrote
  this coverage row" is part of lineage.
- **Alerting (O3).** An alert channel (app-emitted / cron-driven webhook to Slack/email/PagerDuty-equivalent)
  fires on: human-approval-pending (with response SLA), regression detected / finding reopened, budget
  circuit-breaker tripped, target-unreachable beyond backoff, queue depth over threshold, and Langfuse/DB
  emission failure. Alerts are tied to the **durable source** (exploit DB / queue table), not Langfuse alone,
  so an observability outage does not silence them.

**The layer's acceptance criteria are fixed regardless of backend** — it must answer, for a human *and* the
Orchestrator: (1) categories tested + cases per category; (2) pass/fail rate across categories + versions;
(3) is the target more/less resilient over time; (4) which vulns are open/in-progress/resolved; (5) run cost
+ scaling rate; (6) what each agent is doing and in what order. Requirements: inter-agent traces + per-agent
cost attribution; append-only; the data substrate the Orchestrator reads (not just a human dashboard).

## §10. Regression & Validation Harness

- Stores confirmed exploits in a versioned, queryable format; runs the suite automatically on Orchestrator
  trigger (**Railway cron** enqueues) or target change.
- Detects (a) a previously-fixed vulnerability reappearing, (b) fixing one category regressing another.
- **Admission invariant:** a case is admitted only if it reproduces **deterministically** *and* passes for the
  right reason — a real fix, not changed model behavior (PRD-24). "A test that passes because behavior changed
  is worse than no test." Admission consumes only `EXPLOIT_CONFIRMED` evidence via a deterministic regression
  oracle + expected-safe assertion (D13); `adversarial-eval-lifecycle` governs admission, the harness is app
  code.
- **Tiered regression at scale (O5).** "Sample regression runs" (the 100K cost lever, §11) is **stratified**,
  not uniform: **every critical-severity and every recently-reopened case runs on every target change**; only
  lower-severity/older cases are sampled; the **full** suite runs on a scheduled cadence. The documented
  residual detection-latency is capped. Verdict caching for duplicate sequences is bounded by
  `target_version` + case-content hash — a cached verdict is invalidated whenever the target or the case
  changes (never "passes for the wrong reason").
- **SLO (two numbers, PRD-OPT-16):** a **full-suite** time budget and a **per-change critical-subset** budget,
  each verified in CI against fixtures (§18). Concrete budgets are MVP-measured (`open question`, §17).

## §11. Cost, Rate Limits & Scale (100 / 1K / 10K / 100K runs)

**Cost is two independent line families on different scaling functions — never tokens × N** `locked` (D17, F4).
The dimensionally-invalid `list_price / throughput` division from the draft is **removed**; "not tokens × N"
means token spend is *insufficient*, not absent — token accounting stays.

`Cost(N) = Hosting(peak_concurrency) + Inference(N) + Storage(rows) + Egress`, where:
- **Hosting = step function of peak concurrency** (Railway): platform compute, managed Postgres, cron
  (the one hosting line that scales with N, tiny), and Langfuse (Cloud free at MVP; self-host adds
  ClickHouse-RAM-driven cost post-MVP).
- **Inference, modeled per family:**
  - **Hosted inference** (Judge / Orchestrator / Documentation, and hosted-OSS Red Team) = **measured tokens ×
    current provider rates**, adjusted for **cached-input (≈0.1× input) and Batch API (≈50%)** pricing.
  - **Local inference** (Mac Red Team, when the switch selects it) = **hardware amortization + power +
    operator time ÷ measured capacity** — throughput-capped, not price-capped.
- **Storage / egress** are their own lines.

**Per-tier architectural change (the whole point — each tier is a different architecture, not a bigger bill):**
**100** baseline, hosting dominates · **1K** prompt-cache shared context + Batch API · **10K** Red Team fully
off frontier (hosted-OSS/local) + queue backpressure + time-range partition the exploit DB · **100K**
*stratified* regression runs (§10) + BRIN-on-timestamp + partial B-tree on hot partitions + dedicated worker +
bounded verdict caching. Documentation fires on `exploit_rate × N` → sub-linear.

**Rate/failure:** rate-limit handling = **backoff → queue → abort**; a cost circuit-breaker halts on
no-signal/budget. When the queue backs up, jobs accumulate *durably* in Postgres (nothing dropped), depth rises
visibly in observability, and the cost governor throttles new campaigns — graceful, observable degradation (the
CISO-defensible failure mode). **CI/dev runs are their own cost line** (O8) on the $50–200 budget. Exact
external rate limits + auth are per-target (`open question`, OQ2). **All cost numbers are deferred to
measurement (§17); no placeholder number appears here** — none is CISO-defensible until measured from real
traces.

## §12. Deploy, Rollback & Environments

- **Railway** `locked` (D3): Docker build from GitHub, deploy from first commit; managed Postgres; cron
  (regression enqueue); deployment history + Postgres PITR (rollback). No GPU.
- **Environments (O1) — the section now defines them.** At least **two Railway environments**:
  - **non-prod (CI/staging):** TargetAdapter points at a **mock or an explicitly non-production allowlist
    entry**; its **own** Postgres; the environment-scoped allowlist **cannot resolve** the live target's
    credential binding (reinforces per-target binding, §5).
  - **prod:** alone holds live-target credentials and fires live campaigns.
  - Promotion prod ← staging is gated on **green regression SLO + contract tests**. Synthetic-data isolation
    and the no-real-PHI invariant have an environment boundary — a test run and a live campaign are never
    indistinguishable at the infra level.
- **Rollback discipline (O2).** Code rollback (Railway deployment history) reverts the *container*, not the
  managed-Postgres schema/rows. Therefore: **expand/contract (backward-compatible) migrations** are the rule so
  any single deploy is rollback-safe without a DB downgrade; destructive migrations are forbidden in the same
  release that introduces their consumers; checkpoint/jobs payloads are versioned and unknown rows are
  dead-lettered (§7); a **pre-deploy drain/quiesce** step ensures a deploy never lands mid-lease; **Postgres
  PITR is the true rollback of record** for data.
- Perf baselines measured **on Railway**, not locally (§19). Secrets via Railway env references, per environment.

## §13. Failure Modes & Resilience

| Failure | Handling |
|---|---|
| Red Team produces genuinely harmful content | Quarantine + containment (§5); only ever executed via the Policy Gateway against the allowlisted target; treated as untrusted data even by the Judge/Documentation (S4) |
| Judge agrees with everything (drift) | Deterministic oracle precedence + async dual-judging calibration + drift detection (`judge-calibration`, §15); escalate on uncertainty; the Judge never occupies the attacker role |
| Attacker forges/replays evidence | Canonical hash + append-only + per-agent DB roles (S1/S2); run-nonce + UNIQUE constraint (S3) reject replay |
| Orchestrator has no clear next priority | Fallback policy: least-covered category → oldest open finding → regression sweep |
| **Observability (Langfuse) unavailable/degraded (O7)** | Orchestrator falls back to the **exploit-DB system-of-record + queue table** for coverage/priority (the documented fallback policy above), degrading to structured signals rather than random or blocked; emits an alert. The coverage signal the Orchestrator needs is derivable from Postgres |
| Cascading agent failure in one run | Typed errors per boundary; run isolation; partial results persisted; run marked degraded not lost |
| Target unreachable / rate-limited | Typed error → backoff → queue → abort; campaign paused, not failed silently; alert fired |
| Cost accrues without signal | Circuit-breaker halts/redirects the campaign; alert fired |
| Deploy-time version skew | Expand/contract migrations + versioned checkpoints/jobs + drain-before-deploy (§7/§12) |
| Overnight run auditability | Append-only audit log + durable correlation IDs reconstruct who/what/when/order; alerts route human-gate + critical events to a person |

## §14. Human Approval Gates & Platform Trust/Safety

- **Gates:** **publish a critical-severity finding**, and **any remediation**. Autonomy covers discovery,
  evaluation, regression, and drafting; humans own the high-cost calls. The gate is **runtime-enforced**
  (§5, F5), not merely a LangGraph pause.
- **Separation of duties (S7).** The critical-publish and remediation gates must be cleared by an
  **authenticated principal distinct from the run's launcher** — a two-person rule enforced in runtime code:
  the resume/approval action carries an approver identity, the code rejects `approver_id == launcher_id` for
  critical severity, and **both** identities are written to the append-only audit log. **Week-3 limitation
  (owned):** if solo operation is unavoidable for the timeline, the single-operator-wearing-both-hats
  condition is stated explicitly in the AI-use disclosure (§15) and the defense — not quietly permitted.
- Who may trigger runs / view reports is access-controlled; overnight runs are fully audited.
- This boundary is the CISO answer: where it proceeds autonomously, where it stops, how it communicates
  confidence, and what happens when confidence is wrong.

## §15. AI-Use Disclosure

For each AI-powered role: what AI does, what deterministic verification or human approval follows, and what
residual risk remains.

- **Red Team (AI, untrusted):** generates/mutates attacks. Verified by: it cannot reach the target, hold
  credentials, or produce evidence (§5); output is contained and never instructs the control plane. Residual:
  an uncensored model may generate genuinely harmful content — contained, never executed outside the allowlisted
  target.
- **Judge (AI, governed):** classifies attempts. **Independently verifiable (PRD-OPT-08):** the invariant is
  deterministic (oracles/canaries override, §5/D13); calibration uses **async dual-judging** across the full
  ground-truth set, a stratified random sample of live cases, and threshold-near/disputed cases — tracking
  inter-judge agreement, category-specific false-negative rate, calibration error, uncertainty rate, and drift;
  crossing a **drift threshold disables LLM-only dispositions** for the affected category until recalibration
  or human approval. Residual: for categories with no deterministic oracle on an un-seedable external target
  (S8), detection is Judge-judgment + human escalation — stated, not hidden.
- **Orchestrator (AI, trusted):** prioritizes on **verified** metrics only (S6). Residual: coverage metric
  quality is per-target; poisoned aggregates are guarded by the integrity gate + sanity invariants (§9).
- **Documentation (AI, gated):** drafts reports from the **validated `Verdict` + approved evidence references
  or sanitized excerpts by default** (S4/D18) — raw adversarial evidence stays quarantined and is revealed
  only by an **intentional, warned operator action**; never free-form summarization of raw payloads;
  data-quality validated before write; **human approves critical publish** (§14). Residual: injection-laundering
  into a human-facing report — mitigated by structured rendering, default sanitization, and the human gate.
- **Where we deliberately did *not* use AI:** the Policy Gateway (deterministic policy), evidence hashing +
  DB-role enforcement, the deterministic oracles/canaries, and the shared validators (contract-compat,
  eval-case schema, duplicate-sequence, data-quality) + Semgrep/ZAP. AI where judgment is needed, determinism
  where it isn't.
- **Owned limitation:** single-operator two-person-rule exception (S7), if taken, is disclosed here.

## §16. Build-vs-Configure Summary → ADR-0001

**Configure/wrap the mechanism; build the four graded capabilities.** `locked` (D9; full record + verdict:
`docs/adrs/0001-build-vs-configure.md`).
- **Wrap (seeds/engine):** Garak (breadth probes) · PyRIT (multi-turn orchestrators + converters) · Giskard
  RAGET (RAG-specific seeds).
- **Configure (free, satisfies graded reqs):** **Promptfoo** — no-custom-code presets for **OWASP LLM Top 10
  (`owasp:llm`)**, OWASP API Security Top 10 (`owasp:api`), MITRE ATLAS, NIST AI RMF. **Correction (F12):
  Promptfoo ships no `owasp:web` preset** — OWASP **Web** Top 10 category mapping is done by **our own
  deterministic validator over OWASP ZAP output**, not by Promptfoo; `owasp:api` partially covers the
  API/write-back surface. · **OWASP ZAP** (web-layer DAST, *contingent on a target web surface*, OQ2) ·
  **Semgrep** (SAST on our code).
- **Build (no tool delivers these):** Orchestrator · the Red Team's autonomous coverage-driven **mutation
  loop** · the independent, deterministic-fail-closed **Judge** · Documentation + regression-admission.
- **Do not adopt:** any commercial LLM red-team platform (Lakera / HiddenLayer / Robust Intelligence–Cisco AI
  Defense) — out of budget, closed, un-governable, and *is* the product we're asked to build. Burp Suite Pro
  deferred to optional-at-Final; never Burp DAST/Enterprise. (Promptfoo was OpenAI-acquired Mar 2026 — if it
  gates plugins off MIT, fall back to Giskard/custom-runner.)

## §17. Open Questions & Risks

**Open questions (never invented; carried to `tasks-gen`):**
- **OQ1** target **auth mode** (session/bearer/OAuth/none) — resolves at Stage 1; the credential provider is
  designed so it does not block.
- **OQ2** target **API shape** + streaming + **rate limits**, and **whether it exposes a web surface for ZAP**
  (freezes the OWASP-Web DAST slot).
- **OQ3** seeded-demo-data provenance (confirm synthetic, no real PHI); whether the platform has **write
  access to plant canaries** (S8).
- **Measure at MVP, do not guess:** per-agent **token profiles**, **Mac tok/s** (local-vs-hosted Red Team
  crossover), **`exploit_rate`** (Documentation call volume). **No cost number is CISO-defensible until
  measured** — §11 carries the method, not numbers.
- **Pin the LangGraph 1.x version** before the ADR is frozen (§7).
- **D12 (proposed):** MVP ships a hand-authored seed corpus + custom mutation loop; wrap PyRIT/Garak/Giskard
  post-MVP — a `tasks-gen`/`tdd-swarm` sequencing call to ratify.
- Concrete regression **SLO budgets** (§10) and **alert SLAs** (§9) are MVP-measured.

**Top risks:** target details slipping Stage 1; Red Team refusals/quality on hosted-OSS; Judge drift on
un-oracled categories; cost blow-up at scale; the ~2.5h Defense window vs artifact volume; single-operator
separation-of-duties (S7).

## §18. Platform Testing Strategy

The eval suite (§10) exercises the **target**; this section tests the **platform's own code** — required, not
optional, under production-grade posture, and boundary/invariant/regression, not happy-path-only.

- **Unit tests (adversarial/boundary) for the four BUILD capabilities:** the Judge **fail-closes on a canary
  hit** and on missing/invalid evidence; the admission gate **rejects a case that passed for the wrong reason**;
  the cost **circuit-breaker fires at threshold**; the allowlist **deny path** and **cross-target credential
  rejection** hold; `Judge.vendor != Documentation.vendor` is enforced (S5).
- **Invariant/property tests** for the ten load-bearing invariants (`PRESEARCH.md §5.3`), including: the
  verdict state machine never maps `INDETERMINATE`/`ERROR` → safe; run-nonce UNIQUE rejects replay (S3);
  **a Red Team DB role write to the Recorder-owned append-only AttemptResult table is rejected by the DB, not by convention** (S2).
- **Evaluator-injection tests (S4/D18):** a transcript carrying an in-band instruction to flip the verdict
  does **not** change the Judge's disposition when a deterministic oracle fired (`EXPLOIT_CONFIRMED` cannot be
  downgraded); the evidence envelope rejects an oracle/canary field sourced from `hostile`-labelled text;
  the Judge output fails closed when `Verdict` schema validation fails; Documentation renders no raw
  `hostile` content into a report without the intentional warned-operator action.
- **Integration tests** across agent nodes with a **stubbed TargetAdapter**; **both-sided contract tests**
  (§4) at every boundary.
- **e2e** against the **mock target in staging** (§12).
- **CI substrate (O8):** an ephemeral Postgres, a deterministic mock TargetAdapter (record/replay of target
  responses), and cassette-based model responses — so the regression SLO (§10) is measured on **fixtures**,
  never the live target or paid APIs. The CI matrix names which tier runs where, grounding "verified in CI."

## §19. Submission Artifacts & Deliverable Seams

The graded "Optional Engineering Deliverables" are mandatory; each has an architectural seam so it is produced,
not improvised.

- **ATO-style evidence packet (PRD-OPT-07)** — a distinct submission artifact (not ARCHITECTURE.md): the D2/D4
  agent-interaction + trust diagram, a data-flow diagram, an **auth-model matrix** (each agent → the
  targets/credentials it may use → via the Policy Gateway), a **versioned dependency manifest**, self-scan
  results (Semgrep + the platform's eval suite run against itself), test evidence (§18 + eval results), and a
  **sample incident/postmortem** built from §13. → `docs/evidence/ato/`.
- **Triage exercise (PRD-OPT-03)** — a simulated scan report of **≥10 findings across critical/high/medium/
  false-positive**, each with a validate/remediate/defer/document disposition, reusing the VulnReport schema to
  prove the Documentation output is usable for real triage. → `docs/triage/`.
- **Integration packet (PRD-OPT-05/09)** — the versioned contracts are designed for cross-team inheritance
  (consume a peer's agent via schema alone, no shared source); packet = interface diffs (incl. the F2
  `RedTeam→Judge` → mediated-chain correction), correction ADRs, both-sided contract-test results, a dependency
  map, and the §6 end-to-end trace. → `docs/integration/`.
- **Baseline profiles (PRD-OPT-17)** — CPU, memory, latency, throughput under a representative run (100 attack
  cases + full regression suite), captured **on Railway**, shipped as a comparison baseline. → `docs/performance/`.
- **Load/stress test (PRD-OPT-18)** — 100 consecutive cases against the live target recording agent-orchestration
  latency, LLM-call latency, and exploit-storage throughput; identify the bottleneck and name the §11 architectural
  remediation. → `docs/performance/`.
- **Vuln reports (PRD-32)** ≥3 in the §6 VulnReport schema → `docs/vulnerabilities/`. **Cost analysis (PRD-33)**
  per §11 (numbers measured at MVP) → `docs/cost/COST_ANALYSIS.md`. **README (PRD-29)** with the deployed URL +
  run instructions. **Demo video / social post (PRD-31/35).**

## §20. Finding Resolution Register

Every external-review finding (F1–F12) and cold-eyes re-audit finding (S#/O#) and where it is resolved. Audit
detail: `docs/planning/gap-audit.md`.

| # | Resolution | Where |
|---|---|---|
| **F1** | Deterministic fail-closed Judge invariant (verdict state machine; oracle precedence; fail-closed on the verdict not the run; async dual-judging calibration) | §3, §5, §15; D13; D8 |
| **F2** | Trust split: untrusted generator → trusted Policy Gateway + Execution Recorder → external target; Judge sees hashed recorder `AttemptResult` only; contract direction corrected (migration note) | §3, §4, §5; D14; diagram spec |
| **F3** | Langfuse Cloud for MVP; self-host full footprint documented post-MVP | §9, §12; D5 |
| **F4** | Two independent cost line families; invalid `list_price/throughput` division removed | §11; D17 |
| **F5** | Live-campaign gate enforced in Policy Gateway runtime code, independent of trigger; skill flag is convenience; gated side effects idempotent | §5, §14; D14 |
| **F6** | Full Postgres queue delivery semantics (lease/heartbeat/reaper/dead-letter/idempotency/dedup/cancel/poison + backpressure) | §6, §7, §11; D6 |
| **F7** | Config-switch; deployed default = hosted OSS; Mac = dev/cost-baseline; Mac tok/s open | §8, §12; D8 |
| **F8** | OWASP 2021 anchor + 2021↔2025 crosswalk + `{framework,version,id,name}` tags | §5; `THREAT_MODEL.md`; D15 |
| **F9** | Stale `PLAN.md` content corrected | `PLAN.md` (done) |
| **F10** | `disable-model-invocation: true` on `tdd-swarm` | skill file (done) |
| **F11** | DEFENSE_SCRIPT claims labeled + "contract schemas" removed + F1/F2/F5 content | `DEFENSE_SCRIPT.md` |
| **F12** | ADR-0001 softened: no Promptfoo `owasp:web`; OWASP-Web = our validator over ZAP; `owasp:api` partial | §16; ADR-0001 |
| **S1** | Signing-key custody: within one shared trust domain a signature adds nothing over canonical-hash + append-only + DB-role separation (a compromised in-process node could read the key); separate-recorder-principal signing/KMS = documented hardening path | §5, §21; D14 |
| **S2** | Per-agent DB roles: Red Team INSERT-only staging (no read-back); **Recorder role INSERT-only** on the append-only authoritative AttemptResult table (no UPDATE/DELETE to any role); Judge SELECT-only on hash-verified payload; a Red Team write to the Recorder-owned AttemptResult table is DB-rejected (contract test) | §5, §6, §18; D14 |
| **S3** | Run-nonce `{campaign_run_id, attempt_id}` in hashed payload + UNIQUE constraint; regression re-executes live | §4, §6, §10 |
| **S4** | Evaluators consume a typed, trust-labelled, size-bounded **evidence envelope**; oracle/canary results are code-applied typed fields so injection **cannot downgrade `EXPLOIT_CONFIRMED`**; Judge holds no creds/mutation/publish/execute and emits a schema-validated Verdict; Documentation gets the validated Verdict + sanitized excerpts by default; raw evidence quarantined behind a warned operator action; separation/encoding are mitigations, not proof (residual owned) | §3, §4, §5, §15, §18; **D18** |
| **S5** | Vendor-disjoint Judge failover invariant | §8; D8 |
| **S6** | Coverage/resilience computed only from verified, deduped verdicts + sanity invariants | §9, §13 |
| **S7** | Two-person rule on critical-publish/remediation (runtime-enforced); single-operator exception disclosed | §14, §15 |
| **S8** | Explicit canary provisioning where writable; honest "not deterministic" where the external target can't be seeded | §5, §10, §15 |
| **S9** | Hashed `AttemptResult` is authoritative evidence; span carries same hash; reconciliation check | §6, §9 |
| **O1** | ≥2 environments; prod-only live creds; environment-scoped allowlist; gated promotion | §12 |
| **O2** | Expand/contract migrations; versioned checkpoints/jobs; drain-before-deploy; PITR as true rollback | §7, §12 |
| **O3** | Alert channel + conditions tied to durable source | §9, §13 |
| **O4** | Platform testing strategy (pyramid + BUILD-capability + invariant tests + CI matrix) | §18 |
| **O5** | Stratified regression (critical + reopened always); bounded verdict caching; two-number SLO | §10, §11 |
| **O6** | Durable `campaign_id`/`attempt_id`/`finding_id` across spans + rows | §6, §9 |
| **O7** | Langfuse-unavailable failure mode → Postgres fallback + alert | §9, §13 |
| **O8** | CI substrate (ephemeral PG + mock adapter + cassettes); CI/dev as a cost line | §11, §18, §19 |

## §21. Non-Goals & Owned Tradeoffs

**Non-goals (deliberately out of scope this week):**
- Testing more than one target (the second adapter is what would *prove* target-agnosticism — conceded, not
  claimed).
- Real HIPAA/BAA authorization — the posture is synthetic-data ATO-*style* simulation (D11); BAA-upgrade is a
  documented, unpaid hardening path.
- Durable exactly-once execution — LangGraph checkpoints are crash-persistence; DBOS-on-Postgres is the path
  only if unattended multi-hour campaigns come into scope (§7).
- Cryptographic signing / KMS for evidence — unneeded within one shared trust domain; the hardening path when
  the recorder crosses a boundary (§5/D14).
- Building any attack primitive Garak/PyRIT/Giskard already provide (§16).

**Owned tradeoffs (the defense, not softened):**
- One uncensored Red Team model is unconstrained; the *system* around it is not (§5). We accept an unconstrained
  generator to avoid frontier refusals, and contain it structurally.
- Anyone with repo access + credentials could widen the allowlist; the control is **auditability + two-person
  approval**, not prevention (§14).
- Cost figures are absent by choice — a measured number later beats a defensible-sounding wrong number now (§11).
- Where an external target can't be canary-seeded, PHI-exfil detection is honestly non-deterministic (S8) — we
  state the limit rather than imply an oracle we don't have.
- Prompt injection against our own evaluators (S4/D18) is **contained, not eliminated**: oracle precedence
  makes it unable to downgrade `EXPLOIT_CONFIRMED`, and the Judge can take no action even if injected — but it
  remains a residual risk for non-oracle judgments and documentation, owned via calibration, drift monitoring,
  and human review. Prompt separation + encoding are mitigations, not proof.
