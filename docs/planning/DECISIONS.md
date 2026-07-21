# DECISIONS.md — AgentForge / Adversarial Machine

> ADR-style decision log. Each entry: the decision, status, why, the fallback, and what would
> invalidate it. Grounded in `RESEARCH.md` (July 2026 sources) and the `/arch-draft` interview.
> The build-vs-configure decision has its own standalone record: `docs/adrs/0001-build-vs-configure.md`
> (a required Architecture Defense deliverable). Status: `locked` unless noted.

| # | Decision | Status |
|---|---|---|
| D1 | Planning mode = Standard; posture = production-grade | locked |
| D2 | Language = Python 3.12+ | locked |
| D3 | Platform host = Railway (Docker/GitHub, managed Postgres, cron, deployment-history rollback; no GPU) | locked |
| D4 | Orchestration = LangGraph (OSS engine only, self-hosted) + PostgresSaver | locked |
| D5 | Observability = **Langfuse Cloud for MVP** (OTEL SDK v4), self-host post-MVP; exploit DB = system-of-record for finding status | locked (rev. 2026-07-20, F3) |
| D6 | State + queue = one Postgres; `SKIP LOCKED` jobs table + **full delivery semantics**; cron enqueues; no Redis; **per-agent DB roles** | locked (rev. 2026-07-20, F6/S2) |
| D7 | Exploit DB = Railway Postgres (Alembic migrations; partition/BRIN at scale) | locked |
| D8 | Models: RedTeam=**hosted-OSS default + local 24–33B switch** · Judge=Sonnet 4.6 · Orch=Opus 4.8 · Docs=GPT-5.4; **cross-vendor = defense-in-depth, not the invariant** | locked (rev. 2026-07-20, F7/S5) |
| D9 | Security tooling = configure/wrap OSS; build the 4 graded capabilities; buy nothing | locked (→ ADR-0001) |
| D10 | Contracts = versioned JSON Schema, framework-neutral, typed error taxonomy | locked |
| D11 | Compliance = synthetic-data simulation, ATO-*style*; OSS self-host sufficient, no BAA tier | locked |
| D12 | MVP seed strategy = hand-authored corpus + custom mutation loop; wrap PyRIT/Garak/Giskard post-MVP | proposed |
| D13 | Judge invariant = **deterministic, fail-closed verdict state machine** (oracle precedence; fail-closed on the verdict, not the run; async dual-judging calibration) | locked (2026-07-20, F1) |
| D14 | Trust split = untrusted generator → **trusted Policy Gateway + Execution Recorder** → external target; Judge sees hashed recorder `AttemptResult` only; canonical-hash + append-only (not signatures) within the trust domain | locked (2026-07-20, F2/F5) |
| D15 | OWASP taxonomy = **anchor 2021** (PRD's set) + 2021↔2025 crosswalk; structured `{framework,version,id,name}` tags | locked (2026-07-20, F8) |
| D16 | Deploy = **≥2 Railway environments** (prod-only live creds; env-scoped allowlist); expand/contract migrations; drain-before-deploy; PITR as true rollback | locked (2026-07-20, O1/O2) |
| D17 | Cost = **two independent line families** (measured hosted-token cost w/ cache+batch · amortized local capacity · hosting/storage/egress); the `list_price/throughput` division is removed as dimensionally invalid | locked (2026-07-20, F4) |
| D18 | Evaluator-injection containment: Judge/Documentation consume a **typed, trust-labelled, size-bounded evidence envelope**; oracle results are code-applied typed fields (injection cannot downgrade `EXPLOIT_CONFIRMED`); Judge is a pure evaluator (no creds/mutation/publish/execute); Documentation gets sanitized evidence by default; raw evidence quarantined | locked (2026-07-20, S4) |

---

### D4 — Orchestration: LangGraph (engine only) + PostgresSaver `locked`
**Why.** First-class human-in-the-loop (`interrupt()`/`Command(resume=…)`) is the human-approval
gate; PostgresSaver reuses the Railway Postgres we already run; per-node LLM clients make Judge
independence *structural*, not conventional. Rejected AutoGen (maintenance mode) and CrewAI (no
first-class Postgres checkpointer, weaker at-any-node interrupt). We use the **MIT OSS engine only** —
never LangGraph Platform/LangSmith — so there is no lock-in and contracts stay ours.
**Fallback.** Thin custom asyncio orchestrator on the *same* JSON-Schema contracts (a swap, not a
rewrite). Layer DBOS-on-Postgres *under* LangGraph if unattended multi-hour campaigns need exactly-once.
**Invalidate if.** LangGraph 1.x breaks `interrupt()`/PostgresSaver before MVP; a hard exactly-once
requirement lands. **Action:** pin the LangGraph 1.x version before the ADR is frozen.

### D5 — Observability: Langfuse Cloud (Hobby) for MVP, self-host post-MVP; exploit DB is system-of-record `locked (rev. 2026-07-20, F3)`
**Why.** OTEL-native SDK keeps emission framework-neutral; one-request=one-trace with per-agent span
tags gives native per-agent cost + inter-agent order. LangSmith/Braintrust self-host is Enterprise-
only (fails Railway/budget). **Split pinned:** Langfuse observes the *campaign*; the **Postgres exploit
DB is the authoritative system of record** for finding status (Q4) and resilience trend (Q3) — surfaced
via a Postgres view so the two never drift. On Langfuse failure the Orchestrator falls back to
**Postgres-derived coverage and priority signals** (§13, O7), never random or blocked.
**MVP choice (binding).** Langfuse **Cloud (Hobby, free)** with **synthetic data only** — for both the
Defense demo and MVP. **Post-MVP option:** self-hosted Langfuse with its full Web + Worker + Postgres +
ClickHouse + Redis/Valkey + S3 footprint — a documented hardening/migration path (zero re-instrumentation
via the OTEL SDK), **not** the MVP choice.
**Invalidate if.** Real BAA/HIPAA/SOC2 grading appears (it does not — D11) → paid tier + masking.

**Revision 2026-07-20 (F3, verified against langfuse.com/self-hosting + /pricing).** MVP now runs on
**Langfuse Cloud (Hobby, $0, 50k units/mo, 2 users, 30-day retention, no card)**, not self-host. Reason:
self-hosting Langfuse **requires** Web + Worker containers + PostgreSQL + **ClickHouse** + **Redis/Valkey**
+ **S3/blob** (documented min "≥2 CPU / 4 GB across all containers"; a full HA deploy realistically ~4 vCPU
/ 8 GB — an *estimate*, not a Langfuse-quoted figure). That reintroduces the exact Redis dependency D6 sells
having avoided and adds ~5 Railway services. Self-host is retained as a **documented post-MVP path** with its
full footprint in `ARCHITECTURE.md` §9/§12. Synthetic data only. Observability-backend-down is now a designed
failure mode (§13, O7): the Orchestrator falls back to the Postgres system-of-record for coverage/priority.

### D6 — State + queue: one Postgres, `SKIP LOCKED`, cron enqueues `locked`
**Why.** Postgres already exists (exploit DB + checkpoints); a hand-rolled `jobs` table with
`SELECT … FOR UPDATE SKIP LOCKED` and a `queue`/priority column carries both agent work and regression
runs durably; cron *enqueues* (never runs inline) to sidestep its 5-min/overlap-skip limits. Adding
Redis/Celery would split state and duplicate durability. Scale (≤100K total) is far below contention
limits.
**Fallback.** pgmq on the same Postgres (SQS-style metrics) via schema-only install or the
Supabase-Postgres template. **Watch:** keep claim transactions short + archive completed jobs to avoid
hot-table bloat.

**Revision 2026-07-20 (F6 + S2).** "One Postgres, `SKIP LOCKED`" is a claim primitive, not a production
queue. It is specified with full delivery semantics: **at-least-once delivery, lease expiry, worker
heartbeat, a reaper for expired leases, dead-letter for poison jobs, idempotency keys + dedup on
`{campaign_run_id, attempt_id}`, cancellation, no long work inside the claim txn, and depth monitoring +
backpressure** (`ARCHITECTURE.md` §6). Access control is enforced by **per-agent DB roles** (S2): the Red
Team role is INSERT-only into a staging table it cannot read back; the Execution Recorder writes canonical
transcripts to an **append-only** table with no UPDATE/DELETE grant to any agent role; the Judge role is
SELECT-only. Across a deploy the jobs/checkpoint payloads are **versioned** and unknown rows dead-lettered,
with a **drain-before-deploy** step (D16, O2).

### D8 — Per-role models `locked`
**Why.** RedTeam must not refuse authorized offensive generation → local uncensored open-weights;
**on the confirmed 32–48GB Mac, default 24–33B (Dolphin-Mixtral / WhiteRabbitNeo-33B)**, hosted-OSS
burst for the hardest cases and 10K+ scale (a 70B is throughput-tight here). Judge = Claude Sonnet 4.6
(refusal-integrity is the "never approve an exploit" property; structurally independent of the local
Red Team). Orchestrator = Opus 4.8 (planning reasoning, low call volume). Documentation = GPT-5.4
(*different vendor from the Judge* → breaks correlated failure; schema-gated output).
**Fallback.** RedTeam→hosted-OSS uncensored if the Mac saturates/offline; Judge→GPT-5.4.
**Invalidate if.** Real per-agent token/throughput traces move the local-vs-hosted crossover; a
provider ships a reliable authorized-offensive mode. **Action:** measure token profiles + Mac tok/s at
MVP before presenting a cost number.

**Revision 2026-07-20 (F7 + S5).** Two corrections. (1) **Red Team inference is a config switch with a
hosted-OSS default** for the *deployed* path (OpenRouter/Together uncensored), because a developer Mac that
sleeps and is unreachable from Railway cannot support the "continuous / unattended overnight" claim that is
the spine of the pitch; the local 24–33B Mac is reserved for development + the local cost-baseline, and Mac
tok/s stays an `open question`. (2) **Cross-provider separation is defense-in-depth, NOT the Judge
invariant** — the invariant is now deterministic (D13). Refusal behavior is a model *characteristic and
potential failure mode*, not a security control; Judge model selection is governed by **measured calibration,
false-negative rate, consistency, latency, and cost**. **Vendor-disjoint failover invariant (S5):** since
D8's own fallback is `Judge → GPT-5.4` and Documentation *is* GPT-5.4, the platform enforces `Judge.vendor
!= Documentation.vendor` at run start (fail-closed) — fail the Judge to a third vendor (e.g. Gemini) or move
Documentation off GPT-5.4 while the Judge is on it.

### D9 — Security tooling: configure/wrap, build the four `locked` → ADR-0001
**Why.** Garak/PyRIT/Giskard/Promptfoo/ZAP/Semgrep cover breadth, multi-turn scaffolding, RAG seeds,
OWASP mapping, web DAST, and our-code SAST — all free/OSS. The four things none of them do (coverage-
driven orchestration, autonomous mutation, an independent drift-guarded Judge, regression admission)
are exactly the graded custom work. Buying a commercial red-team platform is out of budget, closed,
un-governable, and *is* the product we're asked to build. Full record + verdict: ADR-0001.

### D11 — Compliance posture `locked`
**Why.** PRD mandates synthetic fixtures only and an ATO-*style* packet (the artifact a reviewer would
want), not a real authorization. Self-hosted OSS observability is sufficient; the design stays
BAA-upgradeable (masking, data-residency notes) as a documented hardening path, unpaid.

### D12 — MVP seed strategy `proposed`
**Why.** Wrapping PyRIT/Garak/Giskard is real Python engineering that CSA notes needs scoping; it
risks the Tue MVP. Ship MVP with a hand-authored seed corpus + our custom mutation loop (the hard
gates: Orchestrator, Judge, regression admission cannot be cut), then wrap the OSS seed sources
post-MVP. The contract JSON makes seed sources hot-swappable. *A tasks-gen sequencing call — arch-
finalize/tasks-gen to ratify.*

---

> **Decisions added at the `/arch-finalize` gate (2026-07-20).** Fold the mandatory external review
> (`REVIEW_FINDINGS.md` F1–F12) + a cold-eyes re-audit. Full context: `docs/planning/gap-audit.md`;
> binding architecture: `ARCHITECTURE.md`.

### D13 — Judge invariant = deterministic, fail-closed verdict authority `locked` (F1)
**Why.** The invariant "never approve a confirmed exploit" cannot rest on model **refusal-integrity** — that
is a category error (refusal governs whether a model *generates* harmful content; the invariant is whether it
correctly *classifies* a successful exploit, and a Judge that refuses to engage with adversarial content is
*worse* at judging it). The invariant is enforced by **code + evidence precedence**: a deterministic
oracle/canary hit → `EXPLOIT_CONFIRMED` and the LLM Judge cannot downgrade it; the LLM Judge runs **only**
where deterministic evidence is inconclusive; states are `EXPLOIT_CONFIRMED · EXPLOIT_LIKELY ·
NO_EXPLOIT_OBSERVED · INDETERMINATE · ERROR` (never "safe"); `INDETERMINATE`/`ERROR` never count as safe,
never prove a regression fixed, never enter the regression corpus, never publish. **Fail closed on the
verdict, not the run** — ambiguous cases park in the human-review queue while the Orchestrator continues
unrelated work (hard classification gate *and* live unattended runs). A confirmed exploit is marked *fixed*
only by a deterministic regression oracle + expected-safe assertion, never by an LLM-only verdict.
**Calibration = async dual-judging**, not per-case second-Judge concurrence (concurrence raises false
negatives on disagreement and doubles cost/latency): dual-judge the full ground-truth set + a stratified
random live sample + threshold-near/disputed cases; track inter-judge agreement, category false-negative
rate, calibration error, uncertainty rate, drift; a drift-threshold crossing **disables LLM-only dispositions**
for that category until recalibration/human approval.
**Fallback.** Human confirmation resolves `EXPLOIT_LIKELY`/`INDETERMINATE` (`confirmation_source: human`).
**Invalidate if.** A category proves to have no deterministic oracle *and* an un-seedable external target
(then that category is Judge-judgment + human escalation, stated honestly — D14/S8), or calibration shows the
chosen Judge model is unfit on false-negative rate.

### D14 — Trusted execution + evidence boundary; hashed append-only evidence `locked` (F2/F5)
**Why.** An **untrusted** component cannot be the enforcement boundary — the draft coloured the Target Adapter
red/quarantined while giving it allowlisting, credentials, budgets and abort, and let the Red Team produce the
`AttemptResult` the Judge evaluates (attacker controls the evidence → voids independence). Split into three:
(a) **untrusted** attack generator + content; (b) a **trusted Policy Gateway + Execution Recorder** that alone
holds target-scoped credentials, enforces allowlist + synthetic-data + budget + rate + hard abort **in runtime
code** (F5 — independent of trigger: Claude, direct Python, or cron; `disable-model-invocation` is convenience,
not control), executes against the target, and emits a canonically-hashed, append-only `AttemptResult`; (c)
**external** target. The **Judge evaluates the recorder's transcript only** and fail-closes on missing/invalid
evidence. **Evidence integrity = canonical hashing + append-only storage + per-agent DB roles, NOT signatures**,
within the current shared trust domain (one process / one Postgres): a signature would not help against a
fully-compromised in-process node that can read the key, so integrity/lineage/tamper-evidence is provided by
hashing + role separation; asymmetric recorder signing / KMS is the **hardening path** only when the recorder
crosses a process/service/network/administrative boundary. Gated side effects (publish) are **idempotent**
(run-nonce) so an `interrupt()` replay cannot double-fire. **Contract direction corrected:** `ExecutionRecorder
→ Judge: AttemptResult`; the PRD's `RedTeam → Judge` survives as a *logical* handoff mediated by the gateway —
recorded as an interface correction with a migration note (feeds the integration packet).
**Fallback.** None — this is a trust invariant. **Invalidate if.** The recorder is deployed as a separate
principal across a real boundary → promote signing/KMS from hardening path to requirement.

### D15 — OWASP taxonomy is versioned and anchored to 2021 `locked` (F8)
**Why.** OWASP Top 10:**2025** has shipped (SSRF folded into A01; Injection A03→A05; new A03 Software Supply
Chain Failures + A10 Mishandling of Exceptional Conditions). The PRD enumerates **SSRF standalone**, which
exists only in 2021 → the grading anchor is **2021**. Map web cases to 2021 explicitly, add a 2021↔2025
crosswalk, and store every mapping as `{framework, version, id, name}` (never a bare `A10`, which is SSRF in
2021 and Mishandling-of-Exceptional-Conditions in 2025) so the distinction is machine-checkable and the
regression harness can re-map if we ever migrate the anchor. LLM mappings already track OWASP LLM Top 10 (2025).
**Verified** at owasp.org/Top10/2025 + /Top10/2021.

### D16 — Deploy = multiple environments + rollback-safe migrations `locked` (O1/O2)
**Why.** A section titled "Deploy, Rollback & Environments" that defines one Railway env conflates CI, dev, and
the live-attacking production platform — a CISO-visible failure (a change to attack generation / credential
binding / the allowlist goes commit → live-fire with no soak; synthetic-data isolation has no boundary). Define
**≥2 environments**: non-prod (staging) points the TargetAdapter at a mock / non-production allowlist entry with
its **own** Postgres and cannot resolve live-target credentials; **prod alone** holds live creds. Promotion is
gated on green regression SLO + contract tests. Because a code rollback (Railway deployment history) reverts the
container **not** the managed-Postgres schema/rows: **expand/contract migrations** are the rule, destructive
migrations are forbidden alongside their consumers, checkpoint/jobs payloads are versioned + unknown rows
dead-lettered, a **drain/quiesce** precedes deploy, and **Postgres PITR is the true data rollback**.

### D17 — Cost = two independent line families; invalid formula removed `locked` (F4)
**Why.** `effective_cost_per_run = list_price / realized_throughput_at_load` is **dimensionally invalid**
($/token ÷ tokens/s = $·s/token²); hosted inference is billed **per token regardless of throughput** (throughput
sets latency/capacity, not price). Model **separately**: hosted inference = measured tokens × current rates,
adjusted for cached-input (~0.1× input) + Batch (~50%); local inference = hardware amortization + power + operator
time ÷ measured capacity (throughput-capped); hosting / storage / observability / egress as their own lines. Each
of 100/1K/10K/100K names the architectural change it forces (`ARCHITECTURE.md` §11). "Not tokens × N" means token
spend is **insufficient**, not absent — token accounting stays. **Numbers are deferred to MVP measurement**;
`RESEARCH.md` R6 still carries the old formula string and is **superseded by `ARCHITECTURE.md` §11** for the
future `cost-model` artifact. No placeholder number is presented.

### D18 — Evaluator-injection containment (Judge + Documentation) `locked` (S4)
**Why.** The Judge (Claude Sonnet 4.6) and Documentation (GPT-5.4) both ingest attacker-controlled text — a
successful indirect-injection payload echoed back by the target is a *live* injection aimed at whatever LLM
reads it next. F1's deterministic invariant + calibration address *drift*, not a novel in-transcript injection
that flips a real success to "fail" or launders attacker content into a human-facing report. Binding controls:
1. **Recorder transcripts and target output are hostile data, never trusted instructions.**
2. **Deterministic oracle/canary results are typed, provenance-labelled fields outside attacker-controlled
   text, applied by code** — never interpreted from the transcript by the LLM.
3. The Judge receives a **canonical, typed, size-bounded evidence envelope with explicit trust labels**
   (`trusted` code-populated fields vs `hostile` transcript); oversized transcripts are truncated (recorded).
4. The Judge **has no target credentials, no mutation tools, no publication authority, and cannot execute
   actions** — a pure evaluator.
5. **Judge output is schema-validated** — enumerated verdict states + confidence + typed reason codes; a
   Verdict failing validation is a typed error, not a verdict.
6. The Documentation agent receives the **validated `Verdict` + approved evidence references or sanitized
   excerpts by default** — not raw adversarial content.
7. **Raw adversarial evidence remains quarantined** and requires an **intentional, warned operator action**
   to reveal — never auto-rendered.
8. **Prompt separation + encoding are mitigations, not proof** that prompt injection is impossible.
9. Prompt injection **cannot downgrade `EXPLOIT_CONFIRMED`** because deterministic oracle precedence is
   enforced **outside the model** (D13). It remains a **residual risk** for non-oracle judgments and for
   documentation, addressed through calibration, thresholds, drift monitoring, and human review.
**Where.** `ARCHITECTURE.md` §3 (Judge constraints), §4 (Evidence Envelope + Verdict schema), §5 (S4
resolution), §15 (Documentation disclosure), §18 (platform-injection tests); registered in §20.
**Fallback.** None — a trust control. **Invalidate if.** The evaluators are moved to a fully-structured,
non-generative scoring path that never ingests free text (then several mitigations collapse into that design).
