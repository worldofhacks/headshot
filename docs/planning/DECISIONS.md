# DECISIONS.md — AgentForge / Adversarial Machine

> ADR-style decision log. Each entry: the decision, status, why, the fallback, and what would
> invalidate it. Grounded in `RESEARCH.md` (July 2026 sources) and the `/arch-draft` interview.
> The build-vs-configure decision has its own standalone record: `docs/adrs/0001-build-vs-configure.md`
> (a required Architecture Defense deliverable). Status: `locked` unless noted.

| # | Decision | Status |
|---|---|---|
| D1 | Planning mode = Standard; posture = production-grade | locked |
| D2 | Language = Python 3.12+ | locked |
| D3 | Full-platform host = Railway; public Web only, private runner/scheduler/Postgres (Docker/GitHub, managed Postgres, deployment-history rollback; no GPU) | locked |
| D4 | Orchestration = LangGraph (OSS engine only, self-hosted) + PostgresSaver | locked |
| D5 | Observability = **Langfuse Cloud for MVP** (OTEL SDK v4), self-host post-MVP; exploit DB = system-of-record for finding status | locked (rev. 2026-07-20, F3) |
| D6 | State + queue = one Postgres; `SKIP LOCKED` jobs table + **full delivery semantics**; cron enqueues; no Redis; **per-agent DB roles** | locked (rev. 2026-07-20, F6/S2) |
| D7 | Exploit DB = Railway Postgres (Alembic migrations; partition/BRIN at scale) | locked |
| D8 | Models — per-role **configurable defaults** via `HEADSHOT_*_MODEL` (not hard-coded runtime requirements): RedTeam=**hosted-OSS default + local 24–33B switch** (`HEADSHOT_RED_TEAM_MODEL`) · Judge=`claude-sonnet-5` (`HEADSHOT_JUDGE_MODEL`) · Orch=`claude-opus-4-8` (`HEADSHOT_ORCHESTRATOR_MODEL`) · Docs=`gpt-5.4` (`HEADSHOT_DOCUMENTATION_MODEL`); **cross-vendor = defense-in-depth, not the invariant** | locked (rev. 2026-07-21, F7/S5) |
| D9 | Security tooling = configure/wrap OSS; build the 4 graded capabilities; buy nothing | locked (→ ADR-0001) |
| D10 | Contracts = versioned JSON Schema, framework-neutral, typed error taxonomy | locked |
| D11 | Compliance = synthetic-data simulation, ATO-*style*; OSS self-host sufficient, no BAA tier | locked |
| D12 | MVP seed identity remains hand-authored; bounded native tool imports use a separate reviewed corpus hash and fresh authorization; framework orchestrators stay post-MVP | locked (rev. 2026-07-22) |
| D13 | Judge invariant = **deterministic, fail-closed verdict state machine** (oracle precedence; fail-closed on the verdict, not the run; async dual-judging calibration) | locked (2026-07-20, F1) |
| D14 | Trust split = untrusted generator → **trusted Policy Gateway + Execution Recorder** → external target; Judge sees hashed recorder `AttemptResult` only; canonical-hash + append-only (not signatures) within the trust domain | locked (2026-07-20, F2/F5) |
| D15 | OWASP taxonomy = **anchor 2021** (PRD's set) + 2021↔2025 crosswalk; structured `{framework,version,id,name}` tags | locked (2026-07-20, F8) |
| D16 | Deploy = **≥2 Railway environments** (prod-only live creds; env-scoped allowlist); expand/contract migrations; drain-before-deploy; PITR as true rollback | locked (2026-07-20, O1/O2) |
| D17 | Cost = **three independent line families** (measured hosted-token cost w/ cache+batch · amortized local/capacity-priced inference · hosting/storage/egress); the `list_price/throughput` division is removed as dimensionally invalid | locked (2026-07-20, F4; index row said "two" while naming three — corrected 2026-07-25 to match the D17 body and `docs/cost/COST_ANALYSIS.md`) |
| D18 | Evaluator-injection containment: Judge/Documentation consume a **typed, trust-labelled, size-bounded evidence envelope**; oracle results are code-applied typed fields (injection cannot downgrade `EXPLOIT_CONFIRMED`); Judge is a pure evaluator (no creds/mutation/publish/execute); Documentation gets sanitized evidence by default; raw evidence quarantined | locked (2026-07-20, S4) |
| D19 | Human IdP = Clerk; no custom passwords, OAuth flow, or session database | locked (2026-07-21) |
| D20 | Human session verification = networkless Clerk `session_token` verification with PEM JWT key + explicit exact `authorizedParties` | locked (2026-07-21) |
| D21 | Enrollment = restricted/invitation-only; exact Headshot Organization required; Personal Accounts and user-created Organizations disabled | locked (2026-07-21) |
| D22 | MFA = required for all users; TOTP + backup codes, never SMS-only | locked (2026-07-21) |
| D23 | RBAC = **two** Organization roles assigned exact backend-authoritative custom permissions; system/client role text has no authority | locked (2026-07-21; index row corrected 2026-07-25) |
| D24 | Two-person identity separation = launcher cannot approve/authorize self; no emergency bypass | locked (2026-07-21) |
| D25 | Human authentication never replaces exact live-campaign Policy Gateway authorization | locked (2026-07-21) |
| D26 | Against a black-box target, **canary-anchoring is the only decisive deterministic oracle**; pure-observation oracles stay `INDETERMINATE` and are never marked `runtime_wired` | locked (2026-07-25) |

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
burst for the hardest cases and 10K+ scale (a 70B is throughput-tight here). Per-role models are
**configurable defaults sourced from `HEADSHOT_*_MODEL`**, not hard-coded runtime requirements. Judge
default = `claude-sonnet-5` (`HEADSHOT_JUDGE_MODEL`; structurally independent of the local Red Team — its
refusal behavior is a characteristic, not the invariant, which is deterministic per D13/S5 below).
Orchestrator default = `claude-opus-4-8` (`HEADSHOT_ORCHESTRATOR_MODEL`; planning reasoning, low call
volume). Documentation default = `gpt-5.4` (`HEADSHOT_DOCUMENTATION_MODEL`; *different vendor from the
Judge* → breaks correlated failure; schema-gated output). `claude-sonnet-5` is the current Sonnet;
`claude-sonnet-4-6` remains available as its predecessor.
**Fallback.** RedTeam→hosted-OSS uncensored if the Mac saturates/offline; Judge→`gpt-5.4`.
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

**Revision 2026-07-25 (code reconciliation, `107c11c`).** D8's "configurable defaults via
`HEADSHOT_*_MODEL`" no longer describes the deployed hosted path. The hosted role set is now **frozen
in code** and any deviation is rejected at composition
(`src/agentforge/agents/hosted.py:352-353`). The authoritative mapping is
`HOSTED_ROLE_MODELS` (`src/agentforge/agents/hosted.py:31-38`):

| Role | Model ID (frozen) | Role spend ceiling (`hosted.py:39-45`) |
|---|---|---|
| `orchestrator` | `anthropic/claude-opus-4.8` | $1.50 |
| `red_team` | `qwen/qwen3.5-397b-a17b` | $1.00 |
| `judge` | `google/gemini-2.5-pro` | $4.00 |
| `documentation` | `openai/gpt-5.4` | $1.00 |

Envelope, same file: `HOSTED_PROVIDER = "openrouter"` (`:26`), `HOSTED_MAX_PHYSICAL_CALLS = 56`
(`:27`), `HOSTED_MAX_MEASURED_USD = $10` (`:28`), `HOSTED_MAX_LOGICAL_RETRIES = 1` (`:29`),
`HOSTED_MAX_CONCURRENCY = 1` (`:30`). The four role ceilings sum to $7.50, inside the $10 envelope.

Three consequences for the D8 text above, recorded rather than silently rewritten:

1. **The Judge is `google/gemini-2.5-pro`, not `claude-sonnet-5`** — a different vendor entirely.
   `claude-opus-4-8` and bare `gpt-5.4` are not valid identifiers under the frozen set; the
   provider-qualified forms above are.
2. **The Red Team is a 397B MoE, not a local 24–33B Mac workload.** The "local 24–33B switch" and the
   Dolphin-Mixtral/WhiteRabbitNeo/Dolphin-3.0/Euryale candidates are not configured anywhere in
   `src/`. DeepSeek (`deepseek/deepseek-chat-v3-0324`) is a *documented, unconfigured fallback*
   (`docs/agents/RED_TEAM_MODEL_RESOLUTION.md`), not the configured model. The one document that named
   it as the generator (`docs/evidence/agent-trace.md`) was corrected upstream by PR #44 (`2069036`),
   which also retired the standalone `HostedProvider` generation route to a fail-closed shell
   (`src/agentforge/agents/red_team/providers.py:216-250`), leaving `TracedHostedRedTeamProvider`
   (`hosted_generation.py:185`) as the single governed generator — itself not composed into the
   production Runner.
3. **The S5 vendor-disjoint failover invariant is not implemented.** No
   `Judge.vendor != Documentation.vendor` check exists in `src/agentforge/agents/**` and no test
   references it. The property happens to hold for the frozen set (Google vs OpenAI), but it holds
   by configuration, not by enforcement, and `HOSTED_PROVIDER` is a single provider for all four
   roles. `ARCHITECTURE.md` §20 registers S5 as resolved; that registration is corrected in the
   same pass.

**Not invalidated** — D8's *reasoning* (per-role separation, cross-vendor as defense-in-depth, Judge
selection governed by measured calibration) stands. Only the model identifiers and the enforcement
claim moved. Judge selection "governed by measured calibration" remains **aspirational**: the only
calibration ever measured at this base is of the **deterministic oracle-precedence Judge**
(`judge_provider = "deterministic-code"`), not of any hosted model, and it **fails** — 30 labels, 18
agreements, 6 false negatives, 0 false positives, 18 abstentions
(`tests/test_judge_calibration.py:44-58`). Calibrating a hosted model needs a captured-results bundle;
none is committed. See D13 and `docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md`.

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

### D12 — MVP seed identity and bounded native imports `locked` (rev. 2026-07-22)
**Why.** The approved MVP remains the exact hand-authored nine-case corpus plus custom mutation
loop. A bounded slice now imports native Garak/PyRIT/Giskard/Promptfoo artifacts into untrusted
candidates and advisory findings. Selected candidates form a distinct reviewed corpus hash and need
fresh authorization, so existing grants cannot silently expand. Framework multi-turn orchestrators
and all tool-to-target execution remain post-MVP; Policy Gateway and Judge authority are unchanged.

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
> **Implementation status, recorded 2026-07-25 (`107c11c`) — the calibration paragraph below is
> `specified, NOT implemented`.** `ARCHITECTURE.md` §20's drift register carries the same finding.
> Three specifics: **dual-judge cross-agreement does not exist** (the gate accepts exactly one
> evaluator, and `agreement_rate` measures agreement with ground truth, not judge-vs-judge);
> **per-category disablement does not exist** (per-category metrics are computed, but the reason-code
> logic applies global rates plus a per-category sample floor); and **no stratified live sample has ever
> been drawn** — the six ground-truth slices are hand-authored and self-labelled
> `calibration_status: "AUTHORED_NOT_RUN"`. The deterministic invariant this decision exists to protect
> **is** implemented and holds (oracle precedence in `src/agentforge/agents/judge/judge.py`); it is the
> *drift-detection* half that is designed and unbuilt. D26 records why the gap matters less than it
> looks against a black-box target, and more than it looks for breadth.

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

### D17 — Cost = three independent line families; invalid formula removed `locked` (F4)
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
**Why.** The Judge (`claude-sonnet-5`) and Documentation (`gpt-5.4`) both ingest attacker-controlled text — a
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

### D19 — Clerk is the managed human IdP `locked`
**Why.** The seven-hour MVP cannot responsibly absorb password enrollment/recovery, password hashing,
MFA, OAuth callback security, session rotation/revocation, or a new credential database. Clerk supplies
managed sign-in and Organization membership while the application retains server-side authorization.
The platform builds none of those commodity credential features. `VITE_CLERK_PUBLISHABLE_KEY` and
`CLERK_PUBLISHABLE_KEY` are public identifiers. `CLERK_SECRET_KEY` is not required for request
authentication and is reserved for future Backend API user/invitation administration after a separate
review.
**Fallback.** Auth0 is a credible managed alternative but would require a different integration and is
not the MVP selection. A custom password/session system is not a fallback.
**Invalidate if.** Clerk cannot satisfy the locked Organization, MFA, custom-permission, or session
verification controls in the provisioned environments; then pause deployment and select another managed
IdP rather than weakening a gate.

### D20 — Networkless Clerk session verification `locked`
**Why.** Human endpoints accept only `session_token`. The backend validates the environment's public
Clerk publishable identifier, then supplies the PEM `CLERK_JWT_KEY` and an explicit list of exact
non-wildcard `CLERK_AUTHORIZED_PARTIES` to the official request verifier. The current Python verifier
has no publishable-key option. Local-key verification removes request-time JWKS availability from the
hot path and must validate signature, supported algorithm, expiry,
not-before time, token type, and authorized party. Pending sessions are denied. The verified result is
reduced to a frozen Principal; the token, authorization/cookie headers, raw request state, SDK message,
and client fields are discarded and never logged.
**Failure contract.** Invalid/missing authentication → `401`; active identity without the exact
Organization/permission/distinct approver → `403`; verifier/SDK/security-config failure → fail-closed
`503`. There is no online-JWKS fallback after local verification fails.
**Residual.** Networkless verification sees a signed permission snapshot, not a live membership lookup;
revocation/role-change freshness is bounded by token refresh/expiry. Critical-action step-up or an
online freshness check is a post-MVP hardening option and must itself fail closed.

### D21 — Restricted Headshot Organization enrollment `locked`
**Why.** Enable Clerk Restricted mode and use administrator-issued invitations. Every active user must
belong to the one required Organization named **Headshot**, compared by exact environment-specific
Organization ID. Personal Accounts and user-created Organizations are disabled. Staging and production
have separate Clerk configuration, IDs, origins, keys, invitations, and memberships; staging may not
accept the production Railway origin or production Organization ID. Display names, slugs, email domains,
and frontend organization state are not authority.
**Fallback.** None for meaningful access. A user unable to complete the required Organization task stays
pending/signed out.
**Invalidate if.** The business intentionally becomes multi-tenant; that requires a new isolation ADR,
resource-ownership model, and IDOR test plan before another Organization is accepted.

### D22 — Required MFA `locked`
**Why.** Clerk's required MFA session task prevents a partially configured account from becoming an
active session. Authenticator-app TOTP is the preferred factor and backup codes are enabled for recovery.
SMS can be an additional method but cannot be the sole factor. Incomplete MFA/Organization tasks remain
pending and cannot access protected content.
**Fallback.** Account recovery is an administrator/Clerk workflow, never a backend MFA bypass.
**Invalidate if.** A stronger phishing-resistant factor becomes mandatory; add it without removing the
current fail-closed session-task behavior.

### D23 — Custom-permission RBAC `locked`
**Why.** Clerk system permissions are not included in session claims and cannot be the server-side
authorization source. The backend checks only the immutable custom Organization permission set from the
verified session. Client-supplied role/permission text is ignored, and a verified role label is never
expanded into permissions in application code.

| Role | Exact custom permission assignment |
|---|---|
| `org:operator` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:launch`, `org:campaign:abort`, `org:targets:manage`, `org:config:manage` |
| `org:approver` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read`, `org:campaign:authorize`, `org:findings:approve`, `org:findings:resolve` |

The two-role model is deliberate: both roles can inspect all protected operational and audit data,
while custom mutation permissions preserve launcher/approver separation.
**Fallback.** None that changes authority semantics. A temporarily absent role/permission denies the
operation.

### D24 — Two-person identity separation `locked`
**Why.** Approval is a custom permission **and** an identity comparison. The approver must be an active,
authenticated Headshot Principal carrying the operation's permission, and
`approver.user_id != launcher_user_id`. Role or permission alone cannot prove separation. Both immutable
IDs are audit fields. There is no solo-user or emergency self-approval path; if no second authorized human
is available, the operation remains pending.
**Fallback.** Abort or wait for a distinct approver.
**Invalidate if.** Never by convenience. Any emergency process would require an independently reviewed
break-glass design with stronger controls and a new ADR.

### D25 — Authentication is not campaign authorization `locked`
**Why.** Clerk answers who the human is and which application permissions are present. It does not
authorize an external target. After human gates pass, the trusted Policy Gateway still enforces exact
target authorization, the environment-scoped allowlist, target-bound credentials, synthetic-data-only,
budget, rate, timeout, monitoring, and hard abort. Direct API, scheduled, and agent-triggered paths all
cross the same gateway.
**Fallback.** None. Any missing Policy Gateway input denies execution.
**Invalidate if.** Never; combining human identity with target authorization would collapse two separate
trust boundaries.

---

> **Decision added from the red-team grounding pass (2026-07-25).** Recorded against base `107c11c`.
> Working label during the gap-swarm was "AD-06 canary-anchoring"; it is numbered D26 here so the
> project keeps one decision series. Full analysis:
> `docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-25.md` RT-02.

### D26 — Canary-anchoring is the only decisive deterministic oracle against a black-box target `locked` (2026-07-25)
**Why.** D13 makes a deterministic oracle or canary hit the sole path to `EXPLOIT_CONFIRMED`. The
gap-swarm plan (WP-11) assumed the remaining five category oracles were *unwired* and that wiring
them into the run path would make them decisive. Grounding against the code disproves that: **wiring
them would not make them fire, because there is no source data to populate their observations.**
`ToolCallObservation`, `RetrievalScopeObservation`, state-diff, identity-scope and resource
observations are constructed **only** in `tests/test_category_oracles.py` and nowhere in `src/`; the
recorder persists transcripts only (`src/agentforge/policy/recorder.py`); the sole oracle constructed
in the run path is `CanaryOracle` over the re-read transcript
(`src/agentforge/campaign/coordinator.py:711-726`); and `TargetResponse` carries only `output`,
`status`, and `{adapter, url, trace_id}`. Retrieval lineage, pre/post state hashes, tool-call
authorization decisions, effective role and token/tool counters are **target-internal facts that an
HTTP response body does not contain**, and no attesting collector exists. Against a black-box
`POST /chat` surface, oracle wiring is necessary but nowhere near sufficient.

**The decision.** Three parts, all binding:

1. **Design for canary echo.** Author cases so that a *successful* exploit causes the target to echo
   a **seeded synthetic canary** into the response body. That produces a genuine
   `EXPLOIT_CONFIRMED` through the existing deterministic path with no new trust assumption. It works
   natively for data exfiltration (cross-patient canary) and prompt injection (system-prompt canary),
   and can be re-expressed for other categories by making success surface a canary. The decisive
   count is bounded by the canaries actually seeded in the target and declared as
   `target.canary_refs` — never by the number of cases authored.
2. **Wire only what is genuinely observable.** The **consumption oracle** is platform-observable:
   the Policy Gateway's own meter (request count, tokens, latency, cost of *our* calls) can be
   projected into a resource observation without asking the target for anything. That is a legitimate
   wiring for denial-of-service / unbounded-consumption. It is the only one of the five category
   families that qualifies today. RAG-source *may* qualify if a Week 2 surface exposes
   source/citation digests (WP-12); verify before promising.
3. **Never fake firing.** `tool_call`, `state_diff` and `identity_role` are not decisive against a
   black-box target. Their cases are canary-re-expressed, or LLM-assessed once a model Judge is
   genuinely enabled, or they stay honestly `INDETERMINATE`. **`runtime_wired` must not be flipped to
   `True` without a test proving the observation is actually collected, and no case may be bound to an
   oracle that cannot fire** — either move manufactures `INDETERMINATE` at best and a fake
   confirmation at worst.

`INDETERMINATE` is never relabelled as decisive, and a model Judge never produces
`EXPLOIT_CONFIRMED` (D13/D18). Where a model Judge is enabled it produces `EXPLOIT_LIKELY` /
`NO_EXPLOIT_OBSERVED` **assessments** only, which makes non-canary cases decisive-as-assessment
rather than confirmed.

**Fallback.** Human confirmation, per D13. Where neither a canary nor a human resolves a case, the
case is reported `INDETERMINATE` and excluded from demonstrated coverage.
**Invalidate if.** The target stops being a black box — i.e. it exposes an authenticated,
attestable telemetry surface (tool-call log, retrieval lineage, state digests) that the platform can
collect and bind to an attempt. Then WP-11's observation layer becomes both buildable and decisive,
and this decision narrows to "canary-anchoring is the *baseline*, not the ceiling." A Week 2
citation-digest surface would partially invalidate it for RAG-source only.
**Cost of being wrong.** Low and self-announcing: if a family turns out to be observable, cases
re-bind to the real oracle and get *more* decisive. The failure mode this decision exists to prevent
is the opposite one — spending the delivery window wiring evaluators that cannot fire, and reporting
the resulting `INDETERMINATE` mass as coverage.
