# ARCHITECTURE_DRAFT.md — AgentForge / Adversarial Machine

> **Rough draft** for adversarial finalization by `/arch-finalize` (a different model, on purpose).
> Stable `§N` anchors — downstream skills bind to them. **Build posture: production-grade.**
> All stack sections are now filled from the ADR research (`RESEARCH.md` / `DECISIONS.md` /
> `docs/adrs/0001`); numbers that require measurement (cost, tok/s) are deliberately left to MVP and
> flagged, never invented (cardinal rule).

---

## §1. One-Page Summary (~500 words)
> `arch-finalize` owns the binding version in the repo-root `ARCHITECTURE.md`; this is the draft.

AgentForge is a reusable, **multi-agent adversarial evaluation platform** that continuously red-teams
AI-assisted clinical workflows. Its first target is a live, deployed OpenEMR **Clinical Co-Pilot**
reached over its URL (API + UI); no target code lives in this repo — every target is reached through a
pluggable adapter behind an allowlist. The platform's job is not to find one jailbreak; it is to
*continuously* discover, evaluate, validate, regression-guard, and document vulnerabilities as the
target evolves — the standard is a system a hospital CISO would trust, not a demo.

**Four agents with distinct trust levels** (a single-agent or linear pipeline does not satisfy the
assignment): the **Orchestrator** (trusted control plane) reads observability — coverage gaps, open
findings, regressions — and prioritizes the next campaign, triggers regression runs, and governs cost;
the **Red Team** (untrusted, quarantined) generates novel adversarial inputs and autonomously mutates
partial successes across multi-turn sequences; the **Judge** (independent evaluator) returns
success/fail/partial with consistent cross-run criteria and must *never* approve a confirmed exploit;
the **Documentation** agent (gated) turns confirmed exploits into reproducible vulnerability reports. A
regression harness and an observability layer close the loop. The security property comes from the
*separation*: an agent that both attacks and judges is compromised by design, so the Judge shares no
model, provider, or process with the Red Team.

**The learning loop** — Observability → Orchestrator → Red Team → Target → Judge → (mutate | confirm) →
Documentation / Regression → Observability — is what makes the platform *learn* rather than run attacks
randomly. Confirmed exploits are admitted to a deterministic regression harness only if they reproduce
*and* pass for the right reason (a real fix, not changed model behavior), and are re-run on every
target change.

**Stack (build-vs-configure — ADR-0001).** Python on Railway (Docker-from-GitHub, managed Postgres,
cron, deployment-history rollback). Orchestration is **LangGraph** (OSS engine only) with Postgres
checkpoints; `interrupt()` is the human-approval gate. One Postgres is exploit DB + checkpoints + a
`SKIP LOCKED` work/regression queue. Observability is **self-hosted Langfuse** (OTEL), with the exploit
DB as system-of-record for finding status. Models are assembled per role: a **local uncensored 24–33B**
Red Team (frontier models refuse offensive work), **Claude Sonnet 4.6** Judge (its refusal-integrity is
the "never approve an exploit" property), **Opus 4.8** Orchestrator, and **GPT-5.4** Documentation
(cross-vendor from the Judge to break correlated failure). We **configure/wrap** Garak, PyRIT, Giskard,
Promptfoo, ZAP, and Semgrep for coverage, multi-turn scaffolding, OWASP mapping, and deterministic
checks, and **build** only the four capabilities no tool delivers.

**Defensible to a CISO.** Inter-agent messages are versioned, framework-neutral JSON Schemas with typed
error taxonomies and both-sided contract tests. Adversarial content is quarantined and never reaches
the control plane; credentials are bound to their target; every live campaign passes an allowlist +
synthetic-data + budget/rate gate with a hard abort. Humans approve any critical finding and any
remediation. Cost is modeled at 100/1K/10K/100K runs with hosting and inference as separate lines —
never tokens × N — each tier naming the architectural change it forces.

## §2. System Context & Scope
- **In scope (this repo):** the adversarial evaluation *platform* — four agents, regression harness,
  observability, contracts, policy/allowlist, exploit store, target adapter.
- **Out of scope (external):** the OpenEMR Clinical Co-Pilot (**target**, attacked over its live
  URL — no target code here); model providers; Railway; GitHub.
- **Target reach:** pluggable `TargetAdapter` behind an **allowlist**; API-primary, UI path for
  evidence/e2e. Only target #1 (OpenEMR) is wired this week (`simplification`); the interface stays
  generic.
- **Hard gate:** a deployed target URL accompanies every checkpoint; the platform tests a live
  system, never only a mock.

## §3. The Multi-Agent Model (roles · trust · autonomy)
Four agents with **distinct trust levels** — a hard gate; a single-agent or linear pipeline does not
satisfy the assignment. An agent that both attacks and judges is compromised by design.

| Agent | Responsibility | Trust | Autonomy | Key inputs → outputs |
|---|---|---|---|---|
| **Orchestrator** | Reads observability → prioritizes the next campaign; triggers regression; governs cost | Trusted control plane | Autonomous within budget/coverage policy | observability + findings + coverage → campaign directives, regression triggers, abort signals |
| **Red Team** | Generates novel adversarial inputs; mutates partial successes; multi-turn sequences | **Untrusted / quarantined** | Autonomous generation; cannot self-judge or publish | campaign directive + seeds + prior partials → attempts + transcripts |
| **Judge** | Independent verdict: success / fail / partial; consistent cross-run criteria; uncertainty escalation | **Independent evaluator** | Autonomous verdicts; escalates on uncertainty | transcript + expected-safe behavior + ground truth → verdict |
| **Documentation** | Confirmed exploit → structured, reproducible vuln report; data-quality gated | Gated | Autonomous drafting; **human gate on critical publish** | confirmed exploit → `vuln-report` |

**Why distinct agents (defensible):** attack generation vs evaluation is a conflict of interest in
one context; strategic prioritization vs execution are different jobs; documentation autonomy needs a
trust boundary the generator must not hold. Separation *is* the security property.

**The learning loop:** Observability → Orchestrator → Red Team → Target → Judge → (mutate | confirm)
→ Documentation/Regression → Observability. Without the loop the platform runs attacks randomly; with
it, coverage compounds.

## §4. Inter-Agent Contracts (versioned, framework-neutral)
- **Format:** versioned **JSON Schema** in `contracts/v1/` (minimum v1). Framework-neutral so the
  stack choice never forces a rewrite. Any breaking change → version bump + migration note + updated
  contract tests (a breaking change without all three is a failed run — enforced by `contract-steward`).
- **Message boundaries (typed success schemas):**
  - `orchestrator→redteam`: CampaignDirective (target ref, category, coverage goal, budget/rate caps,
    mutation policy).
  - `redteam→judge`: AttemptResult (case ref, input sequence, transcript, target metadata).
  - `judge→documentation`: Verdict (success/fail/partial, criteria hits, confidence, OWASP tags).
  - `judge→regression`: RegressionAdmission (exploit ref, determinism evidence, passes-for-right-reason).
- **Typed error schemas (published alongside success):** `target-unreachable · budget-exceeded ·
  judge-timeout · no-findings-in-window · regression-detected · rate-limited · adapter-error`.
- **Both-sided contract tests:** every boundary verifies producer *and* consumer conform to the
  published schema (`tests/contract/`).

## §5. Trust Boundaries & Security Model (the platform itself)
- **Zones:** control plane (Orchestrator, policy, human gate) = trusted; Judge/Doc/regression/
  observability = governed; **Red Team + all adversarial content = untrusted/quarantined**; target +
  providers = external.
- **Adversarial-content containment** `hardening`: Red Team output is treated as hostile — it may
  only reach the allowlisted target through the adapter, is never executed against the platform's own
  control plane, and is stored/traced without letting a raw payload harm a human reviewer.
- **Per-target credential binding** `locked`: a pluggable credential provider (session / bearer /
  OAuth / none) is selected per allowlist entry; secrets are referenced, never inline; a credential
  is usable **only** against the target it is bound to — cross-target use is impossible by
  construction.
- **Authorized-live-campaign gate** `locked`: every live run passes allowlist + synthetic-data
  assertion + budget/rate caps + abort, with full trace capture. Live attacks are always intentional.
- **Access control:** only the post-Judge documentation path creates published findings; only a human
  publishes **critical**; only the admission path writes the regression store; the Red Team can do
  neither.

## §6. Data Model & Storage
- **Exploit DB = Postgres** `locked` (Railway managed): versioned, queryable, **indexed by severity /
  category / target-version**, migratable via Alembic (schema change → migrate existing records without
  loss; time-range partition + BRIN at the 10K/100K tiers).
- **One Postgres, three jobs** `locked`: the same instance holds the exploit DB, the LangGraph
  checkpoints, and the **work/regression queue** — a `jobs` table drained with `SELECT … FOR UPDATE
  SKIP LOCKED`, two logical queues (`agent_work` | `regression_run`) by a `queue`/priority column;
  backoff via `run_after`/`attempts`; abort via status flag; depth via `count(*)`. **Railway cron
  enqueues** regression runs (never runs inline). No Redis/Celery (a second stateful service splits
  state off the exploit DB). Fallback: pgmq on the same Postgres.
- **Core entities:** Target · AttackCase · Attempt · Transcript · Verdict · Finding · VulnReport ·
  RegressionCase · RegressionRun · Campaign · CoverageMetric · CostRecord · GroundTruthLabel ·
  ContractVersion · Incident (full state machines: `PRESEARCH.md §5`).
- **Data-quality invariants (validated in the Documentation Agent before write):** unique ID, all
  required fields, referential integrity, **no duplicate attack sequence**. The same validator runs
  in CI (`validate-eval-case`, `detect-duplicate-sequence`) so guidance and enforcement can't drift.
- **Lineage:** every Finding traces back through Verdict → Attempt → CampaignDirective → Orchestrator
  decision (the observability trace answers "which agents produced this finding").

## §7. Orchestration Framework & Agent State
**LangGraph (MIT OSS engine only — self-hosted, no LangGraph Platform/LangSmith)** `locked`. Each
agent's reasoning runs as custom Python inside a node/subgraph. **PostgresSaver** checkpoints to the
same Railway managed Postgres as the exploit DB (one durable store). **`interrupt()` /
`Command(resume=…)` is the human-approval gate** at any node (F6). **Judge independence is structural**
— it runs in its own node with its own model client, sharing no weights/provider with the Red Team.
- **Contracts stay ours:** inter-agent messages are our versioned JSON Schemas, materialized as
  LangGraph `TypedDict` state — the framework never owns the contract.
- **Known gap → resilience (§13):** LangGraph checkpoints are crash-*persistence*, not durable
  execution (no watchdog/auto-resume, no dup-execution guard). Mitigate with an application-level
  `thread_id` lock against overlapping campaigns; layer **DBOS-on-Postgres** *under* LangGraph only if
  unattended multi-hour campaigns become in-scope. **Pin the LangGraph 1.x version before Defense.**
- **Fallback (a config swap, not a rewrite):** a thin custom asyncio orchestrator on the same
  contracts.

## §8. Models per Role
A **different model per role**, sized to its refusal-vs-capability need `locked`:

| Role | Model | Why |
|---|---|---|
| **Red Team** | Local uncensored open-weights via Ollama — **default 24–33B (Dolphin-Mixtral / WhiteRabbitNeo-33B)** on the 32–48GB Mac; hosted-OSS burst (OpenRouter/Together uncensored) for hardest multi-turn + 10K+ scale | Frontier models refuse authorized offensive generation; local = ~$0 marginal, no refusals, off any provider ToS. Never Claude/GPT here |
| **Judge** | **Claude Sonnet 4.6** (Batch API + prompt-cached rubric) | High refusal-integrity *is* the "never approve a confirmed exploit" property; structurally independent of the local Red Team. Fallback: GPT-5.4 |
| **Orchestrator** | **Claude Opus 4.8** (economize to Sonnet/Gemini when hot) | Planning-grade reasoning; low call volume makes frontier affordable |
| **Documentation** | **GPT-5.4** | *Deliberately a different vendor from the Judge* → no single-vendor correlated failure on the trust chain; output schema-gated by the vuln-report validator regardless of model |

Red Team = **untrusted**; Judge model shares no provider/weights with it (independence by
construction). Per-agent token profiles + Mac tok/s are **measured at MVP** before any cost number is
presented (`RESEARCH.md` open items).

## §9. Observability Layer
**Self-hosted Langfuse (MIT)** on Railway, instrumented with the **OTEL-native SDK v4** (emission stays
framework-neutral) `locked`. **One request = one trace:** the Orchestrator opens the root span; Red
Team / Judge / Documentation are child spans tagged `{agent, attack_category, owasp_web, owasp_llm,
system_version, verdict}` → native per-agent cost roll-up + inter-agent order. Reject LangSmith /
Braintrust (self-host is Enterprise-only → fail Railway/budget).
- **System-of-record split (pinned so they can't drift):** Langfuse *observes the campaign*; the
  **Postgres exploit DB is system-of-record** for Q4 (open/in-progress/resolved) and Q3 (resilience
  trend), surfaced via a Postgres view.
- **Defense-window plan:** Langfuse **Cloud Hobby (free)** for the ~2.5h Defense demo (the 6-container
  self-host stack may not stabilize in time) → Railway self-host for MVP with **zero re-instrumentation**.

**The layer's acceptance criteria are fixed regardless of backend** — it must answer, for a human *and*
for the Orchestrator:
1. Which attack categories tested + cases per category?
2. Current pass/fail rate across categories + system versions?
3. Is the target becoming more or less resilient over time?
4. Which vulnerabilities are open / in-progress / resolved?
5. How much did this run cost, and at what rate is cost scaling?
6. What is each agent doing, and in what order?

Requirements: inter-agent traces + **per-agent cost attribution**; append-only; the data substrate
the Orchestrator reads (not just a human dashboard).

## §10. Regression & Validation Harness
- Stores confirmed exploits in a versioned, queryable format; runs the full suite automatically when
  triggered by the Orchestrator (**Railway cron** is the scheduled trigger) or on target change.
- Detects (a) a previously-fixed vulnerability reappearing, (b) fixing one category regressing
  another.
- **Admission invariant:** a case is admitted only if it reproduces **deterministically** *and*
  passes for the right reason — a real fix, not changed model behavior. "A test that passes because
  behavior changed is worse than no test." `adversarial-eval-lifecycle` governs admission; the harness
  itself is app code.
- **SLO:** a full regression scan completes within a defined time budget, verified in CI.

## §11. Cost, Rate Limits & Scale (100 / 1K / 10K / 100K runs)
Cost is **two independent line families on different scaling functions — never tokens × N** `locked`:
`Cost(N) = Hosting(peak_concurrency) + Σ_agents[runs_routed(N) × effective_cost_per_run] +
Storage(rows) + Egress`, where `effective_cost_per_run = list_price / realized_throughput_at_load`
(list × tokens overstates by 17–36× under load).
- **Hosting = step function of peak concurrency** (Railway): platform compute ~$40/mo holds 100–1K;
  managed Postgres ~$10–20/mo; cron is tiny; Langfuse self-host ~$20–60/mo. **Inference = per-run,
  split per agent** (local Mac Red Team amortized + throughput-capped; frontier Judge/Orch/Doc
  quality-bound, cut with prompt-cache 0.1× + Batch API 50%).
- **Per-tier architectural change (the whole point):** **100** baseline, hosting dominates · **1K**
  prompt-cache shared context + Batch API · **10K** Red Team fully off frontier (local/hosted-OSS) +
  queue backpressure + time-range partition the exploit DB · **100K** *sample* regression runs +
  BRIN-on-timestamp + partial B-tree on hot partitions + dedicated worker + verdict caching.
- **Rate/failure:** rate-limit handling = **backoff → queue → abort**; a cost circuit-breaker halts on
  no-signal/budget. When the queue backs up, jobs accumulate *durably* in Postgres (nothing dropped),
  depth rises visibly in observability, the cost governor throttles new campaigns — graceful,
  observable degradation (the CISO-defensible failure mode). Full model + `COST_ANALYSIS.md` skeleton:
  `RESEARCH.md R6`.

## §12. Deploy, Rollback & Environments
- **Railway** `locked`: Docker build from GitHub, deploy from the first commit. Railway **managed
  Postgres** (exploit DB), **cron** (regression trigger), **deployment history** (rollback). No GPU.
- Perf baselines measured **on Railway**, not locally. Secrets via Railway env references.
- Rollback story: revert to a prior Railway deployment; Postgres migrations are forward-only with
  documented down-paths where feasible.

## §13. Failure Modes & Resilience
| Failure | Handling |
|---|---|
| Red Team produces genuinely harmful content | Quarantine + containment (§5); never executed outside the allowlisted target |
| Judge agrees with everything (drift) | Ground-truth calibration set + drift detection (`judge-calibration`); escalate on uncertainty |
| Orchestrator has no clear next priority | Fallback policy: least-covered category, then oldest open finding, then regression sweep |
| Cascading agent failure in one run | Typed errors per boundary; run isolation; partial results persisted; run marked degraded not lost |
| Target unreachable / rate-limited | Typed error → backoff → queue → abort; campaign paused, not failed silently |
| Cost accrues without signal | Circuit-breaker halts/redirects the campaign |
| Overnight run auditability | Append-only audit log reconstructs who/what/when/order |

## §14. Human Approval Gates & Platform Trust/Safety
- Gates: **publish a critical-severity finding**, and **any remediation**. Autonomy covers discovery,
  evaluation, regression, and drafting; humans own the high-cost calls.
- Who may trigger runs / view reports is access-controlled; overnight runs are fully audited.
- This boundary is the CISO answer: where it proceeds autonomously, where it stops, how it
  communicates confidence, and what happens when confidence is wrong.

## §15. AI-Use Disclosure (draft — finalized by arch-finalize)
For each agent role: what AI does, what is independently verified, what human approval gates it, and
what residual risk remains. Central item: **the Judge's criteria are independently verifiable** —
document how a drifting Judge is detected (ground-truth agreement, cross-run consistency) and
corrected. Deterministic validators (contract compat, eval-case schema, duplicate detection,
data-quality) are the explicit "where we deliberately did *not* use AI."

## §16. Build-vs-Configure Summary → ADR-0001
**Configure/wrap the mechanism; build the four graded capabilities.** `locked` (full record:
`docs/adrs/0001-build-vs-configure.md`).
- **Wrap (seeds/engine):** Garak (breadth probes) · PyRIT (multi-turn orchestrators + converters) ·
  Giskard RAGET (RAG-specific seeds).
- **Configure (free, satisfies graded reqs):** Promptfoo (OWASP LLM+Web / MITRE ATLAS / NIST mapping —
  no custom code) · OWASP ZAP (web-layer DAST, *contingent on a target web surface*) · Semgrep (SAST
  on our code).
- **Build (no tool delivers these):** Orchestrator · the Red Team's autonomous coverage-driven
  **mutation loop** · the independent drift-guarded **Judge** · Documentation + regression-admission.
- **Do not adopt:** any commercial LLM red-team platform (Lakera/HiddenLayer/Robust Intelligence) —
  out of budget, closed, un-governable, and *is* the product we're asked to build.

## §17. Open Questions & Risks
- OQ1 target auth mode · OQ2 target API shape + rate limits · OQ3 seeded-data provenance · OQ4 stack
  cluster (resolving via research) · OQ5 local-vs-hosted Red Team for MVP (`PRESEARCH.md §9`).
- Top risks: target details slipping Stage 1; Red Team refusals blocking generation; Judge drift
  eroding trust; cost blow-up at scale; the ~2.5h Defense window vs artifact volume.
