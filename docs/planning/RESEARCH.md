# RESEARCH.md — AgentForge / Adversarial Machine

> Sourced findings behind the stack decisions, from the `agentforge-stack-adr-research` workflow
> (6 parallel research agents + synthesis, ~408k tokens, July 2026 sources). Each area records the
> recommendation, the options weighed, invalidation conditions, sources, and residual open questions.
> Decisions themselves live in `DECISIONS.md`; the build-vs-configure verdict is `docs/adrs/0001-build-vs-configure.md`.
> **Facts here reflect July 2026; re-verify pricing/versions before relying on a number for a CISO.**

---

## R1 — Security tooling: build vs configure (confidence: high)
**Finding.** CONFIGURE/WRAP existing OSS behind our framework-neutral contracts; BUILD custom only
for the four capabilities no tool delivers.
- **WRAP as seed/engine (behind the Red Team adapter):** NVIDIA **Garak** v0.15.0 (50+ probes +
  new Agent-breaker/GOAT multi-turn probes) as breadth seed source; Microsoft **PyRIT** (Crescendo/
  TAP/RedTeaming multi-turn orchestrators + converters + memory) as the multi-turn engine; **Giskard
  RAGET** v3 for RAG-specific seeds (retrieval poisoning, cross-patient context leakage) — the one
  gap Garak/PyRIT leave open for this target.
- **CONFIGURE (near-zero integration, free, satisfies graded reqs):** **Promptfoo** (MIT; ships OWASP
  LLM Top 10 presets + MITRE ATLAS + NIST AI RMF mappings → satisfies the per-case OWASP-mapping
  requirement with no custom code); **OWASP ZAP** (web-layer DAST + CI gate for the OWASP *Web* Top 10
  half: upload/ingestion, write-back HTTP API, SSRF, path traversal, authz); **Semgrep** (free CLI,
  AI-security rules — scans *our* platform code, never the target).
- **BUILD custom (the graded agent work):** (1) Orchestrator (coverage-gap reading + prioritization +
  cost governance — no scanner has the concept); (2) the Red Team's autonomous, coverage-driven
  **mutation loop** (wrapped corpora are *static* seeds; "static payload lists are insufficient" is
  exactly what no scanner covers); (3) the independent, calibrated, drift-guarded **Judge** (PyRIT
  scorers are attack-coupled, Promptfoo's LLM-judge is generic — both violate independence); (4)
  Documentation + regression-admission harness with the "passed for the right reason" gate.
- **Do NOT adopt** any commercial LLM red-team platform (Lakera / HiddenLayer / Robust Intelligence–
  Cisco AI Defense): sales-only, enterprise-priced ($10k–$200k+), closed, un-governable under our
  allowlist/cost caps — and adopting one *is* the product we're told to build. Burp Suite Pro
  ($499/yr) is deferred to optional-at-Final; never Burp DAST/Enterprise.
- **Invalidation:** the deployed Co-Pilot exposes *no* web/HTTP surface (only a model endpoint) →
  ZAP/Burp slot drops; PyRIT/Garak ship native RAG + tool-intent testing → shrink our custom Judge
  scope; Promptfoo (OpenAI-acquired Mar 2026) gates plugins off MIT → fall back to Giskard/custom.
- **Sources:** github.com/NVIDIA/garak · arxiv.org/pdf/2406.11036 · cloudsecurityalliance.org
  (Evaluating PyRIT for Agentic AI Red Teaming, 2026) · azure.github.io/PyRIT · promptfoo.dev/pricing ·
  github.com/promptfoo/promptfoo.

## R2 — Orchestration framework (confidence: high)
**Finding.** **LangGraph** (MIT, **OSS engine only** — self-hosted via pip; *not* LangGraph Platform/
LangSmith). PostgresSaver checkpointer on the same Railway Postgres as the exploit DB. `interrupt()` /
`Command(resume=…)` is the human-approval gate at any node; per-node LLM clients structurally enforce
Judge independence. Reject **AutoGen** (maintenance mode as of 2026) and **CrewAI** (task-level HITL,
no first-class Postgres checkpointer).
- **Fallback (a swap, not a rewrite):** a thin custom asyncio orchestrator on the *same* JSON-Schema
  contracts, writing its own checkpoint rows. If unattended multi-hour campaigns need exactly-once,
  layer **DBOS-on-Postgres** *under* LangGraph rather than replacing it.
- **Caveat (feeds §13 failure modes):** LangGraph checkpoints are crash-*persistence*, not durable
  execution — no watchdog/auto-resume, no dup-execution guard on a `thread_id`. Add an application-
  level lock against overlapping campaigns; consider DBOS if unattended long campaigns become in-scope.
- **Invalidation:** a LangGraph 1.x breaking change to `interrupt()`/PostgresSaver before MVP; a true
  exactly-once requirement. **Pin the LangGraph 1.x version before freezing the ADR.**
- **Sources:** docs.langchain.com/oss/python/langgraph/persistence · …/interrupts · …/add-memory ·
  learn.microsoft.com (AutoGen→Agent Framework migration) · framework comparison (Latenode 2025).

## R3 — Observability backend (confidence: high)
**Finding.** **Self-hosted Langfuse** (MIT) on Railway, instrumented with the **OTEL-native Langfuse
SDK v4** so emission stays framework-neutral. One-request = one-trace: Orchestrator opens the root
span; Red Team/Judge/Documentation are child spans tagged `{agent, attack_category, owasp_web,
owasp_llm, system_version, verdict}` → native per-agent cost roll-up + the six questions via Custom
Dashboards/Metrics API. Reject **LangSmith** and **Braintrust** (self-host is Enterprise-only → fail
the Railway/Postgres-in-perimeter + budget constraints).
- **Ownership split (must be pinned so they don't drift):** Langfuse *observes the campaign*; the
  **Postgres exploit DB is system-of-record** for Q4 (vuln open/in-progress/resolved) and Q3
  (resilience trend), surfaced from a custom Postgres view.
- **Defense-window fallback:** demo on **Langfuse Cloud Hobby** (free, 50k units/mo) for the ~2.5h
  Defense (the 6-container self-host stack — ClickHouse+Redis+MinIO+web+worker+PG — may not stabilize
  in time), then cut to Railway self-host for MVP with **zero re-instrumentation**. Compliance is a
  *simulation* on synthetic data (confirmed) → OSS self-host is sufficient; no BAA tier needed.
- **Sources:** langfuse.com/pricing-self-host · railway.com/deploy/langfuse · langfuse.com/self-hosting
  /…/clickhouse · langfuse.com/docs/observability/…/token-and-cost-tracking · …/custom-dashboards ·
  langfuse.com/integrations/native/opentelemetry.

## R4 — Per-role model assignment (confidence: high)
**Finding.** A **different model per role**, sized to its refusal-vs-capability need, with Red-Team/
Judge provider independence enforced structurally.
- **Red Team** (must not refuse authorized offensive generation; bounded per-run cost): local
  uncensored open-weights via Ollama. **Given the 32–48GB Mac (confirmed): default to a 24–33B model
  (Dolphin-Mixtral, WhiteRabbitNeo-33B-v1.5); a 70B is tight/slow.** Hosted-OSS burst (OpenRouter
  venice/uncensored 24B free for smoke tests; Together Dolphin 3.0 / Euryale 70B paid) for the hardest
  multi-turn cases and at 10K+ scale. **Never Claude/GPT for Red Team** (they refuse). Prefer
  fine-tuned-uncensored over abliterated (stability).
- **Judge** = **Claude Sonnet 4.6** — high refusal-integrity is exactly the "never approve a confirmed
  exploit" property; independence is structural (shares no weights/provider with the local Red Team).
  Bulk verdicts via Batch API (50% off) + prompt-cache the shared rubric (0.1× input). Fallback:
  GPT-5.4 (still frontier, still independent).
- **Orchestrator** = **Claude Opus 4.8** for planning-grade reasoning; low call volume makes it
  affordable; economize to Sonnet 4.6 / Gemini 3 Pro when budget runs hot.
- **Documentation** = **GPT-5.4** — deliberately a *different vendor from the Judge* to avoid
  single-vendor correlated failure on the trust chain; output is deterministically schema-gated by the
  vuln-report validator regardless of model. Fires only on `exploit_rate × N` → sub-linear.
- **Invalidation:** a provider ships a frontier model with a reliable *authorized-security-testing*
  mode → could collapse the local Red Team tier into hosted.
- **Sources:** dev.to (Red-Team AI Benchmark: uncensored LLMs) · atlascloud.ai (uncensored models 2026)
  · benchlm.ai/llm-pricing · Together pricing (aipricing.guru) · markaicode (Ollama 70B M4 Max tok/s).

## R5 — State + work/regression queue (confidence: high)
**Finding.** **One Railway Postgres** is state store + work queue + exploit DB. Hand-rolled `jobs`
table drained with `SELECT … FOR UPDATE SKIP LOCKED`; two logical queues via a `queue` column
(`agent_work` | `regression_run`) + priority. Backoff = `run_after`/`attempts` columns; abort = status
flag (feeds the live-campaign abort gate); depth = a `count(*)` observability already reads. **Railway
cron is a thin, idempotent ENQUEUE trigger** (inserts rows; never runs work inline — sidesteps cron's
5-min-min / overlap-skip / no-kill limits). **No Redis/Celery/RQ/Dramatiq** (Railway has no managed
queue; a second stateful service splits state off the exploit DB). Total scale (100→100K runs) is ~2
orders of magnitude below SKIP LOCKED contention limits.
- **Fallback:** **pgmq** on the same Postgres for SQS-style metrics — but it needs extension support
  (schema-only install on the default Railway template, or the Supabase-Postgres template) and lacks
  configurable backoff/max-attempts, so it stays fallback.
- **Watch:** hot-queue-table bloat — keep claim transactions short (claim→commit→process outside txn),
  archive completed jobs, tune autovacuum.
- **Sources:** docs.railway.com/guides/cron-workers-queues · docs.railway.com/cron-jobs ·
  planetscale.com (healthy Postgres queue) · nerdleveltech.com (LISTEN/NOTIFY + SKIP LOCKED) ·
  github.com/pgmq/pgmq · Railway extension-support thread.

## R6 — Cost model @ 100/1K/10K/100K runs (confidence: high)
**Finding.** Two independent line families on *different* scaling functions — never tokens × N.
`Cost(N) = Hosting_tier(peak_concurrency) + Σ_agents[ runs_routed(N) × effective_cost_per_run ] +
Storage(rows(N)) + Egress(bytes(N))`, where `effective_cost_per_run = list_price / realized_throughput
_at_offered_load` (list-price × tokens overstates by 17–36× under load).
- **Hosting = step function of PEAK CONCURRENCY** (Railway Jul-2026: $20/vCPU-mo, $10/GB-RAM-mo,
  $0.15/GB-mo storage, $0.05/GB egress): L1 platform compute ~$40/mo holds 100–1K; L2 managed Postgres
  ~$10–20/mo flat within a tier; L3 cron is the one hosting line scaling with N (tiny); Langfuse
  self-host adds ~$20–60/mo (ClickHouse RAM-driven).
- **Inference = per-run, split per agent:** Red Team local-Mac = amortized capex + electricity,
  **throughput-capped (~8–17 tok/s for 70B Q4; a 24–33B is faster on the 32–48GB box)** not
  price-capped; hosted-OSS overflow ~$0.88–1.20/M. Judge/Orchestrator/Documentation frontier,
  quality-bound; levers = prompt-cache shared context (0.1× input) + Batch API (50% off).
- **Per-tier architectural change (the whole point):** 100 = baseline, hosting dominates; 1K =
  prompt-cache + Batch API; 10K = move Red Team fully off frontier to local/hosted-OSS + queue
  backpressure (keep compute on one instance tier) + time-range partition the exploit DB; 100K =
  **sample** regression runs + BRIN-on-timestamp + partial B-tree on hot partitions + dedicated worker
  + verdict caching for duplicate sequences.
- **Sources:** docs.railway.com/pricing · docs.railway.com/cron-jobs · Anthropic pricing + Batch API
  docs · Together pricing · arxiv (offered-load throughput spread).

---

## Cross-cutting open questions (carried to the ADR / MVP measurement)
- **Confirm the target exposes a raw web surface** (upload/write-back/auth) for ZAP, not only a chat
  endpoint (`PRESEARCH.md` OQ2). Given the confirmed upload + write-back + tool surface, a web layer is
  *likely* present — but freeze the ZAP slot only after inspection.
- **Measure per-agent token profiles from real traces** — the largest source of cost-model error;
  placeholder token counts cannot be shown to a CISO.
- **Measure real Mac tok/s** on the 32–48GB box to fix the local-vs-hosted-OSS crossover tier.
- **Measure `exploit_rate`** — sets Documentation call volume + its sub-linear scaling.
- **PyRIT-at-MVP vs hand-authored seeds:** recommendation — MVP ships a hand-authored seed corpus +
  our custom mutation loop (the hard gates) with PyRIT/Garak/Giskard wrapped post-MVP; the contract
  JSON makes seed sources hot-swappable. (A tasks-gen/tdd-swarm sequencing call, not an architecture one.)
- **Postgres template:** default Railway (pg_cron) with hand-rolled SKIP LOCKED queue is the primary;
  Supabase-Postgres template only if the pgmq fallback is taken. Record in the ADR.
- **Pin LangGraph 1.x version**; settle the Langfuse-vs-exploit-DB ownership split for Q3/Q4.
