# ADR-0001 — Build vs Configure (security tooling + platform stack)

- **Status:** Accepted; reconciled to the as-built platform on 2026-07-25
- **Date:** 2026-07-20
- **Deciders:** platform author; reviewed at the Architecture Defense
- **Required by:** PRD "Optional Engineering Deliverables → Build-versus-configure decisions" (a graded
  Architecture Defense deliverable)
- **Sources:** `docs/planning/RESEARCH.md` (July 2026, sourced); `docs/planning/DECISIONS.md`

## Context
The platform must continuously red-team a live OpenEMR Clinical Co-Pilot (RAG + write-back + tools +
uploads) as an **autonomous multi-agent system**, defensible to a hospital CISO, on a $50–200 dev
budget, in Python, hosted on Railway (managed Postgres, cron, no GPU). Mature tools exist for pieces of
this — LLM red-team scanners, web DAST, SAST, agent frameworks, observability, queues. The decision the
PRD grades is: *for each capability, do we configure/wrap an existing tool, or build a custom agent —
and why is a custom agent justified where we build one?*

The organizing principle: **configure/wrap the mechanism, build the graded capabilities.** A commercial
platform that "does adversarial testing" is exactly the product we are asked to build — buying one
fails the assignment, the budget, and the governance model.

## Decision

### A. CONFIGURE / WRAP (free OSS, behind our framework-neutral JSON-Schema contracts)
| Tool | Role | Why configure, not build |
|---|---|---|
| **NVIDIA Garak** 0.15.1 | Breadth candidate source | Native JSONL import and one bounded offline probe are operational; other probe families remain adapter-only |
| **Microsoft PyRIT** 0.14.0 | Converter and multi-turn candidate source | Three converters and native `AttackResult` import are operational; scorers and multi-turn orchestrators are advisory/adapter-only, never verdict authority |
| **Giskard Scan** 1.0.0b3 | Agent/RAG scenario source | Packaged prompt-injection scenario loading and native scenario/result import are operational; generated attacks and target scans remain adapter-only |
| **Promptfoo** 0.121.19 | Deterministic offline eval-runner + mapping metadata | Native results import and a pre-authored offline eval are operational with remote generation disabled. Promptfoo has no `owasp:web` preset; ZAP supplies deterministic OWASP Web mapping |
| **OWASP ZAP** | **Web-layer DAST** + CI gate for the OWASP *Web* Top 10 half (upload/ingestion, write-back API, SSRF, path traversal, authz) | Deterministic web scanning is a solved problem; an LLM is the wrong tool. *Contingent on the target exposing a web surface — confirm at inspection* |
| **Semgrep** (free CLI) | **SAST on our own platform code** (agents, adapter, prompt-construction, policy) | Scans *our* code, never the target; deterministic beats an LLM here |
| **Langfuse Cloud**, **Postgres `SKIP LOCKED` queue**, **Railway services/scheduler** | Infrastructure we configure | Managed hosting, database primitives, and observability transport are infrastructure; campaign policy, orchestration, authorization, evidence, and retry semantics remain package-owned |

### B. BUILD custom (the four graded capabilities no tool delivers)
1. **Orchestrator** — reads observability (coverage gaps, open findings, regressions), prioritizes the
   next campaign, triggers regression, governs cost. *No scanner has the concept of a coverage map or a
   cost governor.*
2. **Red Team's autonomous, coverage-driven mutation loop** — wrapped corpora are *static seeds*; the
   PRD's "static payload lists are insufficient" is exactly the gap. (Garak's own literature: probes
   "follow a set plan" with "intrinsically limited coverage.")
3. **Independent, calibrated, drift-guarded Judge** — must *never* approve a confirmed exploit
   (invariant). PyRIT scorers are attack-coupled; Promptfoo's LLM-judge is generic — both violate
   independence. CSA's 2026 evaluation: PyRIT has *no* native RAG-layer or tool-call testing and cannot
   verify an agent's tool calls matched its stated intent — precisely this target's surface.
4. **Documentation + regression-admission harness** — confirmed exploit → schema-gated vuln report;
   Postgres exploit DB with the "passed for the right reason" promotion gate.

### C. Platform-stack build-vs-configure (summary; full rationale in `DECISIONS.md`)
- **Orchestration = build package-owned Python coordination** around versioned contracts and
  PostgreSQL durability. `SecureCampaignCoordinator`, `DurableCampaignRunner`, and
  `DurableScheduler` use the queue, leases, audit state, and physical work-unit reservations; human
  approval is persisted policy state rather than a framework pause.
- **Observability = configure Langfuse Cloud (Hobby) for MVP** (OTEL SDK v4, synthetic data only);
  **self-hosted Langfuse is a documented post-MVP path only** (its full Web+Worker+PG+ClickHouse+Redis+S3
  footprint is not the MVP choice — F3). The **Postgres exploit DB is the authoritative system of record**
  for finding status, and Langfuse failure falls back to Postgres-derived coverage/priority signals. Reject
  LangSmith/Braintrust (Enterprise-only self-host).
- **Models = stage one content-addressed OpenRouter set**: Opus 4.8 Orchestrator, Qwen 3.5
  397B-A17B Red Team, Gemini 2.5 Pro Judge, and GPT-5.4 Documentation. The observed Judge
  identity/hash must pass ground-truth calibration and be human-enabled before campaign launch.
- **Queue = build a thin `SKIP LOCKED` Postgres queue**, not configure Redis/Celery — Railway has no
  managed queue and a second stateful service splits state off the exploit DB.

### D. DO NOT ADOPT
Any commercial LLM red-team platform — **Lakera Red, HiddenLayer, Robust Intelligence / Cisco AI
Defense**. Excluded on three independent grounds: **budget** (sales-only, $10k–$200k+ vs $50–200);
**architecture** (closed, non-composable, un-governable under our own allowlist/cost caps); **thesis**
(adopting one *is* the reusable platform we're told to build).

Burp Suite Pro/DAST/Enterprise was evaluated as the reference manual web-testing workflow but the
commercial product is not installed or purchased for this MVP. Headshot instead implements the
relevant workflow as an LLM-focused Security Workbench: the outbound ledger and Traces provide
Proxy/Logger/Inspector, regression provides governed Repeater, Garak/PyRIT/Giskard/Promptfoo provide
bounded Intruder inputs, ZAP provides passive Scanner, and the independent Judge/evidence system
provides Comparer. Licensing, closed execution, and vendor governance still preclude presenting
Burp itself as integrated. Active DAST, public out-of-band callbacks, DOM testing, and
instrumented-runtime testing remain explicitly unclaimed.

## Consequences
- **Positive:** near-zero integration cost; OWASP **LLM** mapping (`owasp:llm`) + multi-turn scaffolding +
  web DAST come for free — **OWASP Web category mapping is our own deterministic validator over OWASP ZAP
  output, not a Promptfoo preset** (F12); the four custom capabilities are exactly the graded, defensible
  work; wrapped-tool output is
  normalized into versioned contract JSON, so **no tool choice can force a schema rewrite**; the whole
  stack runs under our own cost/allowlist governance.
- **Negative / risks:** the bounded native adapter and offline-execution slice is implemented, but the
  **MVP still ships the reviewed nine-case corpus**. Tool candidates require a separate reviewed corpus
  hash and fresh authorization; multi-turn framework orchestrators remain adapter-only (D12). External
  HTTP side effects are not atomic with PostgreSQL, so the Runner reserves physical work before send,
  preserves ambiguous outcomes, and refuses blind replay. Promptfoo
  (OpenAI-acquired Mar 2026) is a single-vendor licensing risk → Giskard/custom-runner fallback.

## Invalidation conditions
- The deployed Co-Pilot exposes **no web/HTTP surface** (only a model endpoint) → the ZAP/Burp web-DAST
  slot drops; re-scope the OWASP-Web half. **Confirm from the running target before freezing.**
- PyRIT/Garak ship native RAG + tool-intent-verification testing → shrink the custom Judge scope.
- Promptfoo relicenses off MIT or gates red-team plugins → adopt the Giskard/custom eval-runner fallback.
- A frozen model becomes unavailable or returns a different identity → stage a new reviewed
  configuration hash, re-run acceptance, recalibrate the exact Judge identity, and obtain new
  authorization rather than silently substituting.
