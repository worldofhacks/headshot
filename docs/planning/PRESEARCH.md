# PRESEARCH.md — AgentForge / Adversarial Machine

> Consolidated Phase 0–9 planning artifact (Standard mode). Framework-neutral by design:
> the build-vs-configure ADR (`docs/adrs/`) locks the stack; nothing here presumes it.
> Produced by `/arch-draft`. Downstream: `/arch-finalize` → `ARCHITECTURE.md`.
>
> **Tag legend:** `locked` = decided this session · `proposed` = recommendation, confirm at finalize ·
> `open` = unresolved, must not be invented · `simplification` = posture-gated cut, justified ·
> `hardening` = load-bearing under the production-grade posture · `deferred` = out of this week ·
> `research` = pending the stack-ADR research workflow.

---

## §0. Intake

**Product in one sentence.** A reusable, multi-agent adversarial evaluation platform that
*continuously* red-teams AI-assisted clinical workflows — discovering, evaluating, validating,
regression-guarding, and documenting vulnerabilities autonomously — with the deployed OpenEMR
Clinical Co-Pilot as target #1.

**Is:**
- An autonomous multi-agent red-team *system* — Orchestrator · Red Team · Judge · Documentation —
  plus a regression/validation harness and an observability layer.
- **Target-agnostic**: every target is reached through a pluggable adapter behind an allowlist.
- **Production-grade**: defensible to a hospital CISO, not a demo.

**Is not:**
- A static payload list, a single-agent or linear pipeline, or a one-time pentest.
- "The most impressive jailbreak in a demo."
- A system where one agent both attacks and judges (compromised by design).
- A repo that contains any target code (the Co-Pilot is attacked over its live URL).

**Primary problem.** The current testing process relies on manual prompting and static attack
lists; vulnerabilities are hard to reproduce, fixes are validated once and never re-tested, and
there is limited visibility into which attack categories are covered. The concern is not whether a
single exploit exists — it is *whether the system can continuously identify, evaluate, and defend
against new attack techniques as the platform evolves*.

**Primary user.** A security engineer / platform operator responsible for continuously stress-testing
an AI system wired into clinical workflows (see `USERS.md`). The judging stakeholder is a hospital
CISO deciding whether to trust the platform.

**Core workflow (mechanics).** Orchestrator reads observability (coverage gaps, open findings,
regressions) → prioritizes the next campaign → tasks the Red Team → Red Team generates/mutates
adversarial inputs (multi-turn) against the target via its adapter → transcripts captured → the
**independent** Judge returns success / fail / partial → partials feed back to the Red Team for
mutation; confirmed exploits go to Documentation (human-gated for critical) → confirmed exploits are
admitted to the regression harness → regression replays run on target change (Railway cron) →
everything is traced into observability → loop.

**External dependencies.** The live OpenEMR Clinical Co-Pilot (target); model backends (Anthropic,
OpenAI, hosted OSS via OpenRouter/Together, local Ollama on a Mac); Railway (host, managed Postgres,
cron, deployment history); GitHub (repo + CI).

**Ambiguities / risks (carried into §8–§9).** The Co-Pilot's exact auth mode and API shape are
`open` pending inspection; target rate limits are unknown; the stack cluster is `research` pending
the ADR workflow; "stand up the target" reduces to confirming a live URL (target status = *deployed
& reachable now*).

---

## §1. Planning Mode & Build Posture

- **Planning mode — Standard** `locked`. Artifact set: `PRESEARCH.md`, `RESEARCH.md`, `DECISIONS.md`,
  `ARCHITECTURE_DRAFT.md`, `DIAGRAM_PLAN.md`, `CLAUDE_CODE_HANDOFF.md` in `docs/planning/`, plus the
  root/Defense deliverables `USERS.md`, first-pass `THREAT_MODEL.md`, `docs/defense/DEFENSE_SCRIPT.md`,
  and the build-vs-configure ADR in `docs/adrs/`. Matches PLAN.md §5.
- **Build posture — production-grade** `locked` (CLAUDE.md, PLAN.md §1). The bar is "defend it to a
  hospital CISO." Testing, deploy/rollback, failure-mode coverage, observability, auth, and error
  paths are in-scope requirements, not deferrable. Cuts are explicit `simplification` deferrals,
  never silent.

---

## §2. Users, Actors, and Permissions

### 2.1 Human actors
| Actor | Does | Cannot |
|---|---|---|
| **Security Engineer / Operator** (primary) | Authorizes + launches live campaigns, reviews findings, approves critical reports + remediation, sets budget/rate caps, reads observability | — |
| **Reviewer / Approver** (human gate) | Approves/denies publication of critical findings and any remediation; can be the same person as Operator but is a distinct *role* | Be bypassed by any agent |
| **Hospital CISO / Compliance** (judging stakeholder) | Judges whether the platform is trustworthy; consumes ATO packet, trust boundaries, AI-use disclosure | (not an operator) |

### 2.2 Machine actors (agents) — trust levels + permissions `locked` (shape)
Distinct trust levels are a hard gate. The access-control matrix (which agent may write exploits,
which may only read, what needs human approval) is load-bearing.

| Agent | Trust | Reads | Writes | Must NOT |
|---|---|---|---|---|
| **Orchestrator** | governor | observability, coverage, findings, budget | campaign queue, regression triggers, budget/abort signals | generate attacks or render verdicts |
| **Red Team** | **low / quarantined** (produces + handles adversarial content) | seed corpus, target via adapter, prior partials | candidate attempts + transcripts | write to the regression store; publish; render its own verdict |
| **Judge** | **independent** | attack transcripts, expected-safe behavior, ground truth | verdicts (success/fail/partial), uncertainty/escalation | generate or mutate attacks; approve a confirmed exploit as safe (invariant) |
| **Documentation** | gated | confirmed exploits | draft vuln reports | publish a **critical** report without human approval |
| **Regression harness** | deterministic | regression store, target | regression run results, regression/reappearance flags | admit a case that only "passes because model behavior changed" |
| **Observability** | append-only | all agent events | traces, metrics, cost records | mutate historical records |

### 2.3 Access-control invariants
- Only the Documentation flow (post-Judge) may create a *published* finding; only a human may
  publish a **critical** one. `hardening`
- Only the regression-admission path may write to `evals/regressions/`; the Red Team cannot.
- Credentials are **bound to their target**; cross-target credential use is impossible by
  construction (per-target credential provider, secrets by reference). `locked`

---

## §3. Stakeholders & Reviewers (what evidence they need)

| Reviewer | Judges | Evidence they need |
|---|---|---|
| **Architecture Defense grader** (~2.5h) | Is the multi-agent design deliberate + defensible? | `ARCHITECTURE_DRAFT` + diagram, `DEFENSE_SCRIPT.md`, the **build-vs-configure ADR**, first-pass `THREAT_MODEL.md`, trust boundaries |
| **MVP / Final grader** | Thoroughness · thoughtfulness · creativity · viability + defensibility | live URL each checkpoint, eval suite (≥3 categories) + ≥1 live agent, contracts + tests, cost analysis, vuln reports, observability |
| **Hospital CISO (persona)** | Would I trust this with continuous testing of systems physicians depend on? | trust boundaries, human gates, deploy/rollback, cost governance, ATO packet, AI-use disclosure, "how you detect a drifting judge" |

---

## §4. User & Lifecycle Flows

**F1 — Campaign lifecycle (Orchestrator).** read observability → select campaign (coverage gap |
open finding | regression risk | new target version) → enqueue → dispatch Red Team → collect →
Judge → update coverage/findings → cost check (continue | halt/redirect if cost accrues without
signal). *Stop conditions:* budget cap, no-signal window, abort.

**F2 — Attack-case lifecycle.** authored (`evals/seeds/`) → run against target → judged →
`partial` → mutated into N variants (Red Team) → `success` → candidate finding → documented →
**promoted** to `evals/regressions/` (only if deterministic + passes-for-the-right-reason).

**F3 — Finding / vulnerability lifecycle.** candidate → judged(confirmed | rejected | partial) →
documented (draft, `vuln-report` schema) → **human approval gate (critical)** → published →
remediation proposed → fix validated (re-run) → resolved | reopened(regressed).

**F4 — Regression lifecycle.** target change → cron/Orchestrator trigger → full regression replay →
detect (a) previously-fixed vuln reappeared, (b) fixing one category regressed another → flag +
alert + reopen finding.

**F5 — Authorized live-campaign gate.** every live run passes: allowlist check → synthetic-data
assertion (no real PHI) → budget + rate caps armed → full trace capture → abort conditions live.
Live attacks are always intentional. `locked`

**F6 — Human-approval flow.** critical finding OR any remediation → pause → notify Reviewer →
approve/deny → resume. No autonomous publication of critical severity. `hardening`

---

## §5. Domain Model, State Machines, Invariants

### 5.1 Nouns (framework-neutral)
Target · TargetAdapter · AllowlistEntry · CredentialBinding · AttackCase(seed) · Attempt(run) ·
Transcript · Verdict · Finding/Exploit · VulnReport · RegressionCase · RegressionRun · Campaign ·
CoverageMetric · CostRecord · GroundTruthLabel · ContractVersion · Incident.

### 5.2 State machines
- **AttackCase:** `draft → active → retired`
- **Attempt:** `queued → running → {success | fail | partial} | error(typed)`
  typed errors: `target-unreachable · budget-exceeded · judge-timeout · rate-limited · adapter-error`
- **Finding:** `candidate → judged → documented → approved → published → remediated → validated →
  {resolved | regressed}`  (rejected findings exit at `judged`)
- **RegressionCase:** `admitted → passing → {failing(regressed)}`
- **Campaign:** `queued → running → {complete | halted(no-signal|budget) | aborted}`

### 5.3 Invariants (load-bearing — never cut)
1. **The Judge must never approve a confirmed exploit as safe.** (central invariant)
2. No agent both attacks and judges; the Judge is independent of attack generation.
3. A regression case is admitted only if it reproduces **deterministically** *and* passes for the
   right reason (a real fix, not changed model behavior).
4. No **critical** finding is published, and no remediation is applied, without human approval.
5. No live attack runs without passing the F5 authorization gate.
6. Every exploit record has a unique ID, all required fields, referential integrity, and no
   duplicate attack sequence.
7. Credentials are bound to their target; cross-target use is impossible by construction.
8. No real PHI — synthetic fixtures only.
9. Every attack case is tagged **boundary | invariant | regression** and mapped to **OWASP web +
   OWASP LLM**; no happy-path-only cases.
10. Cost is never modeled as tokens × N.

---

## §6. Requirements (testable — seeds the requirements matrix)

**Functional.** FR1 stand up target + submit live URL each checkpoint · FR2 threat model (6
categories + OWASP + ~500w summary) · FR3 eval suite ≥3 categories, reproducible · FR4 ≥1 live
agent vs live target by MVP · FR5 Red Team: novel generation + multi-turn + mutation of partials ·
FR6 independent Judge with consistent cross-run criteria + uncertainty escalation + drift detection ·
FR7 Orchestrator: coverage-driven prioritization + regression trigger + cost governance · FR8
Documentation: confirmed exploit → structured report, data-quality gated · FR9 regression harness:
versioned store, auto-run on trigger, reappearance + cross-category detection · FR10 observability
answers its six questions · FR11 versioned JSON-Schema contracts + typed error schemas + both-sided
contract tests + migration notes · FR12 ≥3 vuln reports + 10-finding triage report.

**Non-functional / engineering (all graded).** NFR1 OWASP web + LLM coverage · NFR2 build-vs-configure
ADR · NFR3 ATO evidence packet · NFR4 integration packet + e2e trace · NFR5 rate-limit/auth/backoff-
queue-abort documented · NFR6 exploit-DB data-quality validators · NFR7 migrations without data
loss · NFR8 SQL indexes + regression-run SLO verified in CI · NFR9 perf baselines + 100-case load
test (measured on Railway) · NFR10 cost analysis @ 100/1K/10K/100K runs · NFR11 AI-use disclosure ·
NFR12 human approval gates · NFR13 deploy/rollback path. Full mapping: PLAN.md §6.

---

## §7. Constraints, Evaluation, Timebox

**Constraints.** Language **Python** `locked`. Host **Railway** (Docker-from-GitHub, managed
Postgres, cron, deployment-history rollback, **no GPU**) `locked`. Local dev + Mac for local
open-weight inference at scale `locked`. Budget **$50–200 dev** `locked`. No real PHI `locked`.
Contracts framework-neutral JSON Schema `locked`. Exploit DB = Postgres `locked`.

**Evaluation axes.** thoroughness · thoughtfulness · creativity · viability + defensibility. The
deliverable that matters is the one defensible to a hospital CISO.

**Timebox.** Architecture Defense ~2.5h · MVP Tue 11:59 PM · Final Fri 12:00 PM.

---

## §8. Scope Inference (production-grade)

**Production-hardening (in-scope baseline).** `hardening`
- Idempotent attempts (replayable by ID); typed error taxonomy on every boundary.
- Retry/backoff on target + LLM errors; rate-limit handling documented as **backoff → queue →
  abort**.
- Secrets by reference (never inline); per-target credential binding; no secrets in logs/traces.
- **Adversarial-content containment**: the Red Team can produce genuinely harmful content — it is
  quarantined, never executed against anything but the allowlisted target, never logged raw where a
  human could be harmed, and never able to reach the platform's own control plane.
- Judge drift detection + a ground-truth calibration set.
- Cost circuit-breaker (halt on no-signal / budget); per-agent cost attribution.
- Audit log sufficient to reconstruct an overnight run (who/what/when/order).
- PHI-safe telemetry (synthetic only; scrub on ingest).
- Deploy/rollback via Railway deployment history; migrations that don't lose data.

**Scope simplifications (posture-gated cuts — flagged, not silent).** `simplification`
- One target wired this week (OpenEMR); the adapter/allowlist stay pluggable but only target #1 is
  configured.
- Adapter is **API-primary**; the UI (browser) path is a thin evidence/e2e slice, not the bulk
  attack channel.
- Local open-weight Red Team inference is a *scale* option (Mac); MVP may use hosted OSS to hit the
  deadline. `research`

---

## §9. Assumptions & Open Questions

**Assumptions (confirmed this session).** Target is deployed & reachable now; it has the full
attack surface (RAG + write-back + tools + uploads); it exposes both an API and a UI; it has seeded
demo data usable as synthetic fixtures; Railway + Postgres are acceptable; per-role model mixing is
available.

**Open questions (must not be invented).** `open`
- OQ1 OpenEMR Co-Pilot's exact **auth mode** (session/bearer/OAuth/none) — pending inspection; the
  per-target credential provider is designed so this does not block.
- OQ2 The target's exact **API shape** + streaming behavior + any **rate limits**.
- OQ3 Provenance/scope of the target's **seeded demo data** (confirm synthetic, no real PHI).
- OQ4 The **stack cluster** — orchestration framework, observability backend, per-role models,
  state/queue mechanism — `research` pending the ADR workflow (`docs/adrs/`, `RESEARCH.md`).
- OQ5 Whether local Mac inference is fast enough for MVP Red Team volume or hosted OSS is used first.

---

## §10. Early Decisions (locked from the interview)

| # | Decision | Value |
|---|---|---|
| D1 | Planning mode | Standard |
| D2 | Build posture | Production-grade |
| D3 | Language | Python |
| D4 | Platform host | Railway (Docker/GitHub, managed Postgres, cron, deployment-history rollback; no GPU) |
| D5 | Exploit DB | Postgres (versioned, indexed by severity/category/version, migratable) |
| D6 | Target reach | Both API + UI; adapter API-primary, UI for evidence |
| D7 | Target auth | Per-target pluggable credential provider; secrets by reference; credentials bound to target |
| D8 | Model posture | Frontier for Judge/Orchestrator/Documentation; refusal-resistant OSS for Red Team |
| D9 | Budget | $50–200 dev; cost governed in `src/policy/`; hosting and inference are separate cost lines |
| D10 | Contracts | Versioned JSON Schema, framework-neutral |

Stack specifics (framework, observability, per-role model names, queue mechanism) are resolved in
`RESEARCH.md` + `DECISIONS.md` once the ADR research workflow lands — recorded there, not invented here.
