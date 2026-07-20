# PLAN.md — Setup & Roadmap

**Project:** AgentForge / Adversarial Machine — a multi-agent adversarial evaluation
platform that continuously red-teams the OpenEMR Clinical Co-Pilot.
**Status:** Greenfield. Skills wired; repo instruction files written; git pending.
**Source of truth:** `Week_3_AgentForge.pdf`. **Operating rules:** `CLAUDE.md`.

This document answers two questions: **what skills we need to create**, and **what
scaffolding we need to build** — sequenced against the real checkpoint deadlines.

---

## 1. Decisions locked this session

| Decision | Choice | Consequence |
|---|---|---|
| Build posture | **`production-grade`** (locked) | Bar is "defend it to a hospital CISO." Testing, deploy/rollback, failure-mode coverage and observability are required. Both arch skills audit against this. |
| Build tool | **Claude Code primary** | Skills in `.claude/skills/`; existing frontmatter kept as-is; no Codex `openai.yaml` / `$skill` / normalization work. |
| Target | **Platform is target-agnostic**; the already-deployed OpenEMR Co-Pilot is target #1 | No target code here. Targets are reached through a **pluggable adapter behind an allowlist**. Generalize the mechanism, specialize the content — the PRD-graded artifacts (threat model, evals, vuln reports) stay Co-Pilot-specific. |
| First-wave skills | threat-model · adversarial-eval-lifecycle · judge-calibration · authorized-live-campaign · **contract-steward** | Built via `skill-creator`. Contracts land first — agent implementation depends on them, and the message schemas are a required Defense evidence-packet item. |
| Skill shape | Skills **orchestrate deterministic validators** for mechanical checks, rather than using LLM judgment | One validator shared by the skill *and* CI, so guidance and enforcement can't drift. Build `validate-eval-case`, `detect-duplicate-sequence`, and contract-compatibility checks first — the PRD mandates these validators as product code regardless. Also a concrete answer to "where did you deliberately not use AI?" |
| Diagrams | **Excalidraw** (locked) | `arch-draft`'s two Excalidraw helper skills aren't installed — apply its layout/contrast rules manually. Commit `.excalidraw` source **plus exported SVG/PNG**, since `.excalidraw` doesn't render on GitHub. |
| Instruction files | Slim `AGENTS.md` (done, 563→32 lines); `CLAUDE.md` canonical | PRD no longer embedded in an instruction file; PDF is canonical. |

**Elevated from the audit:** the PRD's "**Optional Engineering Deliverables**" section
is **mandatory** — its own text says the items are graded and not optional. The roadmap
and requirements matrix below treat them as required.

---

## 2. Two tracks — don't confuse them

The PRD names four "agents." Those are **runtime application components**, not Claude
skills. Skills are **our** development workflows. Keep them separate.

| PRD component | What it is | Built where | Powered by |
|---|---|---|---|
| Orchestrator Agent | app code | `src/agents/orchestrator/` | reads observability → prioritizes; triggers regression; cost governor |
| Red Team Agent | app code | `src/agents/red_team/` | offensive-capable model (local/OSS candidate); seeded by `adversarial-eval-lifecycle` |
| Judge Agent | app code | `src/agents/judge/` | independent model; kept honest by `judge-calibration` |
| Documentation Agent | app code | `src/agents/documentation/` | emits reports in the `vuln-report` schema |
| Regression harness | app code | `src/regression/` + `evals/regressions/` | deterministic; `eval-triage` diagnoses failures |
| Observability layer | app code | `src/observability/` | the data substrate the Orchestrator reads |

**Skills (this repo, `.claude/skills/`)** are the workflows we run to *build and defend*
the above — never one skill per runtime agent.

---

## 3. Existing skills — inventory & fit

All 10 live in `.claude/skills/` — single home, no duplicate source folder.

| Skill | Role in this project | Notes |
|---|---|---|
| `arch-draft` | PRD → `docs/planning/*`, `USERS.md`, defense script, diagrams | Diagrams in **Excalidraw**; its two helper skills aren't installed, so apply layout rules manually + export SVG/PNG. Reframe "users"-scale → **test-run** scale; stages → Defense/MVP/Final. |
| `arch-finalize` | Adversarial gap-audit → binding `ARCHITECTURE.md` | Run in a fresh session for cold eyes. |
| `tasks-gen` | `ARCHITECTURE.md` → `IMPLEMENTATION_PLAN.md` | Phase boundaries = the real checkpoints. |
| `tdd-swarm` | Build the platform via ticketed TDD sub-agents | Needs git + CI + stack decision first. |
| `devlog` | `docs/DEVLOG.md` + `PROJECT_STORY.md` | Run at every phase boundary — the interview tests process. |
| `eval-triage` | Diagnose failing evals | For the Red Team / Judge eval suite. |
| `bug-hunt` | Root-cause debugging + regression pins | Build/incident modes. |
| `grilling` | Stress-test a plan before building | Run before the Architecture Defense. |
| `grill-me` | Manual alias for `grilling` | Redundant but harmless in Claude Code; keep. |
| `interview-prep` | Mock interview from submission artifacts | Before each video interview. |

---

## 4. New skills to build

### Wave 1 — confirmed (build via `skill-creator`)

**`threat-model`** — maintain the living `THREAT_MODEL.md`.
- *Trigger:* "threat model", "map the attack surface", or a target change.
- *Inputs:* PRD, target surface (endpoints, tools, auth), existing eval results.
- *Outputs:* `THREAT_MODEL.md` — ~500-word summary + the six mandated categories
  (direct/indirect/multi-turn injection · PHI leakage / cross-patient / authz bypass ·
  state corruption / context poisoning · tool misuse / recursion · DoS / cost
  amplification · identity / role exploitation), each with **surface, impact, exploit
  difficulty, existing defenses**, plus **OWASP Web + LLM** mapping and a risk score.
- *Satisfies:* Stage 2 hard gate; OWASP mapping requirement.

**`adversarial-eval-lifecycle`** — owns a case's whole life: author → mutate → reproduce → promote.
- *Trigger:* "author an attack case", "mutate this exploit", "promote this to regression".
- *Inputs:* threat model category, a seed prompt/sequence, prior partial successes,
  confirmed exploits awaiting promotion.
- *Outputs:* schema-strict case in `evals/seeds/` — category/subcategory, input
  sequence, expected safe behavior, observed behavior, severity, exploitability,
  regression disposition, OWASP tags, and a **boundary | invariant | regression**
  classification (enforced — no happy-path-only cases). Mutation mode generates N
  variants of a partial success. **Promotion mode** admits a confirmed exploit into
  `evals/regressions/`.
- *Validators (deterministic, shared with CI):* `validate-eval-case` (required fields,
  OWASP enum, boundary/invariant/regression tag) and `detect-duplicate-sequence`.
- *Key rule:* a case is promoted only if it reproduces deterministically **and** the
  reason it now passes is a real fix — not changed model behavior. The regression
  harness itself is app code; this skill governs only **admission** into it.
- *Satisfies:* Stage 3 hard gate; "static payload lists are insufficient"; per-case
  OWASP mapping; feeds the Red Team seed corpus and the regression harness.

**`judge-calibration`** (new, from the audit).
- *Trigger:* "calibrate the judge", "check judge drift".
- *Inputs:* labeled ground-truth set (`evals/ground-truth/`), Judge verdicts across runs.
- *Outputs:* agreement metrics (vs. ground truth and across runs), uncertainty /
  escalation rules, **drift detection** report, and promotion thresholds for new
  criteria.
- *Satisfies:* "the Judge's criteria must be independently verifiable; document how you
  detect and correct a drifting judge"; "ground-truth dataset for evaluating Judge
  accuracy". This is the invariant guardrail: the Judge must never approve a confirmed
  exploit.

**`authorized-live-campaign`** (new, from the audit; **safety-gated**).
- *Trigger:* explicit only — `disable-model-invocation: true`. Live attacks are never
  implicit.
- *Inputs:* target allowlist, campaign scope, budget + rate caps, synthetic dataset.
- *Outputs:* a governed live run — allowlist + synthetic-data checks, budget/rate
  enforcement, full trace capture, and abort conditions — against the deployed target.
- *Satisfies:* "prevent the platform from being turned against systems it should not
  attack"; overnight-run auditability; cost/rate governance. This is core
  "hospital-CISO" material.

**`contract-steward`** (new — promoted from a template to a skill).
- *Trigger:* "define/change an agent contract", "bump the schema", or any edit to an
  inter-agent message shape.
- *Inputs:* the boundary being changed (Orchestrator→RedTeam, RedTeam→Judge,
  Judge→Documentation) and the current `contracts/` schemas.
- *Outputs:* versioned JSON Schema in `contracts/`; typed **success + error** schemas
  (target-unreachable, budget-exceeded, judge-timeout, no-findings-in-window,
  regression-detected); contract tests asserting **both** producer and consumer conform;
  a **migration note** for any breaking change; and the version bump itself.
- *Validators (deterministic, shared with CI):* schema compatibility / breaking-change
  detection, plus producer- and consumer-side conformance tests.
- *Key rule:* a breaking change without a version bump + migration note + updated
  contract tests is a failed run. Schemas stay **framework-neutral** so the
  build-vs-configure decision never forces a rewrite.
- *Trust boundary:* the skill **detects and reports** an incompatible change; it does
  **not** decide whether one is acceptable. That is a human approval gate.
- *Satisfies:* versioned protocol contracts; explicit error schemas; both-sided contract
  tests; migration notes; the Defense evidence packet's message-schema requirement; and
  it feeds the integration packet directly.
- *Why this one earns a skill:* it's the only requirement that fires a multi-step
  checklist *every time* an interface moves, and a silently drifted schema breaks an
  agent handoff without failing loudly.

### Wave 2 — specced, build when their inputs exist

- **`vuln-report`** — generate a report in the exact required schema (unique ID,
  severity, clinical impact, minimal reproducible sequence, observed vs expected,
  remediation, status + fix-validation). Enforces data-quality before writing (unique
  ID, required fields, no duplicate attack sequence) using the **same validator** the
  Documentation Agent runs. Includes a **triage mode** for the 10-finding simulated scan
  report (critical/high/medium/false-positive + validate/remediate/defer/document).
  Doubles as the **Documentation Agent's spec**. *Satisfies:* the ≥3 vulnerability
  reports; the triage exercise; exploit-DB data-quality.
- **`evidence-audit`** — audit checkpoint completeness against the requirements matrix
  (§6): what's built, tested, and has evidence vs. what's missing, per checkpoint. Also
  **verifies the AI-use disclosure** in `ARCHITECTURE.md` is complete and current.
  *Satisfies:* de-risks the "Optional = mandatory" surface; assembles the ATO +
  integration packets.
- **`cost-model`** — a script + template, *not* a skill: the 100/1K/10K/100K **run**-scale
  cost analysis (never tokens × N), including the architectural change required at each
  tier. Cost math is deterministic and the artifact is written once.

### What deliberately does NOT get a skill

Recorded so the reasoning is defensible under questioning — and so we don't grow a skill
set we can't maintain. **A skill must recur, be schema-strict, need judgment, and be a
*dev-time* workflow.** Everything below fails at least one test.

| Requirement | Home | Why not a skill |
|---|---|---|
| OWASP Web + LLM mapping per case | `adversarial-eval-lifecycle` (enum field + coverage view) + CI schema check | A required *field* and a query, not a workflow |
| Documentation Agent | **runtime agent** `src/agents/documentation/` | PRD requires it run without a human; `vuln-report` is its dev-time spec |
| Boundary / invariant / regression test design | `adversarial-eval-lifecycle` | ~90% overlap — splitting invites drift |
| Build-vs-configure ADR (Burp/ZAP/Semgrep/Garak) | `arch-draft` ADR + tool-survey reference file | One-time decision record |
| Integration packet | `contract-steward` output + `evidence-audit` | Assembly over existing contract artifacts |
| ATO evidence packet | `evidence-audit` | Completeness audit + assembly |
| AI-use disclosure | written by `arch-finalize`, **verified** by `evidence-audit`; judge half → `judge-calibration` | A section, not a workflow — but must stay current |
| Rate limits / auth / backoff-queue-abort | `ARCHITECTURE.md` + `src/policy/` | Doc + code |
| Exploit-DB data quality | validator in the Documentation Agent, shared with `vuln-report` | PRD says validate *in the agent* |
| DB migrations, queues, workflow state | `tdd-swarm` tickets; migration notes → `contract-steward` | Code |
| Data model, lineage, access control, human approval | `arch-draft`/`arch-finalize` — ARCHITECTURE §4 (trust boundaries) | Architecture |
| SQL indexes + regression SLO | code + CI check | Deterministic |
| Perf baselines + 100-case load test | benchmark script + CI | Deterministic beats an LLM here |
| Observability's six questions | `src/observability/` — treat them as its **acceptance criteria** | Runtime capability |
| Regression harness | app code; `adversarial-eval-lifecycle` governs only **admission** into it; the "passed for the right reason" judgment → `eval-triage` + `judge-calibration` | Runtime capability |
| Multi-agent core capabilities | runtime agents | Not skills |

---

## 5. Scaffolding — target repo structure

Not created yet (this session is setup + plan). `arch-draft` → `tasks-gen` → `tdd-swarm`
will build most of it. The tree below is the target; the exact stack dir (`src/` vs a
package) is gated on the build-vs-configure ADR (§8).

```
Adversarial Machine/
├── README.md                    setup · arch overview · DEPLOYED TARGET URL · run steps   [submission]
├── ARCHITECTURE.md              ~500-word summary + agents + agent-interaction diagram    [HARD GATE ← arch-finalize]
├── THREAT_MODEL.md              ~500-word summary + 6 categories + OWASP map              [HARD GATE ← threat-model]
├── USERS.md                     users · workflows · why-automation                        [submission ← arch-draft]
├── IMPLEMENTATION_PLAN.md       phases → tasks, §-anchored                                [← tasks-gen]
├── TICKETS.md · LESSONS.md      ticket board + accumulated fixes                          [← tdd-swarm, bug-hunt]
├── PLAN.md · CLAUDE.md · AGENTS.md · .gitignore                                           [done]
├── .claude/skills/              the 10 workflow skills (+ new ones as built)              [done]
├── contracts/v1/                JSON Schemas: orch→redteam, redteam→judge, judge→doc + error taxonomy  [required]
├── docs/
│   ├── planning/                PRESEARCH · RESEARCH · DECISIONS(ADRs) · ARCH_DRAFT · HANDOFF  [← arch-draft]
│   ├── adrs/                    ADRs incl. build-vs-configure (Burp/ZAP/Semgrep/Garak/frameworks)  [required @ Defense]
│   ├── diagrams/                system context · request lifecycle · trust boundaries · deploy (.excalidraw + SVG/PNG)
│   ├── defense/DEFENSE_SCRIPT.md  architecture-defense walkthrough                        [DUE @ Defense ← arch-draft]
│   ├── requirements/            REQUIREMENTS_MATRIX (every PRD item → artifact/test/checkpoint/evidence)
│   ├── vulnerabilities/         ≥3 professional vuln reports                              [submission ← vuln-report]
│   ├── triage/                  10-finding simulated scan + triage decisions              [required]
│   ├── integration/             integration packet (diffs · ADRs · contract-test results · e2e trace)  [required]
│   ├── evidence/ato/            ATO-style evidence packet                                 [required]
│   ├── incidents/               sample incident / postmortem                              [required]
│   ├── cost/COST_ANALYSIS.md    dev spend + 100/1K/10K/100K RUN projection                [submission ← cost-model]
│   ├── performance/             CPU/mem/latency/throughput baselines + 100-case load test [required]
│   ├── prompts/                 prompt log — feeds devlog + the AI-use disclosure
│   └── DEVLOG.md · PROJECT_STORY.md                                                        [← devlog]
├── evals/
│   ├── seeds/                   schema-strict seed cases (boundary/invariant/regression + OWASP)  [HARD GATE ← eval-authoring]
│   ├── regressions/             confirmed exploits → deterministic repeatable tests
│   ├── fixtures/                synthetic PHI / patient fixtures — NO real data
│   ├── ground-truth/            judge calibration set                                     [← judge-calibration]
│   ├── results/                 versioned run outputs (pass/fail/partial)
│   └── EVAL_LOG.md              running log                                              [← eval-triage]
├── src/  (stack TBD — see §8)
│   ├── agents/{orchestrator,red_team,judge,documentation}/
│   ├── domain/                  framework-neutral domain model (keep portable)
│   ├── target/                  pluggable target adapters + allowlist (no target code here)
│   ├── regression/              harness (versioned exploit store, replay)
│   ├── observability/           traces · coverage · pass/fail · cost-per-agent · resilience trend
│   ├── policy/                  allowlists · budgets · rate limits · human-gate enforcement
│   └── storage/                 exploit DB, **target-scoped** (unique IDs · required fields · indexes · migrations)
├── tests/{unit,contract,integration,security,load}/                                       [← tdd-swarm]
├── migrations/  ·  deploy/  ·  observability/                                              [required]
```

---

## 6. Requirements coverage (condensed matrix)

Every PRD requirement → where it's satisfied and by when. A machine-readable version
(`docs/requirements/REQUIREMENTS_MATRIX.csv`) is the first job of `evidence-audit`.

| Requirement | Artifact / deliverable | Produced by | Checkpoint |
|---|---|---|---|
| Live target + deployed URL | running Co-Pilot + URL in README | Stage 1 standup | every checkpoint |
| Threat model (6 categories + OWASP) | `THREAT_MODEL.md` | threat-model | MVP |
| Eval suite ≥3 categories, reproducible | `evals/seeds/`, `results/` | eval-authoring + tdd-swarm | MVP |
| ≥1 live agent prototype | Red Team or Judge vs live target | tdd-swarm | MVP |
| Architecture doc (agents, diagram, ~500w) | `ARCHITECTURE.md` | arch-draft → arch-finalize | MVP (draft @ Defense) |
| Users doc | `USERS.md` | arch-draft | MVP |
| Inter-agent contracts + tests | `contracts/v1/` + `tests/contract/` | contract-gen + tdd-swarm | MVP→Final |
| Typed success + error schemas | error taxonomy in `contracts/v1/` | contract-gen | MVP→Final |
| Build-vs-configure ADR | `docs/adrs/…` (Burp/ZAP/Semgrep/Garak/…) | arch-draft | **Defense** |
| 10-finding triage report | `docs/triage/…` | vuln-report + manual | Final |
| Integration packet + e2e trace | `docs/integration/…` | tdd-swarm + contract tests | Final |
| ATO evidence packet | `docs/evidence/ato/…` | evidence-audit | Final |
| AI-use disclosure | section in `ARCHITECTURE.md` | arch-finalize | MVP→Final |
| Exploit-DB data quality | `src/storage/` validators | vuln-report gate | MVP→Final |
| DB migrations · indexes · query SLO | `migrations/`, `src/storage/` | tdd-swarm | Final |
| Perf baselines + 100-case load test | `docs/performance/…` | tdd-swarm | Final |
| ≥3 vulnerability reports | `docs/vulnerabilities/…` | vuln-report | Final |
| Cost analysis @ 100/1K/10K/100K runs | `docs/cost/COST_ANALYSIS.md` | cost-model | Final |
| Observability layer | `src/observability/` + dashboards | tdd-swarm | MVP→Final |
| Regression harness | `src/regression/` + `evals/regressions/` | tdd-swarm | MVP→Final |
| Demo video · social post | video · X/LinkedIn @GauntletAI | manual | Final |

---

## 7. Roadmap by checkpoint

**Now — setup (this session).** ✅ skills → `.claude/skills/`; `CLAUDE.md`; slim
`AGENTS.md`; `.gitignore`; this plan. ⏳ git init + first commit.

**→ Architecture Defense (~2.5h post-kickoff).** Run `arch-draft` →
`docs/planning/*`, `USERS.md`, `docs/defense/DEFENSE_SCRIPT.md`, the **build-vs-configure
ADR**, and a first-pass `THREAT_MODEL.md` summary. Optionally `grilling` to stress-test
before you present. **Blocker:** target details (local path, deployed URL, auth, test
creds, synthetic fixtures) — get these in the `arch-draft` interview.

**→ MVP (Tue Jul 21, 11:59 PM).** `arch-finalize` → `ARCHITECTURE.md`; `tasks-gen` →
`IMPLEMENTATION_PLAN.md`; then `tdd-swarm`: Stage 1 target stood up + **deployed URL**;
Stage 2 `THREAT_MODEL.md`; Stage 3 `evals/` across **≥3 categories** + **≥1 live agent**
(Red Team or Judge) against the live target; `contracts/v1` + error taxonomy; requirements
matrix. Define **v1 contracts + error taxonomy before** writing agents.

**→ Final (Fri Jul 24, 12:00 PM).** Full four-agent platform + harness + observability;
≥3 vuln reports; cost analysis; triage report; ATO evidence packet; integration packet;
perf baselines + load test; demo video; social post. `devlog` throughout;
`eval-triage`/`bug-hunt` for regressions; `interview-prep` before the video.

**Cross-cutting:** `devlog` at every phase boundary · `authorized-live-campaign` gates
every live run · `judge-calibration` before trusting Judge verdicts · deployed URL
submitted at **every** checkpoint.

---

## 8. Open decisions for `arch-draft` (don't pre-decide — gate on the ADR)

The build-vs-configure ADR is a required Defense deliverable; keep the domain model and
JSON contracts **framework-neutral** so this choice never forces a rewrite.

- **Orchestration framework:** LangGraph / CrewAI / AutoGen / custom.
- **Models per role:** frontier vs local/OSS — the Red Team especially, since frontier
  models often refuse offensive workflows; weigh cost + a local/uncensored option.
- **Observability:** Langfuse / LangSmith / Braintrust / custom (must surface inter-agent
  traces + per-agent cost).
- **State + queue:** what stores agent state and the work-item / regression queue.
- **Exploit DB:** SQL (Postgres/SQLite, indexed by severity/category/version, migratable)
  vs document store.
- **Language:** Python (LangGraph / Garak / PyRIT ecosystem) vs TypeScript.
- **Target reach:** where the Co-Pilot is hosted and how the platform authenticates to it.

---

## 9. Immediate next actions

1. **git init + first commit** (this session) — `main`, `.gitignore`, everything staged.
   Add a secret-scanning pre-commit (e.g. gitleaks) before the first push. Push to
   **GitHub** (PRD asks for it; confirm with the instructor if GitLab is your host).
2. **Gather target details** — the #1 external blocker for Stage 1.
3. **Run `arch-draft`** in a focused session → Defense packet (script + diagrams
   + build-vs-configure ADR). This is the burning path given the ~2.5h defense window.
4. **Build Wave-1 skills** (`threat-model`, `adversarial-eval-lifecycle`,
   `judge-calibration`, `authorized-live-campaign`, `contract-steward`) via
   `skill-creator` — `contract-steward` first, since agent work depends on its schemas.

---

## 10. Skill pipeline — how they compose

The chain, and the artifact each handoff passes:

```
PRD
 └─> arch-draft ........... docs/planning/* · USERS.md · DEFENSE_SCRIPT · diagrams
      │                     + first-pass THREAT_MODEL.md   <- the "AUDIT.md slot"
      └─> arch-finalize .... ARCHITECTURE.md  (binding)
           └─> tasks-gen ... IMPLEMENTATION_PLAN.md
                └─> contract-steward ... contracts/v1/*   (schemas BEFORE agents exist)
                     └─> tdd-swarm ..... src/ + tests/
                          |              [needs: stack ADR -> GitHub -> CI + test runner]
                          |
                          ├─ threat-model ............... THREAT_MODEL.md (deepened)
                          ├─ adversarial-eval-lifecycle . evals/seeds/ -> evals/regressions/
                          ├─ judge-calibration .......... evals/ground-truth/
                          ├─ authorized-live-campaign ... gates every live run -> traces
                          ├─ eval-triage ................ diagnoses failing evals -> EVAL_LOG.md
                          └─ bug-hunt ................... regression pins -> LESSONS.md
                                │
                                └─> vuln-report ......... docs/vulnerabilities/ + docs/triage/
                                     └─> evidence-audit .. ATO + integration packets vs §6
                                          └─> interview-prep .. mock questions from all of it

devlog runs at every phase boundary: setup · Defense · MVP · Final.
grilling stress-tests any plan before it gets built.
```

### Seams found and closed

| Seam | Problem | Fix |
|---|---|---|
| `AUDIT.md` | Read by 4 skills; **nothing produces it** in Week 3 | `THREAT_MODEL.md` occupies the slot (recorded in `CLAUDE.md`); never create `AUDIT.md` |
| Threat-model ordering | `arch-draft` wants the AUDIT-slot artifact as *input*; PRD orders Stage 2 before Stage 4 | First pass comes out of `arch-draft` Phase A/B; `threat-model` deepens it for MVP |
| `tdd-swarm` preconditions | Assumes GitHub remote, protected `main`, CI checks, a test runner — none exist yet | Chain: stack ADR → GitHub → CI + runner → `tdd-swarm` |
| `tasks-gen` stall | Asks for "the deliverables checklist path" | Pre-answer: `Week_3_AgentForge.pdf` + PLAN §6–§7 |
| Missing artifacts | `EVAL_LOG.md`, `TICKETS.md`, `LESSONS.md`, `docs/prompts/` are referenced by skills but were absent from the tree | Added to §5 |
| "eval" trigger collision | `adversarial-eval-lifecycle` / `eval-triage` / `judge-calibration` overlap on the word | Boundaries recorded in `CLAUDE.md` |
| Excalidraw helpers | `arch-draft` cites two skills that aren't installed | Apply its layout rules manually; export SVG/PNG |
| `grill-me` | 147-byte alias for `/grilling` | Valid in Claude Code (manual-invoke alias); kept |
