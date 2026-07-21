# REVIEW_FINDINGS.md — external review of the arch-draft output

> Findings from an independent review of the committed planning artifacts (July 2026), plus
> two claims verified against primary sources. Each entry: **Finding** (what is wrong),
> **Impact** (why it matters), **Correction** (what to do), **Touches** (which artifacts).
> These are **mandatory audit input for `/arch-finalize`** — resolve each one explicitly and
> record the resolution in `ARCHITECTURE.md` or `DECISIONS.md`. Tag: `must-fix` unless noted.

| # | Finding | Tag |
|---|---|---|
| F1 | Judge invariant rests on model refusal-integrity, which cannot enforce it | must-fix |
| F2 | Target Adapter is untrusted yet is the enforcement boundary; Red Team controls the Judge's evidence | must-fix |
| F3 | Self-hosted Langfuse contradicts D6's "one Postgres, no Redis" | must-fix |
| F4 | Cost formula is dimensionally invalid | must-fix |
| F5 | Live-campaign gate enforced by a skill flag, not by runtime | must-fix |
| F6 | Postgres queue lacks delivery semantics | should-fix |
| F7 | Overnight autonomy depends on a developer Mac | must-fix |
| F8 | OWASP taxonomy is unversioned | should-fix |
| F9 | Stale content in PLAN.md | housekeeping |
| F10 | `tdd-swarm` performs git writes but is auto-invocable | must-fix (safety) |
| F11 | Defense script presents planned behaviour as implemented | must-fix (presentation) |
| F12 | ADR-0001's Promptfoo OWASP-Web claim may be overstated | verify |

---

### F1 — The Judge invariant cannot come from refusal-integrity `must-fix`

**Finding.** D8 and `DEFENSE_SCRIPT` S4b state that Claude Sonnet's refusal-integrity *is* the
"never approve a confirmed exploit" property.

**Impact.** Category error. Refusal training governs whether a model will **generate** harmful
content; the invariant concerns whether it correctly **classifies** a successful exploit. They are
orthogonal — and a Judge that refuses to engage with adversarial content is *worse* at judging it.
Rubric drift, false negatives, and prompt injection against the Judge are separate failure modes
that refusal behaviour does not address. This claim does not survive one follow-up question.

**Correction.** Make the invariant **deterministic and fail-closed**: canary/oracle hits override
the Judge's verdict; category-specific deterministic oracles wherever one exists; a calibrated
ground-truth set with confidence thresholds; human escalation on ambiguity; immutable stored
transcripts. Cross-provider separation is retained as **defense-in-depth, not the invariant**.

**Touches.** `DECISIONS.md` D8 · `ARCHITECTURE_DRAFT` (Judge, evaluation pipeline) ·
`DEFENSE_SCRIPT` S2/S4b/S6 · `judge-calibration` skill scope.

---

### F2 — Target Adapter is in the wrong trust zone; the Judge's evidence is attacker-controlled `must-fix`

**Finding.** The diagram spec colours `TARGET ADAPTER` red/quarantined while assigning it
allowlisting, synthetic-data enforcement, credential binding, budgets, and hard abort. Separately,
the contract says `RedTeam → Judge: AttemptResult` while the diagram shows `Target → Judge`.

**Impact.** An untrusted component cannot be the enforcement boundary — the trust diagram
contradicts itself at exactly the point it exists to prove. And if the Red Team produces the
`AttemptResult`, the attacker controls the evidence the Judge evaluates, which voids the
independence claim that the whole architecture rests on.

**Correction.** Split into three: (a) **untrusted** attack generator and content; (b) **trusted
policy gateway + execution recorder** — enforces allowlist, scoped credentials, budget, rate caps,
abort, and emits a hashed/signed `AttemptResult`; (c) **external** target. The Judge evaluates the
recorder's transcript only. Resolve the contract-direction inconsistency in favour of the recorder.

**Touches.** `docs/diagrams/D2-D4-...spec.md` (zones + edges) · contracts v1 · `ARCHITECTURE_DRAFT`
§ trust boundaries · `DEFENSE_SCRIPT` S2/S3/S4c.

---

### F3 — Self-hosted Langfuse contradicts the simplified-infrastructure story `must-fix`

**Finding.** D5 locks self-hosted Langfuse while D6 sells "one Postgres, `SKIP LOCKED`, no Redis"
as the simplicity win.

**Impact.** Verified against Langfuse's own docs: self-hosting requires **Web + Worker containers,
PostgreSQL, ClickHouse, Redis/Valkey, and S3/blob storage**, with ~4 vCPU / 8 GB minimum. That is
roughly five additional Railway services, and it reintroduces the exact Redis dependency D6 claims
to have avoided — plus unmodelled cost, backup, and failure surface.

**Correction.** Invert D5's own fallback: **Langfuse Cloud for MVP** (synthetic data only), with
self-hosting as a documented post-MVP path. Alternative if cloud is unacceptable: OTEL + Postgres
metrics only. Whichever is chosen, its full footprint must appear in deployment, cost, and failure
analysis. Sources: langfuse.com/self-hosting, /self-hosting/deployment/infrastructure/containers.

**Touches.** `DECISIONS.md` D5/D6 · `ARCHITECTURE_DRAFT` § observability + deployment · cost model.

---

### F4 — The cost formula is dimensionally invalid `must-fix`

**Finding.** `effective_cost_per_run = list_price / realized_throughput_at_load`.

**Impact.** Price is $/token; throughput is tokens/second. Dividing them yields $·s/token², which
is meaningless. Hosted inference is billed per token **regardless of throughput** — throughput sets
latency and capacity, not price. Conflating the two produces a cost number that cannot be defended.

**Correction.** Model separately: **hosted inference** = measured tokens × current rates, adjusted
for cached-input and batch pricing; **local inference** = hardware amortization + power + operator
time ÷ measured capacity; **platform hosting, storage, observability, egress** as their own lines.
Name the architectural change forced at each of 100 / 1K / 10K / 100K runs. Note that "not tokens ×
N" means token spend is **insufficient**, not absent — token accounting stays.

**Touches.** `ARCHITECTURE_DRAFT` § cost · `DEFENSE_SCRIPT` S6 cost row · future `COST_ANALYSIS.md`.

---

### F5 — The live-campaign gate is enforced by a skill flag, not by the runtime `must-fix`

**Finding.** `DEFENSE_SCRIPT` S4c claims disabling model invocation makes every live attack
intentional. `interrupt()` is described as the human-approval gate.

**Impact.** `disable-model-invocation` only prevents *Claude* from auto-invoking a skill. It has no
effect if someone runs the Python directly, or when Railway cron fires. And LangGraph `interrupt()`
provides pause/resume mechanics, not authorization — nodes **replay on resume**, so any
pre-interrupt side effect must be idempotent or a gated publish can double-fire.

**Correction.** Enforce allowlist, scoped credentials, authorization, budgets, rate caps, and
egress restriction **in runtime code**, independent of how execution was triggered. Keep the skill
flag as a convenience, not a control. Make gated side effects idempotent.

**Touches.** `ARCHITECTURE_DRAFT` § policy/trust · `DEFENSE_SCRIPT` S4c · `authorized-live-campaign`
skill scope · `src/policy/`.

---

### F6 — Postgres queue lacks delivery semantics `should-fix`

**Finding.** D6 specifies `SELECT … FOR UPDATE SKIP LOCKED` plus attempts and `run_after`.

**Impact.** That is a claim primitive, not a queue. Under production-grade posture the omissions
are load-bearing.

**Correction.** Specify at-least-once delivery, lease expiry, worker heartbeat, a reaper for
expired leases, dead-letter state, idempotency keys, deduplication, cancellation, and poison-job
handling. No long-running work inside the claim transaction. Document queue-depth monitoring and
back-pressure behaviour.

**Touches.** `DECISIONS.md` D6 · `ARCHITECTURE_DRAFT` § state/queue.

---

### F7 — Overnight autonomy depends on a developer Mac `must-fix`

**Finding.** The platform deploys to Railway while Red Team inference runs on a local Mac.

**Impact.** "Continuous" and "unattended overnight runs" are the spine of the pitch. A laptop that
sleeps and is not reachable from Railway cannot support either claim.

**Correction.** Either route the deployed path to **hosted OSS inference** and reserve local for
development and cost experiments, or document the connectivity design (secure tunnel, availability
window, failover) and state the resulting availability limits honestly.

**Touches.** `DECISIONS.md` D3/D8 · `ARCHITECTURE_DRAFT` § deployment · cost model · `DEFENSE_SCRIPT` S8.

---

### F8 — OWASP taxonomy is unversioned `should-fix`

**Finding.** `THREAT_MODEL.md` uses IDs such as `A03 Injection` and `A01 Broken Access Control`
without naming the taxonomy version.

**Impact.** **OWASP Top 10:2025 has shipped** — SSRF is folded into A01 and Injection moved A03→A05
(verified at owasp.org/Top10/2025). Unversioned IDs are ambiguous and read as wrong to anyone on the
2025 list.

**Correction.** Note that **the PRD itself enumerates the 2021 set** (it lists SSRF as a standalone
category), so map to **2021 explicitly** rather than silently migrating. State the version, add a
2021↔2025 crosswalk (SSRF→A01, Injection A03→A05, plus new A03 Software Supply Chain Failures and
A10 Mishandling of Exceptional Conditions), and store structured tags `{framework, version, id,
name}` so either list can be reported. LLM mappings already align to OWASP LLM Top 10 2025.

**Touches.** `THREAT_MODEL.md` · eval-case schema · `adversarial-eval-lifecycle` reference data.

---

### F9 — Stale content in PLAN.md `housekeeping`

**Finding.** PLAN.md says "git pending" and lists `git init` as a next action in three places
despite three commits on `main`; the requirements matrix still names `eval-authoring` and
`contract-gen` instead of `adversarial-eval-lifecycle` and `contract-steward`.

**Correction.** Update status line, §7 "Now" bullet, §9 action 1, and the two matrix rows.

**Touches.** `PLAN.md` lines ~5, ~278, ~323, ~224, ~253, ~257, ~258.

---

### F10 — `tdd-swarm` performs git writes but is auto-invocable `must-fix`

**Finding.** `.claude/skills/tdd-swarm/SKILL.md` has no `disable-model-invocation`, yet the skill
creates branches, commits, opens PRs, merges integration branches, and contains deletion language.

**Correction.** Set `disable-model-invocation: true`. Consider the same audit for any other skill
with destructive authority, and scope broad `allowed-tools: Bash` entries where practical — note
that in Claude Code `allowed-tools` **grants** permission, it does not restrict.

**Touches.** `.claude/skills/tdd-swarm/SKILL.md` · optionally `.claude/settings.json` hook policy.

---

### F11 — The defense script presents planned behaviour as implemented `must-fix`

**Finding.** The script reads in present tense throughout, but there is no `src/`, no `contracts/`,
no `evals/`, and no running platform. Its evidence pack also lists "contract schemas," which do not
exist.

**Impact.** The most damaging failure available at the Defense. An architecture flaw is arguable;
appearing to claim a system you have not built is not.

**Correction.** Label every claim **implemented / selected / measured / planned**. Remove "contract
schemas" from the evidence pack until they exist. S8 already volunteers open items — extend that
honesty to the implementation status of the platform itself.

**Touches.** `DEFENSE_SCRIPT.md` — evidence-pack line and every beat's Say/Why.

---

### F12 — ADR-0001's Promptfoo OWASP-Web claim may be overstated `verify`

**Finding.** ADR-0001 credits Promptfoo with OWASP Web + LLM mapping "with no custom code."
Promptfoo exposes `owasp:llm` and `owasp:api` framework IDs; a standard `owasp:web` framework ID
may not exist.

**Correction.** Verify against current Promptfoo docs. If unsupported, soften the ADR claim and
assign Web-category mapping to our own deterministic validator.

**Touches.** `docs/adrs/0001-build-vs-configure.md`.
