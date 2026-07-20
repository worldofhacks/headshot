# DEFENSE_SCRIPT.md — AgentForge / Adversarial Machine

> Presenter's script for the ~2.5h Architecture Defense. Each beat: **Say** (the line), **Why it
> holds** (the substantiation), **If pushed** (the follow-up), **Concede** (the honest limit).
> Goal: defend every architectural decision — *especially where agents act autonomously* — to a
> hospital-CISO standard. Evidence pack: `ARCHITECTURE_DRAFT.md`, diagrams **D2** (agent interaction)
> + **D4** (trust boundaries), `ADR-0001` (build-vs-configure), `THREAT_MODEL.md`, contract schemas.
> Tag: `must-land` unless noted.

| # | Beat | What it lands | Time |
|---|---|---|---|
| S0 | The standard | Frames every answer against the CISO bar | 15s |
| S1 | What it is | Reusable platform, not a Co-Pilot test suite | 60s |
| S2 | Why this shape | **The spine** — separation is a security property | 3m |
| S3 | Diagram walk (D2) | Shows the loop *learns* rather than runs randomly | 3–4m |
| S4a | Build vs configure | We bought nothing; we built the four graded things | 90s |
| S4b | Per-role models | The refusal problem, solved structurally | 90s |
| S4c | Trust boundaries | Where autonomy stops | 90s |
| S4d | Contracts + regression | A test passing for the wrong reason | 90s |
| S5 | Threat model | Full surface, OWASP-mapped, honestly unproven | 60s |
| S6 | Hard questions | `reactive` — answers pre-loaded | — |
| S7 | Run of show | `pre-flight` — not spoken | — |
| S8 | Still-open | Volunteer them; honesty is the CISO move | 45s |

---

### S0 — The standard `must-land`

**Say.** "The deliverable that matters isn't the most impressive jailbreak — it's the platform a
hospital CISO would trust with continuous testing of systems their physicians depend on. Every
decision here is made to that bar."

**Why it holds.** It is the PRD's own closing standard. Stating it first means every later answer is
judged against a bar you set.

**If pushed.** "That's why the hard parts here are the Judge, regression semantics, the cost governor,
and the trust boundary — not the attacks."

---

### S1 — What it is `must-land`

**Say.** A reusable, **multi-agent adversarial evaluation platform** that *continuously* red-teams a
live clinical Co-Pilot — discovering, evaluating, validating, regression-guarding, and documenting
vulnerabilities autonomously. Target-agnostic via a pluggable adapter behind an allowlist. The OpenEMR
Co-Pilot is **target #1, not the subject**; it is attacked over its live URL, and no target code lives
in this repo.

**Why it holds.** The PRD asks for a *reusable* platform, not a one-time pen test. Target-agnosticism
is enforced structurally — adapters plus allowlist — rather than promised.

**If pushed.** "Generalize the mechanism, specialize the content. Engine, contracts, harness, and
observability are target-neutral; threat model, eval suite, and vuln reports are Co-Pilot-specific."

**Concede.** Only one target is wired today. A second adapter is what would prove the claim.

---

### S2 — Why this shape `spine`

**Say (1) — why multi-agent, not one agent or a pipeline.** Attack generation and attack *evaluation*
are a conflict of interest inside one context. Strategic prioritization is not execution. Documentation
autonomy needs a trust boundary the generator must not hold. **Separation is the security property, not
an org chart.**

**Say (2) — why an independent Judge.** "An agent that both attacks and judges is compromised by
design." The Judge shares no model, no provider, and no process with the Red Team — independence *by
construction*. Its invariant: it must **never** approve a confirmed exploit.

**Say (3) — why autonomous at all.** "Adapting as attackers adapt, without a human in the loop for
every step." Static payload lists rot. A human approving every prompt caps throughput at human speed.
The value is the runs that happen while nobody is watching — so the Orchestrator is a machine operator
reading the system's own state to decide what to test next.

**Why it holds.** Each separation maps to a named failure it prevents: self-grading, random testing,
unreviewed disclosure.

**If pushed — "isn't this just microservices with prompts?"** "The boundaries are trust boundaries, not
deployment boundaries. The Red Team runs an uncensored model over untrusted output; the Judge runs a
different vendor under refusal-integrity. Merging them doesn't cost modularity — it costs the security
property."

**Concede.** More agents means more coordination surface, and every boundary is somewhere a contract
can drift. That is exactly why contracts are versioned and both-sided contract-tested (S4d).

---

### S3 — Diagram walk (D2) `must-land`

**Say.** Trace the loop live: **Coverage + Findings view → Orchestrator → Red Team → Target Adapter →
live Co-Pilot → Judge → {mutate | confirm} → Documentation → Human approval → Vuln report**, with the
Regression Harness admitting confirmed exploits and every agent writing back to the data plane.

**Why it holds.** The colors carry the argument: **blue** trusted control plane, **green** data &
observability plane, **purple/teal** governed evaluators, **red** quarantined Red Team, **gray**
external, **yellow** human gate. The Red Team has **exactly one exit** — the Target Adapter — so
quarantine is visible rather than asserted. Edge 1, **Coverage + Findings → Orchestrator**, is *why
this learns instead of attacking randomly.*

**If pushed — "what closes the loop?"** "The Judge's verdict writes to the exploit DB; the Orchestrator
reads coverage gaps and open findings from that same store. The loop closes through data, not a
hand-off."

**Concede.** The learning signal is only as good as the coverage metric behind it — that metric is
per-target and computed against declared capabilities.

---

### S4a — Build vs configure `must-land` → ADR-0001

**Say.** "We stand on Garak, PyRIT, Giskard, Promptfoo, ZAP, and Semgrep for coverage, multi-turn
scaffolding, OWASP mapping, web DAST, and our-code SAST — all free and OSS. We *built* exactly the four
things none of them do: coverage-driven orchestration, autonomous mutation, an independent
drift-guarded Judge, and regression admission. We bought nothing — a commercial red-team platform is
out of budget, closed, un-governable under our own allowlist and cost caps, and buying one *is* the
product we were asked to build."

**Why it holds.** The ADR evaluates each tool against what it actually covers and where it falls short,
so "custom" lands as a finding rather than a default.

**If pushed — "PyRIT already does multi-turn refinement, why not just use it?"** "It does, and we wrap
it. What it doesn't do is orchestrate by coverage gap, judge independently, document reproducibly, or
maintain a regression corpus across target versions. We configured the attack primitives and built the
system around them."

**Concede.** Wrapping PyRIT/Garak/Giskard is deferred to post-MVP (D12, the only `proposed` decision).
MVP ships a hand-authored corpus plus our mutation loop, because the wrap is real engineering that
risks Tuesday.

---

### S4b — Per-role models `must-land`

**Say.** "Frontier models refuse authorized offensive generation, so the Red Team is a **local
uncensored 24–33B** on the dev Mac — no refusals, ~$0 marginal cost, outside any provider's ToS
exposure. The **Judge is Claude Sonnet 4.6** precisely because refusal-integrity *is* the 'never
approve an exploit' property, and it shares no provider with the Red Team. Documentation is **GPT-5.4**
— a *different vendor from the Judge*, so a single-vendor failure can't corrupt the whole trust chain."

**Why it holds.** Each role's model is chosen for the property that role must guarantee, and vendor
diversity across Judge and Documentation breaks correlated failure.

**If pushed — "you're running an uncensored model?"** "The model is unconstrained; the *system* around
it is not. Allowlisted target only, synthetic data only, per-target scoped credentials, budget and rate
caps, full trace capture, human approval before any finding publishes."

**Concede.** Local throughput is unmeasured. Token profiles and Mac tok/s get measured at MVP **before
any cost number is presented** — see S8.

---

### S4c — Trust boundaries + human gates (same canvas as S3) `must-land`

**Say.** "Adversarial content is quarantined and never reaches our control plane. Credentials are
**bound to their target** — cross-target use is impossible by construction. Every live campaign passes
allowlist, synthetic-data, and budget/rate gates with a hard abort. Humans approve any critical finding
and any remediation. **That is where autonomy stops.**"

**Why it holds.** Two independent controls: the allowlist decides what you *may* hit; per-target scoped
credentials decide what you *can* reach. Neither alone is sufficient.

**If pushed — "what stops this being turned on something else?"** "Live attacks are never implicitly
invoked — the campaign workflow has model-invocation disabled, so a run is always an intentional human
act, fully traced."

**Concede.** Anyone with repo access and credentials can widen the allowlist. The control is
auditability, not prevention — every run is attributable.

---

### S4d — Contracts + regression integrity `must-land`

**Say.** "Inter-agent messages are versioned, framework-neutral JSON Schemas with typed error
taxonomies and both-sided contract tests. A regression case is admitted only if it reproduces *and*
passes for the right reason — a real fix, not changed model behavior. **A test that goes green because
behavior drifted is worse than no test.**"

**Why it holds.** Breaking changes require a version bump, a migration note, and updated contract tests;
the tooling *detects* incompatibility, a human *decides* whether to accept it.

**If pushed — "how do you tell a fix from drift?"** "Planted canaries make leakage a deterministic
string match rather than a judgment call, and admission requires deterministic reproduction before
promotion."

**Concede.** Not every category has a canary-style deterministic oracle. Where judgment is unavoidable,
the Judge's ground-truth calibration set is the control (S6).

---

### S5 — Threat model `must-land`

**Say.** Six categories across the full attack surface — RAG, write-back, tools, uploads. Priority
order: **injection → PHI exfiltration → tool misuse (write-back is a real action) → state corruption →
DoS/cost → identity/role.** Each mapped to OWASP Web + LLM Top 10.

**Why it holds.** Priority follows blast radius: write-back means an attack changes clinical state
rather than merely leaking it.

**If pushed — "what defenses exist today?"** "Stated honestly as *to-be-probed*. The platform
establishes them empirically rather than assuming them."

**Concede.** Categories the target cannot currently express are marked *modeled but not exercisable*,
with the reason — the eval suite draws its ≥3 categories from the live-testable set.

---

### S6 — Hard questions `reactive`

| They ask | You answer |
|---|---|
| How do you keep the Judge honest / detect drift? | Ground-truth calibration set + cross-run agreement metrics; escalate on uncertainty; the Judge never occupies the attacker role (`judge-calibration`). |
| Where did you deliberately *not* use AI? | Deterministic validators shared by skill *and* CI: contract-compat, eval-case schema, duplicate-sequence, data-quality — plus Semgrep/ZAP/Promptfoo. AI where judgment is needed, determinism where it isn't. |
| How is this not turned against systems it shouldn't attack? | Allowlist + per-target credential binding + synthetic-data assertion + budget/rate caps + abort. Every live run is intentional and fully traced. |
| What if the Red Team produces genuinely harmful content? | Quarantined; only ever executed against the allowlisted target; never runs against our control plane; stored and traced without surfacing a raw payload to a human. |
| How is cost not tokens × N? | Two line families on different functions: hosting is a step function of peak concurrency; inference is per-run, split per agent, priced at throughput-at-load. Each tier (100→100K) names the architectural change it forces. |
| Deploy / rollback? | Railway Docker-from-GitHub; managed Postgres; cron triggers regression; **deployment history is rollback**. Perf baselines measured on Railway. |
| What backs the queue, and what happens when it backs up? | One Postgres (`SKIP LOCKED`); jobs accumulate *durably* — nothing dropped — depth is visible, and the cost governor throttles new campaigns. Graceful, observable degradation. |
| One honest weakness? | LangGraph checkpoints are crash-persistence, not exactly-once durable execution — mitigated with an app-level lock; DBOS-on-Postgres is the path if unattended multi-hour campaigns come into scope. |

---

### S7 — Run of show `pre-flight`

1. Finish **D2** + **D4** diagrams (Excalidraw + exported SVG/PNG) — **highest priority; S3 depends on them.**
2. Confirm ADR-0001 reads clean.
3. Confirm `THREAT_MODEL.md` summary + `USERS.md`.
4. Dry-run S2–S4 aloud (~8 min).
5. Stand up Langfuse Cloud Hobby so the demo shows inter-agent traces + per-agent cost.
6. Confirm the deployed target URL is in hand (Stage-1 hard gate).

---

### S8 — Still-open `volunteer these`

**Say.** "Four things aren't settled, and none of them block the architecture."

- Target's exact auth mode + API shape — pending inspection.
- Whether the target exposes a web surface for ZAP.
- Real per-agent token profiles + Mac tok/s — measured at MVP **before any cost number is presented**.
- PyRIT/Garak/Giskard wrapping deferred to post-MVP (D12 is the only `proposed` decision).

**Why it holds.** All four are tracked (`PRESEARCH.md §9`, `RESEARCH.md` open items) with owners and
trigger conditions — surfaced deliberately, not discovered live.

**If pushed.** "Naming them is the point. A platform whose operator can't say what's unproven isn't one
you'd trust with continuous testing."
