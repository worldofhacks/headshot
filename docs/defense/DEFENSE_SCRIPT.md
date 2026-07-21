# DEFENSE_SCRIPT.md — AgentForge / Adversarial Machine

> Presenter's script for the ~2.5h Architecture Defense. Each beat: **Say** (the line), **Why it
> holds** (the substantiation), **If pushed** (the follow-up), **Concede** (the honest limit).
> Goal: defend every architectural decision — *especially where agents act autonomously* — to a
> hospital-CISO standard. Evidence pack: `ARCHITECTURE.md` (binding), diagrams **D2** (agent interaction)
> + **D4** (trust boundaries), `ADR-0001` (build-vs-configure), `THREAT_MODEL.md`.
> Tag: `must-land` unless noted.
>
> **Status-label convention (F11 — never claim a system you have not built).** Every load-bearing claim
> is one of `[implemented]` (code exists + runs), `[selected]` (decided, not yet built), `[measured]`
> (a real number from a real trace), or `[planned]` (designed, scheduled). **At Architecture Defense the
> platform is not built** — there is no `src/`, `contracts/`, or `evals/` yet — so nearly everything here
> is `[selected]` or `[planned]`; the diagrams and this script are the deliverables, the running platform
> is not. Do not present a `[selected]` decision in the present tense as if it were `[implemented]`.

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
construction*. Its invariant — never approve a confirmed exploit — is **`[selected]` deterministic and
fail-closed**: a canary/oracle hit overrides the LLM Judge, and ambiguity resolves to
`INDETERMINATE`/`ERROR`, which never count as safe. Model independence is **defense-in-depth, not the
invariant** (`ARCHITECTURE.md` §5, D13) — see S4b.

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

**Say.** Trace the loop live: **Coverage + Findings view → Orchestrator → Red Team → Policy Gateway +
Execution Recorder → live Co-Pilot → (recorded) → Judge → {mutate | confirm} → Documentation → Human
approval → Vuln report**, with the Regression Harness admitting confirmed exploits and every agent
writing back to the data plane. The Judge evaluates the **recorder's hashed `AttemptResult`**, not the
raw target response — the attacker never produces the evidence it is judged on.

**Why it holds.** The colors carry the argument: **blue** trusted control plane, **green** data &
observability plane, **purple/teal** governed evaluators, **red** quarantined Red Team, **gray**
external, **yellow** human gate. The Red Team has **exactly one exit** — the **trusted Policy Gateway**
(which holds the only target credentials and enforces the allowlist) — so quarantine is visible rather
than asserted. Edge 1, **Coverage + Findings → Orchestrator**, is *why this learns instead of attacking
randomly.* *(Diagram render is being regenerated for this trust-split — spec is updated; see the diagram
spec's regen note.)*

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

**Say.** "Frontier models refuse authorized offensive generation, so the Red Team is an **uncensored
open-weights model** — `[selected]` **hosted-OSS by default** for the deployed/overnight path (so
'continuous, unattended' is real on Railway), with a **local 24–33B on the dev Mac** as a config switch
for development and the local cost-baseline. The **Judge is Claude Sonnet 4.6**, chosen on **measured
calibration, false-negative rate, consistency, latency, and cost** — *not* because of refusal behavior:
the 'never approve a confirmed exploit' invariant is enforced **deterministically** (oracle/canary
precedence, fail-closed), and refusal is a model *characteristic and failure mode*, not a security
control. Documentation is **GPT-5.4** — a *different vendor from the Judge*, so a single-vendor failure
can't corrupt the trust chain (defense-in-depth, not the invariant)."

**Why it holds.** Each role's model is chosen for the property that role must guarantee, and vendor
diversity across Judge and Documentation breaks correlated failure.

**If pushed — "you're running an uncensored model?"** "The model is unconstrained; the *system* around
it is not. Allowlisted target only, synthetic data only, per-target scoped credentials, budget and rate
caps, full trace capture, human approval before any finding publishes."

**Concede.** Local throughput is unmeasured. Token profiles and Mac tok/s get measured at MVP **before
any cost number is presented** — see S8.

---

### S4c — Trust boundaries + human gates (same canvas as S3) `must-land`

**Say.** "Attack *generation* is untrusted; attack *execution* is not. The Red Team proposes inputs but
holds no credentials and has no path to the target — its only exit is a **trusted Policy Gateway +
Execution Recorder** that enforces the allowlist, per-target scoped credentials, synthetic-data-only,
budget and rate caps, and a hard abort, and records a **hashed, append-only `AttemptResult`** the Judge
reads. Credentials are **bound to their target** — cross-target use is impossible by construction, and
the allowlist is environment-scoped. Humans approve any critical finding and any remediation. **That is
where autonomy stops.**"

**Why it holds.** Two independent controls: the allowlist decides what you *may* hit; per-target scoped
credentials decide what you *can* reach. Neither alone is sufficient — and both live in the **trusted**
gateway, not the untrusted generator, so the attacker never controls the enforcement point or the
evidence the Judge sees.

**If pushed — "what stops this being turned on something else?"** "The allowlist, scoped credentials,
authorization, budget and rate caps are enforced in the **Policy Gateway's runtime code** — independent
of *how* a run was triggered (Claude, a direct Python call, or Railway cron). Disabling model-invocation
on the campaign skill is a convenience that stops *Claude* auto-invoking it; it is **not** the control,
because it does nothing against a direct run or a cron fire. Every run is fully traced and attributable."

**Concede.** Anyone with repo access and credentials can widen the allowlist — the control is
auditability plus a **two-person rule** on critical publish and remediation (`approver_id != launcher_id`),
not prevention. For the Week-3 timeline a single operator may wear both hats; where that happens we state
it explicitly rather than let "distinct role" quietly permit self-approval.

---

### S4d — Contracts + regression integrity `must-land`

**Say.** "Inter-agent messages are versioned, framework-neutral JSON Schemas with typed error
taxonomies and both-sided contract tests. A regression case is admitted only if it reproduces *and*
passes for the right reason — a real fix, not changed model behavior. **A test that goes green because
behavior drifted is worse than no test.**"

**Why it holds.** Breaking changes require a version bump, a migration note, and updated contract tests;
the tooling *detects* incompatibility, a human *decides* whether to accept it.

**If pushed — "how do you tell a fix from drift?"** "Where we can plant canary tokens in the target's
synthetic fixtures, leakage is a deterministic string match rather than a judgment call, and admission
requires deterministic reproduction before promotion. A confirmed exploit is marked *fixed* only by a
deterministic regression oracle — never by an LLM-only verdict."

**Concede.** The canary oracle needs write access to the *target's* data, and the target is external — so
for a target we cannot pre-seed (likely for the flagship PHI-exfiltration category), detection is
Judge-judgment **plus human escalation**, not deterministic. We state that honestly rather than imply an
oracle the ownership boundary denies; the ground-truth calibration set is the control there (S6).

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
| How do you keep the Judge honest / detect drift? | The invariant is **code, not model behavior**: a deterministic oracle/canary hit overrides the LLM Judge, ambiguity fails closed (`INDETERMINATE`/`ERROR`, never "safe"). Drift is caught by async dual-judging over the ground-truth set + a stratified live sample; crossing a drift threshold disables LLM-only dispositions for that category (`judge-calibration`). |
| What stops the transcript from injecting your *own* Judge or Documentation agent? | A target response echoed back is a live injection aimed at the next LLM — so the Judge/Documentation treat transcript content as **untrusted data, not instructions**: rubric-as-system + fenced transcript, structured extraction, and Documentation renders from structured fields + escaped evidence. Platform-injection cases are in the Judge calibration set. |
| Where did you deliberately *not* use AI? | The Policy Gateway (deterministic policy), evidence hashing + DB-role enforcement, the oracles/canaries, and validators shared by skill *and* CI: contract-compat, eval-case schema, duplicate-sequence, data-quality — plus Semgrep/ZAP. AI where judgment is needed, determinism where it isn't. |
| How is this not turned against systems it shouldn't attack? | Allowlist + per-target credential binding + synthetic-data assertion + budget/rate caps + abort — all enforced in the **Policy Gateway's runtime code, independent of trigger** (not a skill flag). Every live run is fully traced. |
| What if the Red Team produces genuinely harmful content? | Quarantined; holds no credentials; only ever executed via the trusted gateway against the allowlisted target; never runs against our control plane; treated as untrusted data even by the Judge/Documentation. |
| How is cost not tokens × N? | Two line families on different functions: **hosting** is a step function of peak concurrency; **inference** is modeled *separately* — hosted = measured tokens × current rates (prompt-cache + Batch adjusted), local = amortized capacity — never a `list_price ÷ throughput` figure (that is dimensionally invalid). Each tier (100→100K) names the architectural change it forces. **Numbers are deferred to measurement.** |
| Deploy / rollback? | Railway Docker-from-GitHub; **≥2 environments** (prod alone holds live-target creds); managed Postgres; cron enqueues regression. Rollback: deployment history reverts *code*; **expand/contract migrations + Postgres PITR** roll back *data*; drain-before-deploy avoids mid-lease landings. Perf baselines measured on Railway. |
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
