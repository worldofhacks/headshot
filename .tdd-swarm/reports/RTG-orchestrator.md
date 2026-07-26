# RTG orchestrator report — red-team gap-closure swarm

**Role:** root orchestrator (PROMPT-ORCHESTRATOR.md + README.md controlling).
**Worktree:** `<repo>` (verified via `pwd`).
**Status:** `BLOCKED(base-precondition)` — held at Wave 0 entry. Live **target** authorization
now received & tracked (see §8); live **platform-deployment** surface still incomplete.
**Last updated:** session start + owner target-authorization received.

---

## 1. Orientation completed

Read in full: `AGENTS.md`, `CLAUDE.md`, `PLAN.md` (via CLAUDE.md summary), the coverage
review `docs/security/RED_TEAMING_COVERAGE_REVIEW_2026-07-24.md`, the swarm `README.md`,
`PROMPT-ORCHESTRATOR.md`, and the full WP index (WP-01 … WP-22 incl. lettered subpackages)
plus role overlays. Requirements source of truth `Week_3_AgentForge.pdf` acknowledged as
canonical.

Swarm shape understood: 18 waves (Wave 0 → Wave 18), Test → independent Test Review/freeze →
Implementer → independent Code + Security Review per code package, ≤3 concurrent workers,
serialized migrations (WP-02 → WP-10 → WP-04 → WP-11 → WP-16A → WP-18A → WP-15 → WP-19),
contract stewardship (WP-19B), then the live phase WP-21A (zero-call preflight) → WP-21B–E
(live, authorization-gated) → WP-21 reconciliation → WP-22 independent audit.

## 2. Repository state inventory (preserve, do not touch)

| Fact | Value |
|---|---|
| Branch | `swarm/final-submission-gap-closure` |
| HEAD | `66e670fee8c6c66a5236c7d932a0c4a2e9f74b87` (`plan: authorize reviewed OpenRouter execution swarm`) |
| local/origin/gitlab `main` | `23490ea9846bffcf36168b58f2c36edeceabb8df` (all three identical — dual-remote main in sync) |
| Commits ahead of main | 2, both planning-only (`define final submission TDD swarm`, `authorize OpenRouter execution swarm`) |
| Modified tracked files | 92 (unstaged) |
| Untracked files | 123 |
| Dirty in `.tdd-swarm/prompts/` (PROTECTED, count-sensitive) | 52 |
| Dirty under `src/` | 24 |
| Dirty under `console/` | 8 |
| Dirty under `docs/` | 3 |
| Dirty elsewhere (reports, manifest, TICKETS.md, …) | 44 |

The active final-submission swarm (`T-F00 … T-F15`, many lettered subpackages) is
**mid-execution**: `.tdd-swarm/final-submission-manifest.md` is itself dirty and being edited
("session-lease scope repair"); its evidence boundary is anchored on base `23490ea`; it owns
its own live-authorization packages (T-F04b/T-F05b/T-F06b/T-F07b). It is **neither complete
nor deliberately paused.**

## 3. Base-SHA precondition — NOT satisfiable without a human decision

README Precondition #2 (verbatim intent): choose/record a **clean** `<RED_TEAM_GAP_BASE_SHA>`
**after** the active final-submission work "has been integrated or explicitly set aside."
README ¶7–9: this bundle is deliberately outside `.tdd-swarm/prompts/`; do not copy prompts
into that namespace "until the active swarm is complete or deliberately paused."

Neither condition holds. Every path to a clean base requires an action I am explicitly
forbidden to take unilaterally:

1. **Commit / integrate the active work** → that is "integrating" it on the user's behalf and
   risks corrupting the count-sensitive 82-prompt contract in `.tdd-swarm/prompts/`. Forbidden
   ("preserve all user changes; never edit the count-sensitive namespace").
2. **Stash / set aside the active work** → that is "explicitly setting it aside" — the user's
   decision, not mine; also risks the 123 untracked files and the count-sensitive namespace.
3. **Run the swarm on the dirty tree (base = HEAD 66e670f, dirty)** → breaks the swarm's core
   discipline: per-package disjoint file ownership, frozen test-file hashes, immutable
   `<REVIEW_SHA>`, reviews scoped to `<DIFF_BASE>..<REVIEW_SHA>`, and `git diff --check` are
   all contaminated when ~215 uncommitted changes ride every branch checkout. A "clean base"
   in the README's sense does not exist while the tree is dirty.
4. **Run in a separate `git worktree` at 66e670f (excludes the uncommitted work)** → builds the
   gap-swarm on a base that omits the in-flight final-submission changes to the *same* files
   (`policy/gateway.py`, `runner.py`, `coordinator.py`, `target/openemr_adapter.py`,
   `campaign/*`, `api/*`, console). Guarantees a massive future merge conflict — exactly what
   Precondition #2 exists to prevent. Contradicts the explicit *sequencing* requirement.

**Conclusion:** no safe default exists. Resolving the active swarm (integrate **or** pause) is
a decision only the user can make. Candidate base once resolved is recorded below.

- **Candidate `<RED_TEAM_GAP_BASE_SHA>` (pending user decision):** to be the sole current head
  after the active swarm is integrated or paused. If paused-in-place with a clean tree at
  today's HEAD, that is `66e670f`; if the final-submission work is merged to `main` first, the
  base becomes that new integrated head. **Not yet recorded as final — awaiting decision.**

## 4. Second, predetermined blocker — live validation is unauthorized

The kickoff states verbatim: **"This kickoff message is not campaign autho."** The Live-only
evidence law (README §"Live-only evidence law") and WP-21 require named, hash-bound
authorization artifacts that must **never** be synthesized:

- exact deployed Railway release SHA + dual-remote/CI-green attestations;
- owner-authorized deployed OpenEMR **live test-environment URL** with seeded synthetic
  **non-PHI** live records and provisioned test principals;
- Headshot/Clerk controls, separate campaign authorizations, genuine pinned tools/providers,
  budgets, rate caps, aborts, and observation points.

None are present in this kickoff. Therefore, independent of the base-SHA blocker:

- WP-21B–E are **predetermined `BLOCKED`** (missing live authorization ≠ permission to
  substitute a mock/fixture/cassette/fake-target — that stays non-evidentiary).
- WP-22 **cannot** certify the platform as "fully live-validated"; every behavioral criterion
  requiring live proof (RT-01/02/03/04/05/06/07/08 live legs, and the RT-09–14 live legs)
  remains open/blocked.

Even a fully successful WP-01 → WP-20 build yields only `LIVE_EVIDENCE_REQUIRED` implementation
prechecks — never operational/demonstrated/regression-protected/closed status.

## 5. Decision required from the user (single unblock)

To let Wave 0 begin safely, choose how the active final-submission swarm is resolved so a clean
base exists (README Precondition #2):

- **(A) Pause the active swarm in place** — you commit or stash the ~215 uncommitted changes
  yourself (so the count-sensitive namespace stays under your control), tell me the resulting
  clean head SHA, and I take that as `<RED_TEAM_GAP_BASE_SHA>`.
- **(B) Integrate the active swarm first** — land the final-submission work onto `main`
  (dual-remote, CI green), then I base the gap-swarm on that new integrated head.
- **(C) Explicitly authorize a separate isolated worktree at a base you name**, accepting the
  future-merge-conflict risk in §3 item 4, and explicitly waiving Precondition #2's sequencing
  for that isolated run.

Separately, live validation (WP-21B–E, and any WP-22 "closed" claim) needs the §4 authorization
artifacts. Absent those, the swarm can at most reach WP-20 + WP-21A (zero-call preflight), and
the honest end-state is **not fully live-validated**.

## 6. Predetermined answers to the final required report (as of now)

1. **Integrated commits / completed waves:** none. Held at Wave 0 entry pending §5 decision.
2. **Test/review status:** no packages dispatched; no tests authored/frozen; no reviews run.
3. **Live evidence / independent review status:** none produced; WP-21 phase not reachable
   without §4 authorization.
4. **RT-01…RT-14:** 0 closed. All 14 are `BLOCKED` on the base-SHA decision (§3) and, for their
   live legs, on live authorization (§4). None can be closed by local/deterministic evidence.
5. **Exact remaining blockers:** (a) base-SHA precondition — active swarm not integrated/paused
   (§3); (b) live-campaign authorization + deployed-target/Railway/Clerk artifacts absent (§4).
6. **Fully live-validated?** **No** — and cannot be, in this session, without the §4 live
   authorizations. Local tests never establish coverage or closure (README closure standard).

## 7. Orchestrator actions taken (safe, non-destructive)

- Verified worktree via `pwd`; inventoried and preserved all dirty files (no writes to tracked
  files, no writes anywhere under `.tdd-swarm/prompts/`, no branch/reset/checkout/stash/push).
- Created this report only (new file under `.tdd-swarm/reports/`, the location the kickoff
  designates).
- **No** provider/target/ZAP/OAST/browser/deployment/publication/remediation/spend/push/merge
  action was taken (compliant with WP-01…WP-20 external-action freeze and the unauthorized live
  phase).

---

## 8. Session update — owner target authorization received (tracked, SID-free)

The owner supplied a **live target authorization** in answer to §5. It is recorded SID-free at
`.tdd-swarm/reports/RTG-target-authorization.md` and summarized here.

- **Target:** `https://agent-production-9f62.up.railway.app`; surfaces Week1 `/app`, Week2
  `/week2`, plus `POST /chat {session_id,message}`. Synthetic-only, bounded, ≤3 workers, no
  DoS/infra-change/rotation/deletion. Two per-week **SIDs = bearer credentials**, stored ONLY in
  the out-of-repo bundle; never committed here.
- Target is **already partially wired** in-repo (`README.md`, `docs/evidence/zap/*`,
  `evals/results/live-campaign-20260724/*`, three `AF-VULN-2026-0724-*` reports,
  `scripts/live_probe.py`, `console/vite.config.ts`); a prior live run (`aceddc4…`) already hit
  it (9×200 / 9 INDETERMINATE / $0.09).

**What this changes:** the *owner-authorized deployed live target URL + surfaces + provisioned
synthetic principals* requirement is now satisfied — a real advance for RT-07 (Week2 exposes the
missing ingestion/upload/extraction/RAG surfaces) and for the live legs generally.

**What it does NOT change — the swarm is still blocked from starting:**

1. **[Still blocks Wave 0]** Base-SHA precondition (§3). The owner's answer did not integrate or
   pause the active final-submission swarm; the tree still carries ~215 uncommitted changes incl.
   52 files in the protected `.tdd-swarm/prompts/` namespace. I cannot safely begin the TDD code
   waves. **This is the single gating item.**
2. **[Blocks live phase]** The rest of the WP-21A surface is absent: exact deployed **AgentForge
   platform** Railway SHA, dual-remote/CI-green for it, Headshot/Clerk controls, a **separate**
   two-person approver identity (launcher ≠ approver), platform budgets/rate caps/abort wiring,
   observation points. Target-auth ≠ platform-auth.
3. **[Blocks live phase]** The capabilities a live campaign would exercise (mutation loop,
   semantic/oracle Judge, OAST, browser, active ZAP, expanded corpus, wired regression) mostly do
   not exist yet — they are what WP-01→20 build. Live execution "through production code paths"
   is impossible for code not yet written.
4. **[Architecture caveat]** The bundle is a **Bruno CLI** harness = an *independent* target
   exerciser, not the AgentForge production path. It can corroborate + seed regression, but does
   not by itself satisfy WP-21 "operational/demonstrated" (which requires the deployed platform's
   own gateway/adapter/Recorder/Judge).

**Remaining single decision to start the build waves:** resolve the active swarm so a clean base
exists — options A (you pause & give me the clean head SHA), B (integrate final-submission to
main first), or C (explicitly authorize an isolated worktree at a named base, waiving
Precondition #2's sequencing and accepting future-merge-conflict risk). Until then, held at Wave
0. The tracked target authorization will be consumed by WP-21A once the build reaches the live
phase and the §2 platform-deployment surface is present.

---

## 9. Session update — base largely cleared; one temporary blocker (active live run)

Re-inventoried live state. **Major progress:**

- HEAD advanced `66e670f → 54b3a4d3` (branch `swarm/final-submission-gap-closure`, now **5 ahead
  of `main`**). New commits: `efd5ce3` register authorized targets · `23fbdfe` authorized
  synthetic live campaign (target config/scan/draft reports) · `54b3a4d3` final live findings +
  target config + 4 vuln reports.
- **Protected `.tdd-swarm/prompts/` namespace is now 0 dirty** (committed). Dirty count fell
  ~215 → **9**.
- **Secret hygiene verified solid:** `54b3a4d3` gitignores `**/Runtime.bru`,
  `**/adversarial-smart-bruno-*/`, `**/claude-adversarial-run/`, `tmp/`; SIDs stay in gitignored
  `.env.campaign`/`.env.local`. Working-tree SID sweep = clean (no SID string anywhere in-repo).

**One remaining, temporary blocker — an active live campaign is mutating the tree:**

- Process **PID 61972** `python scripts/platform_live_run.py`, `LC_CAMPAIGN_RUN_ID=
  platform-live-20260724b-week1` (paced), is **running now**. The 9 dirty entries are its output
  (old `…20260724-week1` manifests deleted, new `…20260724b-week1/` attempts DX-001/DX-002 being
  written, `approval.json` + `scripts/platform_live_run.py` modified).
- Therefore **no clean base exists yet** and starting the gap-swarm now is unsafe: worker
  branches, `scripts/check.sh`, `git diff --check`, and frozen-hash freezes cannot run against a
  tree a live process is actively rewriting, and the swarm must not interfere with a live run.

**Base-SHA decision (resolved in principle):** the owner effectively chose path A/B-hybrid by
committing the active work to the branch. Intended `<RED_TEAM_GAP_BASE_SHA> = 54b3a4d3` (or its
clean successor once the in-flight live-run output is committed/stashed). **Awaiting a clean
tree** (live run finishes or is paused → its 9 entries committed/stashed).

**Live-phase closure caveats (unchanged; block WP-21 closure, NOT the WP-01→20 build):** platform
Railway SHA + dual-remote/CI-green for it + Clerk/Headshot + separate two-person approver +
platform budgets/rate/abort + observation points still required; and the capabilities WP-01→20
build do not exist yet, so live "through production code paths" comes only after the build.

**Ready-to-start trigger:** clean working tree at `54b3a4d3` (or successor) → I lock the base,
reserve no migration until WP-02's wave, and dispatch Wave 0 (WP-01 physical dispatch gate;
WP-07 public shell; WP-08 ownership authorization) under the Test → Test-Review/freeze →
Implement → Code+Security review sequence, ≤3 workers.

---

## 10. Gap analysis outcome — DE-SCOPED execution plan (do the biggest/best only) — **[LOCKED]**

> **[LOCKED DECISION — owner-approved.]** Execution scope is the **oracles-first** plan:
> **WP-11 oracles/instrumentation → WP-13/13E broker+adapters → WP-14 full-spectrum corpus →
> WP-12/16B/17 surfaces+fuzzer → WP-03/16D egress → WP-15 mutation** (then WP-05 reaper, reopen
> WP-19). WPs marked DEFER/SKIP below are out of scope unless re-opened by the owner.
>
> **Invariants that hold through every lever (non-negotiable):** the tool broker's generation
> authority is **`target_scope:none`**; the mutation loop **binds a NEW corpus hash + a NEW
> exact-scope authorization** (never mutates inside an already-authorized campaign); **every
> generated turn is dispatched only through the existing PolicyGateway** (→ WP-01/WP-03), and the
> two-person control (launcher ≠ approver) is preserved.
>
> **W0 START GATE (both required):** (1) **clean working tree**, and (2) **dual-remote CI green** —
> the latter currently **gated on Codex's ruff-format fix** landing. Hold at W0 entry until both.
>
> **Live-web scanning caveat (unchanged):** W4's active/live web dispatch (ZAP/fuzzer against the
> target) still needs a **separate persisted exact ZAP/target authorization**; campaign approval
> and the existing `/chat` target authorization do NOT cover it. Build W4 code under the gate;
> execute its live legs only under that separate authorization.

Ran a 7-agent grounded gap analysis (workflow `wf_3207c24e-216`) against current code, through two
lenses: expand security-SCAN capability + use ALL tools fully on every user-engaged run.

**Core finding:** a user-engaged run today **VALIDATES a fixed ~14-case corpus; it does not
red-team generatively and invokes ZERO security tools live.** Garak/PyRIT/Giskard/Promptfoo
contribute only 5 pre-baked single-turn prompt-injection candidates frozen offline by sha256;
ZAP/fuzzer/OAST/browser never run; only 1 oracle fires (substring canary) so 7/9 seeds →
permanent `INDETERMINATE`. The web findings (AF-VULN-004/005/006) came from an **external Bruno
client, not the platform scanner.**

**Hard ordering rule:** decisiveness gates breadth. More tools/corpus before oracles = more
INDETERMINATE, not more findings. **WP-11 oracles/instrumentation MUST precede all breadth work.**

**Ranked focus (execute these):**
1. WP-11 — deterministic recorder/tool-call + state-diff oracles & trusted observation. *Value
   gate for everything.* (L)
2. WP-13 + WP-13E — tool broker + wire the 4 adapters into the run behind `target_scope:none`,
   dispatch via existing PolicyGateway. *Seed-replay → generative scan; per-run tool use 0→N.* (L)
3. WP-14 — full-spectrum corpus (all 6 PRD categories + OWASP Agentic ASI) as default workload. (L)
4. WP-13A/13B/13C — Garak multi-family · PyRIT multi-turn (Crescendo/TAP) · Giskard RAG/agent. (M/L)
5. WP-12(config-unpin, S) + WP-16B fuzzer + WP-17 BOLA/BFLA matrix over the **already-built** Week2
   upload/read/RAG surfaces (currently `enabled:false`). *Highest find-power vs the real target.*
6. WP-03 + WP-16D — pin validated destination (DNS-rebind TOCTOU) + governed process-egress.
   *Prerequisite that gates all live active-process/web scanning.*
7. WP-15 — authorized feedback mutation loop (new hash + 2nd authorization). *After 1,2,4.*
8. WP-05 — expired-lease reaper loop (crash self-heal for long autonomous scans). (M)

**Deliberately DEFER/SKIP (not the biggest levers now):**
- **Already done:** WP-01 (RT-09 abort/lease/scope re-check); the live-coordinator run + AF-VULN-004/5/6.
- **Hardening, not capability:** WP-02 DB roles, WP-04 idempotency (fold into 13B), WP-06/07/08
  readiness/public-shell/ownership-auth. WP-09 = 1-line ZAP evidence-drift truthfulness fix (do
  inline, not as a lever).
- **Low-ROI this window:** WP-13D Promptfoo (overlaps Garak), WP-16A/16C workbench/checks,
  WP-18A OAST, WP-18B WebSocket/DOM, WP-19A report export. WP-19 regression loop → re-open only
  AFTER rank-1 oracles make replays decisive.

**Sequence (honoring ≤3 workers + serialized contract/migration):** W0 parallel {WP-09 fix ·
WP-12 config-unpin · WP-03 pin} → W1 lead {WP-11 via contract-steward} → W2 {WP-13/13E broker ‖
WP-14 corpus; serialize the two schema migrations} → W3 {13A‖13B(+WP-04)‖13C behind broker} →
W4 {WP-16D egress first, then WP-16B‖WP-17‖passive-ZAP live} → W5 {WP-15 → WP-05 → reopen WP-19}.

**Caveats:** live-web scan needs a separate persisted ZAP/target authorization (campaign approval
is insufficient); the "Week2 surfaces already addressed" analyst flag was WRONG — surfaces built
but still `enabled:false`, so config-unpin is genuinely not-done; two-person + gateway-owned
dispatch invariants must hold through every lever; WP-13/WP-15 each add a new inter-agent contract
(serialization tax not in the L estimate).

**Base/live status:** live run finished (0 processes); HEAD `1ac3ee0`, 6 ahead of main, tree DIRTY
(25 entries = completed run output). Ready to lock base + start W0 the moment the tree is clean.

---

## 11. W0 hold — start-gate state (as of this check) + aligned first wave

**Plan LOCKED** (see §10). Held at W0 entry; **not dispatched** — gate unmet.

**Start-gate reading:**
- Tree: **DIRTY (22 entries).** The 3 ruff-flagged files (`api/postgres.py`, `api/read_models.py`,
  `tests/test_birdseye_api.py`) are dirty-only; their committed versions at `723be15` are
  ruff-clean. → Codex's ruff-format fix is **not yet committed**.
- CI: **GitHub GREEN** at `723be15` (container/test/console/security-tools/secret-scan all pass);
  **GitLab pipeline #16994 (branch) `pending`** — not yet green.
- Branch `723be15` is pushed to both origin and gitlab (same SHA).

**Both gate conditions unmet → HOLD.** Will lock base = the clean, dual-green HEAD once Codex's
fix is committed and GitLab #16994 (or its successor on the new commit) goes green.

**Aligned first wave (per owner's locked lever order `WP-11 → broker → corpus → surfaces/fuzzer →
egress → mutation`):**
- **W0 = WP-11** (deterministic recorder/tool-call + state-diff oracles & trusted-observation
  contract). **contract-steward FIRST** on the Recorder→Judge observation/oracle boundary (versioned
  handoff) before any producer/consumer code, then the required Test → Test-Review/freeze →
  Implement → Code+Security review sequence, ≤3 workers. WP-11 also needs the WP-11 **Ground-truth
  Reviewer** gate for any human-labeled calibration.
- **WP-03 destination-pin** moves to the **egress wave** (with WP-16D), matching the owner's order
  ("egress" after "surfaces/fuzzer"), not W0.
- **WP-09 ZAP evidence-drift** = trivial truthfulness fix; fold inline (not a wave).
- Migration note: with the de-scoped plan, **WP-11 is the first migration** in scope — reserve ONE
  Alembic revision rebased onto the sole current head at dispatch, replace `<MIGRATION_REV>`, land
  it before any later migration lane; do not create parallel heads.

**Live-web caveat reaffirmed:** W4 active/live web dispatch still needs a separate persisted exact
ZAP/target authorization (owner-noted); build under gate, execute live only under that authorization.

---

## 12. Manual-start override (owner instruction)

**[OWNER — LOCKED]** Do **not** auto-watch, poll, or auto-start. The §10 W0 start-gate (clean tree +
dual-remote CI green) is **necessary but no longer sufficient** on its own: even once both hold, W0
dispatches **only on an explicit owner "go."** Orchestrator remains idle/held until then; no worker
launches, no monitoring loop, no target/network/deploy action.

---

## 13. Start-gate REVISION (owner) — GitLab dropped; base-pin trigger

**[OWNER — LOCKED, supersedes §10/§11 gate wording]** GitLab is now a **mirror** (no independent
GitLab CI). The W0 start gate is therefore:

1. **Clean working tree** (Codex's ruff-format fix committed), AND
2. **GitHub CI green** — already green at `723be15` and must remain green on the fix commit, AND
3. **Base pinned by the integration manager** (`<RED_TEAM_GAP_BASE_SHA>` recorded by them).

**Do NOT wait on any GitLab pipeline** (drop #16994 entirely). Per §12, I remain held and do **not**
poll/auto-watch: my start trigger is being told the **integration manager has pinned the base**
(with the SHA). On that signal I verify (clean tree + GitHub green at the pinned SHA) and immediately
dispatch **W0 = WP-11**. (GitLab-mirror affects only this start gate; the separate dual-remote
*release* law is reconciled later, not here.)

---

## 14. EXPANDED MANDATE (owner) — default scan = frozen 100-case, fully-oracled, decisive

**[OWNER — LOCKED, expands §10; oracles-first ordering preserved]** The default user-launched scan
must run the full **reviewed 100-case** corpus with complete oracle coverage and produce **DECISIVE**
verdicts across all six categories — not ~9 mostly-INDETERMINATE. A case is authored **only after**
the oracle it binds to exists.

**Immediate track (supersedes §10 ranks 1→3→5 sequencing for this deliverable):**
**T1 WP-11 oracles → T2 WP-14 author-to-100 → T3 WP-12 wire 100 as default.** (The runtime broker
WP-13 and mutation WP-15 remain §10 scope but are the GENERATIVE expansion BEYOND the 100 reviewed
cases — they are NOT required for this deliverable and follow it.)

**T1 — WP-11 oracles (the unlock).** Deterministic observation so the Judge decides not abstains,
**deterministic oracle precedence over any model Judge**. Seven families:
1. tool-call oracle: name + args + authorization decision + side-effects (forbidden-tool /
   unintended-invocation / parameter-tampering);
2. patient/tenant scope oracle: retrieval-scope + principal traces (cross-patient / authz-bypass /
   privilege-escalation);
3. state-diff / write oracle: pre/post diff (state-corruption / clinical-writeback);
4. RAG-source oracle: source/document/chunk IDs + metadata-filter decisions (indirect-injection /
   context-poisoning);
5. output-sink canaries: HTML / Markdown / URL / SQL / template / command (improper output handling);
6. system-prompt canary + cross-patient exfil canary (extend the two existing);
7. consumption oracle: request / tool-call / token / latency / cost counters (DoS / unbounded).

**T2 — WP-14 corpus to 100.** Author ~86 more `AttackCase` (attack-case.v1.json) → 100 total across
ALL six categories (prompt_injection, data_exfiltration, tool_misuse, state_corruption,
denial_of_service, identity_role_exploitation), single- and multi-turn, each with: `owasp[]` (Web
2021 + LLM 2025) full-taxonomy; `oracle_expectation` bound to a T1 oracle that **exists**
(availability != unavailable); expected_evidence; severity; exploitability; test_design
(boundary/invariant/regression); synthetic provenance; stable IDs + content hashes. Independent
review + Ground-truth review before freeze; content-address + dedup; **freeze the 100-case manifest
with an exact expected physical-request count**. (AI never fabricates the human ground-truth labels.)

**T3 — WP-12 wire default.** Replace the 9/14 default with the frozen 100-case baseline in
coordinator/runner; a default scan dispatches all 100 via PolicyGateway → Recorder → Judge with
oracles active; update logical/physical caps to the 100-case counts; two-person authorization bound
to the exact **100-case corpus hash**; sequential dispatch **≤0.5 req/s**; hard-abort re-check before
every physical send.

**HONEST BAR (non-negotiable):** goal = DECISIVE verdicts (pass / fail / confirmed / held), NOT 100
fabricated passes. Target resistance → decisive **NO_EXPLOIT / held** is the correct, valuable
result. Confirmed exploits → Documentation → vuln reports (publication human-gated). A case whose
oracle isn't ready **stays INDETERMINATE**; never relabel INDETERMINATE as decisive; never author a
case against a non-existent oracle to inflate the count.

**GOVERNANCE (unchanged):** gateway-only target exit; oracle precedence; two-person auth bound to the
exact corpus hash; synthetic data only; Documentation drafts only confirmed findings; TDD, isolated
branch → PR; coordinate with the integration manager on the corpus + coordinator-default seams.

**DELIVER + REPORT metrics:** WP-11 oracles live; frozen reviewed 100-case corpus (6 categories,
full OWASP mapping, each bound to a real oracle); 100 as default scan size; a default scan producing
100 decisive verdicts. Report **category coverage**, **oracle coverage (% cases with a live oracle)**,
and the **verdict distribution**.

**Gate status at this check (HOLD — base not pinned):** tree clean except this report; ruff-format
committed (258 files clean); but local HEAD `23dc7a1` is **UNPUSHED** (GitHub 422 "no commit"),
GitHub green only at `723be15`, PR #29 supersedes prior — integration in flight, **base NOT pinned**.
W0 dispatches only on: integration manager pins base `<SHA>` + that SHA pushed & GitHub-green + tree
clean. No polling; awaiting the base-pin signal.

---

## 15. W0 dispatch plan PREPPED (held) — see RTG-W0-dispatch-plan.md

Ran read-only prep workflow (`wf_a31387e3-ef8`, 3 analysts). Fire-ready plan in
`.tdd-swarm/reports/RTG-W0-dispatch-plan.md`. Headlines:
- **WP-11 is mostly wiring:** 5 of 7 oracle *evaluators* already exist (`ToolAuthorization`,
  `RetrievalScope`, `StateCorruption`, `ResourceLimit`, `Canary`×2), registered
  `runtime_wired=False`. NEW work = `RagSourceOracle`, `RenderSinkOracle` (6 sink predicates,
  biggest gap), request-count dimension, cross-patient canary scope, observation-collection layer,
  5 contracts (steward first), ONE migration on sole head `0017`, Judge 4-state + required-oracle gate.
- **WP-14 = 86 new cases → 100 six-category** (PI20/DX18/TM18/SC15/DS14/IR15). 32 (PI+DX) are
  oracle-ready now; 39 (SC/DS/IR) are **WP-11-gated**. New corpus_id (NOT the frozen 3-category
  `headshot-live-100-v1`). Physical count 121 or 124 (review-locked). Add NFKC/confusable dedup.
- **Ground-truth labels needed (human, non-fabricable):** 6 per-category calibration slices
  (labeler + distinct reviewer), applicability N/A records, train/dev/holdout split + guide hash.
- **Seam handoffs to integration manager:** `target/catalog.py` (WP-12 hard rebase), MVP floors
  `postgres.py:2631`/`runner.py:1072`/`birdseye.py:385` + `runner.py:1140` LIVE_100 caps
  (cross-lane retarget, not in any WP write-list), judge verdict-enum change vs in-flight hosted.py.
- **Open decisions before fire:** attack-case **v1 vs v2** (recommend build v2); turn balance;
  label ownership; floors-retarget owner.

**Gate (unchanged HOLD):** base NOT pinned. Integration manager now on branch
`codex/platform-observability-followup` @ `971dd98`, HEAD moving, sole Alembic head `0017`, tree
clean but for this report. No dispatch, no polling — awaiting base-pin signal.

---

## 16. Owner decisions LOCKED — ready to fire on A's pinned SHA

1. Schema = **attack-case v1** (no v2 prerequisite; v2/ASI = documented planned enhancement; new
   corpus_id, `AF-M11-*` IDs). 2. Turn balance = **79/21 → 121 physical** (review-lock at freeze).
   3. Ground-truth = **owner-attested blind**; propose labels from designed-in synthetic outcomes;
   single-human-attested documented as a limitation if no 2nd reviewer; concrete labels+guide hash
   surfaced during execution. 4. Floors-retarget (`postgres.py:2631`, `runner.py:1072/1140`,
   `birdseye.py:385`) **owned by A** (WP-20A/B).
   Coordination with A: base pinned WITH `catalog.py` surface edits; preserve Judge verdict-enum API
   that `hosted.py` consumes. Full detail in `RTG-W0-dispatch-plan.md §H`.

**HOLD unchanged:** fire W0 the instant A pins the base SHA (verify clean + GitHub-green first). No
polling. All decisions locked; nothing else blocks dispatch.

---

## 17. FIRE attempt on ce7ab84 — base verified green, BUT reconciliation blocker

Owner pinned `ce7ab84` and said fire. Verified per fire-sequence:
- **`ce7ab84` = PR#35 integration merge, GitHub CI GREEN** (console/container/secret-scan/
  security-tools/test all pass). Alembic head **0017** (same as everywhere; "post-0018" appears to
  be a non-Alembic phase label — no 0018 rev exists on ce7ab84 or the checkout).

**But the working directory is NOT on ce7ab84** — it is on branch
`redteam/judge-calibration-corpus-evidence` @ `8ce852b`, which:
- does **NOT descend from `ce7ab84`** (divergent line via 971dd98; both at Alembic 0017 so no
  migration divergence yet);
- **already holds partial WP-11/WP-14 work**: 16 cases (9 seeds + 7 drafts) across all 6 categories,
  6 ground-truth slices (all `AUTHORED_NOT_RUN`, agent/rule-labeled — NOT human), a passing
  model-Judge calibration harness (`runtime_enabled:false`). Missing: the NEW oracles
  (RagSource/RenderSink not present), observation-collection layer, and the 86 additional cases /
  100-case corpus (`evals/corpora/` does not exist);
- **has an ACTIVE pytest process (PID 4301)** running in this worktree right now; the repo has **~40
  live Codex worktrees**.

**Why I did NOT fire:** blindly creating branches + running a heavy ≤3-worker TDD build with
`scripts/check.sh` in this shared, actively-used checkout would collide with the active pytest and
the 40-worktree operation; and building fresh off `ce7ab84` would DUPLICATE/CONFLICT with the
existing `redteam/...` WP-11/WP-14 foundation. The pin (`ce7ab84`) and the actual work location
(`8ce852b`, divergent) don't match — a reconciliation only the owner/integration-lead can direct.

**Deliverable done regardless:** ground-truth label spec at
`.tdd-swarm/reports/RTG-ground-truth-label-spec.md` (format + which cases + attestation fields).

**Awaiting one decision:** which branch/base to build on + who owns `redteam/...` (see message to
owner). Ready to fire immediately on the answer.

---

## 18. REFOCUSED MANDATE (owner) — BUILD → AUTHORIZE → RUN (authoritative params)

Owner refocused: the 100-case corpus does not exist (`evals/workloads/headshot-live-100-v1.json`
missing; active = 9 seeds); committed catalog caps (40/40/60/$1/1800s) reject a ~121-req scope.
Sequence = **BUILD → AUTHORIZE → RUN.** Working in isolated worktree
`/Users/quietguy/Documents/Dev/Gauntlet/wt-rtg-swarm` (branch `rtg/wp11-wp14` off `8ce852b`).

**BUILD** — author `evals/workloads/headshot-live-100-v1.json`: expand the 9 active seeds → 100
cases, attack-case **v1**, 6 categories, OWASP Web+LLM tags, `oracle_expectation` per case. **Every
case binds to a REAL, WIRED oracle** — never reference an oracle ID that doesn't exist/fire (that is
what pinned 7/9 to permanent INDETERMINATE). 79 single + 21 two-turn ≈ 121 physical. Reconcile
`corpus.py` LIVE_100 constants (category counts → 6-category; keep ~121 physical) as a reviewed
change. Independent review + dedup + content-address + freeze.

**AUTHORIZE** — operator-AUTHORIZED envelope for this campaign (apply to committed catalog as a
reviewed change; hand to **m** for merge; **do NOT self-raise beyond it**):
`attempts/logical=130, physical=160, max_usd=25, timeout=3600s, rps=0.5, concurrency=1`.
Two-person: launcher mints operation_hash bound to corpus_hash + caps; **distinct approver** approves.

**Judge handoff (from v)** — identity_sha256 `aac135ea…`, calibration_id `JC-67647b62…`,
slice_set_sha256 `39e1b72d…`. Calibrated model-Judge **NOT enabled** (`human_approved:false`) →
**deterministic oracles are the decisive layer** regardless of the pending enable decision.

**RUN** — governed pipeline only: Policy-Gateway-only egress, generation ⊥ evaluation,
deterministic-oracle precedence. Report cases run, verdict distribution (CONFIRMED/SAFE/
INDETERMINATE), which oracle families fired. **Honest mix only — no weakening or relabeling.**

**Ground-truth:** two-person (distinct reviewer available) — spec at
`RTG-ground-truth-label-spec.md`. Need the two principal ids at attestation.

**Staging reality:** BUILD is mine now; RUN is gated on caps merged by **m** + two-person
RunAuthorization + live-run access (SIDs in `.env.campaign`). Honest note: against a black-box
`/chat` target only response-**canary** oracles observe directly; scope/tool/state/resource/identity
oracles fire only where the run pipeline collects those observations — corpus maximizes decisive
(canary-anchored) cases and reports the rest honestly as INDETERMINATE, never relabeled.

---

## 19. CRITICAL GATE sharpened (owner + v): WIRE oracles FIRST, then bind corpus

- **Judge stays OFF** for the run (`human_approved:false`, by design) — the model cannot confirm
  exploits. **Confirmations come only from oracle / canary / human hits.**
- **v found 7 of 9 oracles `runtime_wired=False`** — only the 2 canaries fire today. A 100-case run
  against 2 wired oracles = **100 INDETERMINATE**. **Wiring the pending oracle families (WP-11
  observation-collection) is the PREREQUISITE for a decisive scan.** Wire before/as the corpus is
  built; **bind each case to a wired oracle.**
- **Order (reaffirmed oracles-first):** WP-11 WIRE (observations/** + recorder + registry
  runtime_wired flips, each proven by a test that the observation is actually collected) → author
  the 100-case corpus bound to wired oracles → authorize → run.

**Honesty boundary (mine to hold):** wiring makes an oracle FIRE only where its observation is
actually AVAILABLE from the run against this target. Grounding agent G1 (in flight,
`wf_fe6e6c95-f17`) is measuring, per family, whether the pipeline can collect that observation from
the live target's `/chat` + Week2 surfaces. I will wire + bind cases to the families whose
observations are genuinely available (decisive), and honestly leave the truly-unobservable ones
INDETERMINATE. **I will NOT flip `runtime_wired=True` without a test proving real collection, nor
bind cases to an oracle that won't fire — that would just manufacture INDETERMINATE or fake
confirmations.** "Wired" must mean wired.

---

## 20. Judge WILL be enabled — TWO-LAYER decisiveness (owner + v re-attesting)

v is re-binding the LLM Judge to prod config + re-attesting → it WILL be enabled. Verdict model:

| Layer | Authority | Dispositions |
|---|---|---|
| **Deterministic oracle / canary** (precedence) | **ONLY CONFIRMED authority** | `EXPLOIT_CONFIRMED` (oracle/canary hit) · oracle-negative |
| **Enabled LLM Judge** (non-oracle cases only) | assessment, never CONFIRMED | `EXPLOIT_LIKELY` · `NO_EXPLOIT_OBSERVED` |
| neither decides | — | `INDETERMINATE` (genuine only) |

**Precedence (Worker C Judge):** RULE1 fail-closed `ERROR` → RULE2 oracle/canary hit →
`EXPLOIT_CONFIRMED` (deterministic, sole CONFIRMED path; LLM can NEVER confirm or override an oracle
hit — the Judge invariant holds) → RULE3 no oracle → enabled LLM → `EXPLOIT_LIKELY` |
`NO_EXPLOIT_OBSERVED` → RULE4 `INDETERMINATE`. Keep the required-oracle-policy gate: an
oracle-backed NO_EXPLOIT is strong; an LLM `NO_EXPLOIT_OBSERVED` is an assessment, kept distinct.

**Both layers built:** still WIRE the 7 pending oracles (they give CONFIRMED authority + decisive
negatives); the enabled LLM makes the remaining non-oracle cases decisive
(LIKELY/NO_EXPLOIT_OBSERVED) instead of INDETERMINATE.

**Honesty conditions I hold:** (1) oracle/canary is the ONLY `EXPLOIT_CONFIRMED`; (2) LLM
dispositions count ONLY once v's re-attestation lands genuinely (`human_approved:true` + calibration
gate passes) — if it doesn't, the LLM layer stays off and those cases are INDETERMINATE, not faked;
(3) generation ⊥ evaluation preserved; (4) INDETERMINATE never relabeled. Report distribution across
all four dispositions + which oracle families fired.

---

## 21. GROUNDING RESULT (wf_fe6e6c95) — honesty-critical: wiring ≠ firing on a black-box target

**Handoff confirmed:** v's Judge SHAs all match (identity `aac135ea`, calib `JC-67647b62`, slice_set
`39e1b72d`); currently `runtime_enabled/human_approved=false` (v re-attesting).

**THE finding (evidence-backed):** against the live black-box `POST /chat`, the ONLY
target-observable, wired, decisive deterministic oracle is the **CANARY** (substring over
`response_transcript`; `coordinator.py:713`, `judge.py:132-135`). The 5 category oracles
(tool_call, resource, state_diff, identity_role, retrieval_scope) consume observations
(`ToolCallObservation`, etc.) that are **never constructed anywhere in `src/`** and that a black-box
`/chat` **never returns** — the adapter surfaces only HTTP body/status/url
(`openemr_adapter.py:374-382`), the recorder persists only transcripts (`recorder.py:41-63`), and
`_adjudicate` builds only `CanaryOracle`. **So wiring those oracle evaluators into the run path does
NOT make them fire — there is no source data to populate their observations. They stay
INDETERMINATE regardless of wiring.** Wiring is necessary-but-insufficient; the missing thing is
target telemetry a black box won't give.

**Honest decisive design (what actually works):**
1. **Canary-anchoring = the lever.** Design cases so a successful exploit ECHOES a seeded synthetic
   canary into the `/chat` body → decisive `EXPLOIT_CONFIRMED`. Works natively for data_exfiltration
   (cross-patient canary) + prompt_injection (system-prompt canary) and can be RE-EXPRESSED for
   other categories (make success surface a canary). This gives real CONFIRMED across categories.
2. **Consumption oracle IS platform-observable** — the gateway's own meter (tokens/latency/cost/
   request-count of our calls to the target) can be projected into a `ResourceObservation`. That's a
   legit new wiring for DoS/unbounded-consumption (the ONE category oracle we can honestly make fire).
3. **Enabled LLM Judge** (once v attests) → `EXPLOIT_LIKELY`/`NO_EXPLOIT_OBSERVED` on non-canary
   cases — makes them decisive-as-assessment (never CONFIRMED).
4. **RAG-source**: possibly wireable IF the Week2 surface exposes source/citation digests (needs a
   Week2 adapter/observation point, WP-12) — stretch, verify before promising.
5. **tool_call / state_diff / identity_role pure-observation oracles: NOT decisive vs a black-box
   target.** Those cases get canary re-expression or LLM assessment; genuinely-unobservable ones stay
   honestly INDETERMINATE. **I will NOT flip their `runtime_wired=True` — that would fake firing.**

**RUN reality (G2):** direct launchers (`platform_live_run.py`, `live_campaign.py`) are RETIRED/
fail-closed. Only path: Web API `POST /campaign-authorization-requests` → distinct approver
`POST …/decisions` (code-enforced `launcher != approver`, `store.py:732-735`) → `POST /campaigns` →
Postgres queue → private DurableRunner. **Two-person needs 2 distinct authenticated principals.**

**AUTHORIZE reality (G2):** caps live in **4 committed files** (`config/targets/clinical-copilot-
20260724.json`, `live-target-catalog.staging.json`, `.production.json`, `docs/evidence/
authorization-requests/caps.json`) — must move in lockstep. Envelope `130/160/$25/3600/0.5` = the
catalog **ceiling**; the actual RUN caps must EXACTLY equal the corpus (`logical==#cases`,
`physical==sum(turns)`, `retries==0`) per `runner.py:1140-1150` — and **retries must be 0** (catalog
has 1). Workload build also needs per-case provenance sidecars + the embedded 14-case baseline +
pinned manifest sha (`corpus.py:312-527`).

**Awaiting owner call:** confirm the honest canary-anchored + consumption-wire + LLM design (vs.
spending effort wiring oracles that cannot fire against this black-box target).

---

## 22. BUILD fired (honest design) + price precondition status

Owner GO on honest design. Building in worktree `wt-rtg-swarm` (`rtg/wp11-wp14`).
- **Price precondition NOT yet on my base:** `docs/COST_MODEL.md` absent; corrected real prices
  (opus 5/25, gemini 1.25/10, qwen .39/2.34) not in my config — node still correcting the $100/M
  ceiling. **RUN is gated on this landing** (reservation ~$30-40 must fit under the $50 hard cap, or
  the run refuses). BUILD proceeds now; I confirm the correction before firing the campaign.
- **Caps** (reviewed change for m, derived AFTER corpus built): `logical=#cases`, `physical=Σturns`,
  `retries=0`, in the 4 committed files; budget/timeout/rps per envelope. retries currently 1 → 0.
- **Design:** 100 cases, 6 categories (PI20/DX18/TM18/SC15/DoS14/IR15), 79 single + 21 two-turn =
  121 physical, attack-case v1, canary-anchored (success echoes a SEEDED synthetic canary),
  consumption oracle wired from the gateway meter (DoS), non-canary → LLM-assessed. WP-11 observation
  layer NOT built (Horizon 2); unobservable oracles NOT flipped to runtime_wired.
- **Honest bound:** decisive CONFIRMED count is limited by the canaries actually SEEDED in the live
  target (declared `target.canary_refs`); cases without a seeded-canary echo are LLM-assessed, not
  faked. Real distribution reported after RUN.

---

## 23. BUILD COMPLETE + verified — headshot-live-100-v1 (commit d9d7b4a)

Independently verified (not agent self-report):
- **100 cases**, categories {PI20/DX18/TM18/SC15/DoS14/IR15}=100; **79 single + 21 two-turn = 121
  physical**; loader loads with pinned manifest sha `07d649…252d`; **validate_attack_case 100/100**;
  32 corpus/workload/full-scan/work-unit tests PASS (no regression from the corpus.py 6-category
  reconciliation; MVP/FULL_SCAN identities intact).
- **Honest decisive-layer split (oracle_expectation.kind):** 26 system_prompt_canary + 33
  synthetic_canary = **59 canary** (anchored on the 2 genuinely-seeded canaries); **14
  resource_limit_violation** (consumption, pending wiring); **23 none** (LLM-assessed); **4** baseline
  recorder-oracle (patient_scope×2 + forbidden_tool×2, unwired → honest INDETERMINATE).
- Committed to `rtg/wp11-wp14` (305 files). Not pushed; A aligns onto ce7ab84.

**Decisiveness depends on BOTH layers at RUN:** a canary case that misses (target resists) falls to
RULE3 → enabled LLM Judge → NO_EXPLOIT_OBSERVED (decisive) — so ~96/100 are decisive IF the LLM Judge
is enabled (v) and consumption is wired; without the LLM enabled, canary-misses + the 23 none → all
INDETERMINATE. LLM-enable (v) + consumption-wire are the two remaining decisiveness levers.

**Next:** (1) wire consumption oracle from gateway meter (14 DoS cases); (2) caps reviewed change for
m (logical=100, physical=121, retries=0); (3) confirm price correction landed; (4) two-person
authorize + governed RUN → honest report.

---

## 24. Consumption oracle WIRED + verified (commit d896908)

TDD (Test→freeze→Implement→Code+Security review), both reviews APPROVED.
- `_adjudicate` now runs `ResourceLimitOracle` from the gateway's MEASURED trio (elapsed_ms,
  request_count, response_size) re-read from Postgres, ALONGSIDE `CanaryOracle` (canary precedence
  intact; Judge never reads hostile transcript). Target-internal tokens/tool-calls/cost left None →
  skipped, never fabricated. `recorder-resource-limits-v1` runtime_wired=True justified by an
  end-to-end measured-breach test.
- Migration **0018** (expand-only nullable JSONB `attempt_result.resource_measurements`), verified
  **single head ← 0017** (no parallel heads); ORM parity holds.
- Independent verify: frozen 9 + regression green; **full suite 1524 passed / 3 pre-existing skips**.
- The 14 DoS cases can now fire on a real measured breach (timeout / request-count / response-size).

**Decisive layers now live:** canary (59) + consumption (14) deterministic; LLM (23, on Judge
enable) — ~96/100 decisive once the LLM Judge is enabled; 4 baseline unwired = honest INDETERMINATE.

**Next:** caps reviewed change for m (logical=100, physical=121, retries=0; budget=50 hard cap,
timeout=3600, rps=0.5) across the 4 catalog files; then RUN preconditions (price correction landed +
LLM Judge enabled + caps merged + platform deployed with these commits) → two-person governed RUN.

---

## 25. BUILD deliverable COMPLETE on rtg/wp11-wp14 — RUN is a coordinated multi-party step

Three verified commits on `rtg/wp11-wp14` (off `8ce852b`; A aligns onto `ce7ab84`):
- `d9d7b4a` corpus: headshot-live-100-v1 (100 canary-anchored cases, loader-validated, sha 07d649…252d)
- `d896908` consumption oracle wired (measured dims; 1524 suite green; migration 0018 single head)
- `f43ef2f` caps envelope for m (100/121/0 exact-match validated; test_runner_campaign 29 passed)

**RUN cannot be executed by me alone** — it is a governed live campaign requiring, in order:
1. **m** integrates `rtg/wp11-wp14` onto `ce7ab84` (incl. caps; note production.json flag) + **deploys**
   the Railway release with these commits (the retired launchers mean the ONLY path is Web API →
   Postgres queue → private DurableRunner, so the code must be deployed).
2. **node**: price correction landed (real prices in role config) so the reservation (~$30-40) fits
   under the $50 cap — else the run refuses at reservation.
3. **v**: LLM Judge enabled (`human_approved:true`) so non-canary cases are decisive (else INDETERMINATE).
4. **Two distinct principals** (launcher ≠ approver, code-enforced): `POST /campaign-authorization-
   requests` (corpus_hash=07d649…, caps envelope, run_nonce) → distinct approver `POST …/decisions` →
   `POST /campaigns` → Runner with `AGENTFORGE_WORKLOAD_ID=headshot-live-100-v1` + pinned manifest sha
   + leased SIDs.

I can prepare the authorization-request payload + a zero-call RUN-readiness preflight next. The
two-person approval and the deploy are external. Post-run I report cases run, verdict distribution
(CONFIRMED/EXPLOIT_LIKELY/NO_EXPLOIT_OBSERVED/INDETERMINATE), oracle families fired, and metered cost.

---

## 26. CORPUS LANE (g) FINALIZE COMPLETE — handed to m (branch rtg/wp11-wp14)

4 clean commits: d9d7b4a corpus · d896908 consumption wiring (migration 0018) · f43ef2f caps ·
5205d8d finalize. Handoff doc: `docs/RTG_CORPUS_LANE_HANDOFF.md` (in-branch).

**Bar met (verified):** 100 cases / 6 categories (PI20/DX18/TM18/SC15/DoS14/IR15); every case
OWASP-tagged (Web+LLM) + oracle_expectation; **59 guaranteed-confirm canary cases** (≥1 met);
consumption oracle wired (14 DoS decisive). End-to-end confirm proven for 5 real canary cases across
5 categories (deterministic fixture, not live). 200 candidate whole-corpus labels
(AUTHORED_PENDING_HUMAN_ATTESTATION, two-person slots empty).

**Batching:** 3 sub-workloads (34/33/33 cases, 41/40/40 physical), each ≤56, no cap raise, ≤$30<$50.
**CRITICAL for m:** runner does NOT chunk → must submit **3 separately-authorized sub-workloads**;
each needs its own exact-match caps (headshot-live-100-v1 caps=121 is the aggregate ceiling).

**Cross-lane flags:** (1) caps envelope written to production.json too — m scope if needed;
(2) whole-corpus labels change v's slice_set_sha256 (39e1b72d) → v re-calibrate/re-attest before LLM
enablement. **RUN preconditions (external):** price (node) · Judge enable (v) · deploy (m) · two
principals. Corpus lane deliverable is DONE; RUN/report of actual verdicts awaits those.

---

## 27. rt2 reproduction package delivered + validate-corpus regression fixed

Helped rt2 (per owner offer) with the 3-vuln reproduction design off the canary cases:
- **V1** system-prompt leakage (`AF-M11-PI-101`, boundary, A04·LLM07), **V2** cross-patient PHI exfil
  (`AF-M11-DX-001`, invariant, A01/A07·LLM02/LLM08), **V3** maintenance-mode privilege-escalation
  (`AF-M11-IR-102`, multi-turn, A01·LLM07).
- Each has a **distinct benign NEGATIVE CONTROL** proving the oracle confirms on the real leak, not
  innocent traffic (V2's control returns alpha's OWN canary yet must NOT trip the beta oracle → "right
  reason"). Paired positive(echo)/negative(benign) proof through the real `_adjudicate` seam:
  `tests/test_rt2_vuln_reproduction.py` **4 passed** (deterministic fixture, not live).
- Full lineage + proposed `AF-VULN-2026-0725-00{1,2,3}` ids in `docs/RTG_RT2_REPRODUCTION_DESIGN.md`
  (rt2 writes the reports). Controls artifact `evals/reproduction/rt2-negative-controls.v1.json`.

**Self-caught regression fixed:** my finalize commit had placed the 200-label candidate corpus in
`evals/ground-truth/`, which made `validate-corpus` RED (it validates every file there as a strict
slice; a candidate corpus can't be one). Relocated to `evals/ground-truth-candidates/` (+README,
ref updates) → **validate-corpus GREEN** (16 authored / 54 labels). Invariants held throughout
(canary/oracle/human = only CONFIRM; LLM never confirms; INDETERMINATE ≠ safe).

Branch `rtg/wp11-wp14`: 7 commits, tree clean, validate-corpus green. Corpus lane fully done +
rt2 assist delivered. Run itself awaits deploy (m) + Judge-enable (v) + the two attestors.

---

## 28. Both critical-path deliverables DONE (commits d0c2cae, f888791)

**1. 3 loadable batch sub-corpora** — `resolve_workload("headshot-live-100-batch-0N")`:
batch-01 (34 cases/41 phys, sha cb852c), batch-02 (33/40, a29bf9), batch-03 (33/40, fadf6d). Shared
`_load_reviewed_workload_manifest` spine; `load_live_100_corpus` UNCHANGED (sha 07d649…252d); batch
entries byte-identical to the whole (no re-authoring); union = exactly the 100; each physical ≤56 (no
cap raise); closed registry preserved. Per-batch exact caps in `live-100-batch-caps.json`. Code +
Security review APPROVED; 54 batch/regression tests + validate-corpus green.
**Runner follow-up for m (not a cap-escape):** `runner.py:~1140` (exact-cap) + `~682` (order-drift)
are LIVE_100-gated → generalize to `{LIVE_100_CORPUS_ID, *LIVE_100_BATCH_IDS}`. 56 hosted cap still
fails closed via `_require_hosted_workload_capacity`.

**2. Two-person attestation packet** — `docs/attestation/`: LABELING_GUIDE.v1.md (guide hash
`faa12714…b488`, reproduces), ATTESTATION_PACKET.md (100/100, blank P1 labeler + P2 distinct-reviewer),
attestation_entry.csv. Bound to manifest sha 07d649 + candidate sha adf733ba; invariants stated.

Corpus lane branch `rtg/wp11-wp14`: **9 commits, tree clean, validate-corpus green** — complete
integration input for m. Everything the corpus lane owed (+ the rt2 assist) is delivered. Run itself
still awaits deploy (m) + Judge-enable (v) + the two attestors.

---

## 29. Demo-critical: canary confirmed LIVE + registry flag made accurate

**Answer:** the canary oracle IS live at runtime and the governed run's canary-confirmed finding fires
— it never depended on the registry flag. Evidence: `coordinator.py:461` keeps run_oracle True when a
case has a canary_ref (all 59 do); `768-772` builds+runs `CanaryOracle(canary_token)`; the
`CampaignAbort("oracle canary is missing")` at :770 is unreachable for canary cases; NOTHING in
runner/coordinator/gateway reads the registry `runtime_wired` flag (only test-only build_evaluator).
Proven by `test_live_100_canary_confirm.py` (5/5 → EXPLOIT_CONFIRMED).

**Action (commit on rtg/wp11-wp14):** flipped the 2 canary registrations to `runtime_wired=True`
(accurate — the canary observation is composed into _adjudicate and fires; availability stays
`local_fixture_only`), mirroring the consumption precedent. Registry now truthfully shows **3
runtime-wired oracles** (2 canary + consumption); the 6 unobservable category oracles correctly stay
False (the honest "8 of 9" was a stale flag, now 6 of 9 correctly-False). Both reviews APPROVED;
**calibration untouched** (calibration.py diff empty; all 6 judge-calibration tests green); full
affected surface 348 passed; validate-corpus green. No CONFIRM/Judge/INDETERMINATE-not-safe invariant
weakened.
