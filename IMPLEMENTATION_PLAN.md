# IMPLEMENTATION_PLAN.md — AgentForge / Adversarial Machine

> Executable decomposition of the binding **`ARCHITECTURE.md`** (§1–§21). Produced by `/tasks-gen`
> (2026-07-20), corrected pass 2026-07-20. Requirements source: `Week_3_AgentForge.pdf`;
> deliverables/phase checklist: `PLAN.md` §6–§7; binding constraints: `ARCHITECTURE.md` (esp. **§20**),
> `docs/planning/gap-audit.md`, `docs/planning/DECISIONS.md` (D1–D18), `THREAT_MODEL.md`,
> `docs/planning/CLAUDE_CODE_HANDOFF.md`, `docs/planning/PRESEARCH.md` §5.2 (entities/state machines).
> Posture: **production-grade** — a happy-path-only acceptance is incomplete.
>
> **Task fields.** `Files:` new vs extended paths · `Anchors:` ARCHITECTURE § + D#/ADR · `Map:` PRD-## /
> F# / S# / O# satisfied · `Deps:` task IDs that must land first · `Est:` XS≤1h · S 2-3h · M 4-6h · L ~1d ·
> `Accept:` behavior incl. edge + error · `Verify:` command/observation that proves it · `Test:`
> unit/integration/eval hook (evals tagged boundary|invariant|regression) · `Skills:` dev workflow ·
> `⚠ HUMAN AUTH:` requires explicit human authorization (external-state; **not executed in planning**).
> Checkboxes are state; update in place. **This plan is not committed by the pass that generates it** and
> `tasks-gen` writes no application code.

## ⚠ External-state operations — HUMAN AUTHORIZATION REQUIRED

The following require **explicit human authorization** and are **not executed during planning**. Tasks
that touch them are tagged `⚠ HUMAN AUTH`:

1. GitHub repository creation, remote configuration, and push (P11)
2. Railway project/environment creation and deployment (M1, M15)
3. Langfuse Cloud project/account creation (M6)
4. Live target probing or modification (D1, M5, M7)
5. Credential and secret configuration (M1, M4, M5)
6. Live load/stress testing (F10)
7. Social-post publication (F13)
8. Hosted-OSS Red Team inference — provider account creation + scoped credentials + budget cap (M8; per the MVP decision to run hosted-OSS)

## Skill-creation order (skills referenced by tasks that do not yet exist)

Only the 10 dev-workflow skills exist today. These **build skills must be created via `skill-creator`
before their consumers**, frontmatter + trigger boundaries validated against `CLAUDE.md`:

- **First wave (before MVP consumers):** `contract-steward` (P1) · `threat-model` (P2) ·
  `adversarial-eval-lifecycle` (P3) · `judge-calibration` (P4) · `authorized-live-campaign` (P5)
- **Before Final consumers:** `vuln-report` (P6) · `evidence-audit` (P7)
- **`cost-model` is NOT a skill** — a deterministic script/template (F5).

## Phase gates (real submission deadlines — do not reorder)

| Phase | Gate | Hard-gate deliverables |
|---|---|---|
| **D — Architecture Defense** | ~2.5h post-kickoff, **2026-07-20** | Binding `ARCHITECTURE.md` ✓, D2/D4 diagram (D3 gate), `ADR-0001` ✓, `DEFENSE_SCRIPT.md` ✓, first-pass `THREAT_MODEL.md` ✓, trust boundaries ✓, **deployed target URL** (D1) |
| **M — MVP** | **Tue 2026-07-21 23:59** | Deployed platform + URL; `THREAT_MODEL.md` (deepened); `./evals/` ≥3 categories + ≥1 live agent vs live target; `contracts/v1` + error taxonomy; requirements matrix |
| **F — Final** | **Fri 2026-07-24 12:00** | Full four-agent platform + harness + observability; ≥3 vuln reports; cost analysis; triage report; ATO packet; integration packet; perf baselines + load test; demo video; social post |

---

## Prerequisites & Enablement  (start immediately; mostly parallel; local except P11)

- [x] **P1 — Create skill `contract-steward`** ∥
  - Files: NEW `.claude/skills/contract-steward/SKILL.md` · Anchors: `CLAUDE.md` skill spec, §4 · Map: enables P10, F9
  - Deps: none · Est: S
  - Accept: (a) created via `skill-creator`; (b) valid frontmatter (name/description); (c) **trigger boundary** = "define/change an inter-agent contract, bump a schema" — distinct from tasks-gen; (d) edge: covers versioned schema + typed errors + both-sided tests + migration notes; (e) error: a description colliding with an existing trigger is flagged
  - Verify: appears in Skill tool; frontmatter lints; trigger-boundary review vs `CLAUDE.md`
  - Test: — (skill; `skill-reviewer` if available) · Skills: **skill-creator**

- [x] **P2 — Create skill `threat-model`** ∥
  - Files: NEW `.claude/skills/threat-model/SKILL.md` · Map: enables M7 · Deps: none · Est: S
  - Accept: (a) `skill-creator`; (b) trigger = "map/deepen the attack surface" — **distinct from** adversarial-eval-lifecycle; (c) edge: outputs the 6 categories + OWASP `{framework,version,id,name}` per D15; (d) error: overlap with eval-authoring flagged
  - Verify: Skill tool lists it; boundary review · Test: — · Skills: **skill-creator**

- [x] **P3 — Create skill `adversarial-eval-lifecycle`** ∥
  - Files: NEW `.claude/skills/adversarial-eval-lifecycle/SKILL.md` · Map: enables M8, M11, F4 · Deps: none · Est: S
  - Accept: (a) `skill-creator`; (b) trigger = "author/mutate/promote an attack case" — **distinct from** `eval-triage` (diagnoses a failing eval) and `judge-calibration` (ground-truth/drift); (c) edge: enforces boundary|invariant|regression tag + no happy-path-only; (d) error: trigger collision on "eval" flagged
  - Verify: Skill tool; boundary review vs `CLAUDE.md` trigger-boundaries note · Test: — · Skills: **skill-creator**

- [x] **P4 — Create skill `judge-calibration`** ∥
  - Files: NEW `.claude/skills/judge-calibration/SKILL.md` · Map: enables M10 · Deps: none · Est: S
  - Accept: (a) `skill-creator`; (b) trigger = "calibrate the judge / check drift" — systematic, **never per-incident**; (c) edge: covers ground-truth + dual-judging + drift metrics; (d) error: overlap with eval-triage flagged
  - Verify: Skill tool; boundary review · Test: — · Skills: **skill-creator**

- [x] **P5 — Create skill `authorized-live-campaign` (safety-gated)** ∥
  - Files: NEW `.claude/skills/authorized-live-campaign/SKILL.md` · Map: enables M4, F10 · Deps: none · Est: S
  - Accept: (a) `skill-creator`; (b) **`disable-model-invocation: true`** (live attacks are never implicit — `CLAUDE.md`); (c) trigger = explicit only; (d) edge: enforces allowlist + synthetic-data + budget/rate + abort as gate checklist; (e) error: a run without the gate is a failed run
  - Verify: Skill tool shows it non-model-invocable; frontmatter has the flag · Test: — · Skills: **skill-creator**

- [x] **P6 — Create skill `vuln-report`** ∥ (before Final)
  - Files: NEW `.claude/skills/vuln-report/SKILL.md` · Map: enables F2, F6, F7 · Deps: none · Est: S
  - Accept: (a) `skill-creator`; (b) trigger = "write a vuln report / triage a scan"; (c) edge: enforces the 6 PRD-21 fields + data-quality (unique id, no dup sequence) + triage mode; (d) error: a report missing a required field is rejected
  - Verify: Skill tool; boundary review · Test: — · Skills: **skill-creator**

- [x] **P7 — Create skill `evidence-audit`** ∥ (before Final)
  - Files: NEW `.claude/skills/evidence-audit/SKILL.md` · Map: enables F8, F9, F12 · Deps: none · Est: S
  - Accept: (a) `skill-creator`; (b) trigger = "audit checkpoint completeness / assemble ATO+integration packet"; (c) edge: verifies AI-use disclosure current; (d) error: a missing graded deliverable is surfaced
  - Verify: Skill tool; boundary review · Test: — · Skills: **skill-creator**

- [x] **P8 — Repo scaffold + stack + import smoke test**
  - Files: NEW `pyproject.toml`, `src/` tree (per `PLAN.md` §5: `agents/`, `domain/`, `target/`, `regression/`, `observability/`, `policy/`, `storage/`), `ruff.toml`, `tests/test_smoke.py`
  - Anchors: §7 · Map: PLAN §5/§7, D2 · Deps: none · Est: M
  - Accept: (a) `pip install -e .` on Python 3.12; (b) **a real import smoke test** (`import agentforge; assert agentforge.__version__`) so `pytest -q` **passes** (≥1 test, not 0); (c) `ruff check .` clean; domain layer imports no LangGraph; (d) **edge:** a **local pre-commit gate** (`ruff` + `pytest`) fails on a lint error or broken import; (e) **error:** a broken import fails the smoke test. *(Type checking is deferred — no type-error gate is claimed unless a checker is configured in a later task. **GitHub-Actions CI is wired in M1 after the P11 bootstrap** — P8 does not assume a remote.)*
  - Verify: `pytest -q` shows 1 passed; `ruff check .` clean; pre-commit hook runs locally · Test: `test_smoke.py` import assertion · Skills: —

- [x] **P9 — TargetAdapter interface + deterministic fake** (breaks the gateway↔adapter cycle)
  - Files: NEW `src/target/base.py` (generic `TargetAdapter` interface), `src/target/fake_adapter.py` (deterministic record/replay fake)
  - Anchors: §2, §5 · Map: PRD-01 (interface), enables M4, M12 · Deps: P8 · Est: S
  - Accept: (a) generic interface (no OpenEMR specifics); (b) the **deterministic fake** returns fixed, replayable responses for gateway + CI tests; (c) **edge:** fake supports simulated typed errors (target-unreachable, rate-limited); (d) **error:** the fake never reaches a network
  - Verify: fake round-trips a canned attempt with no network · Test: adapter-interface conformance test against the fake · Skills: —

- [x] **P10 — contracts/v1 schemas + typed errors + both-sided contract tests**
  - Files: NEW `contracts/v1/{campaign_directive,attack_attempt,attempt_result,evidence_envelope,verdict,regression_admission}.json`, `contracts/v1/errors/*.json`, `tests/contract/*`
  - Anchors: §4, D10, **D18** · Map: PRD-OPT-04/06/10/11 · Deps: P8, **P1** · Est: L
  - Accept: (a) versioned JSON Schema (min v1), framework-neutral; (b) **Evidence Envelope** with per-field trust labels (`trusted` code-populated `oracle_results[]`/`canary_hits[]`/`policy_decision`/`expected_safe_behavior`/`ground_truth_ref` vs `hostile` transcript) + size bound; (c) **AttemptResult** carries `content_hash` + `{campaign_run_id, attempt_id}`; **Verdict** schema-validated with enumerated states + confidence + typed reason codes; (d) typed error taxonomy (`target-unreachable · budget-exceeded · judge-timeout · no-findings-in-window · regression-detected · rate-limited · adapter-error · evidence-missing · evidence-integrity-failed`); (e) **edge/error:** a breaking change without version bump + migration note + updated tests **fails the run**
  - Verify: `pytest tests/contract` green producer **and** consumer of every boundary; `contract-steward` breaking-change detector fires on an unversioned edit
  - Test: **boundary** — oversized transcript truncated+recorded; **invariant** — a Verdict failing schema validation is a typed error, not a verdict · Skills: **contract-steward** (P1)

- [ ] **P11 — Repository bootstrap (dual-remote)  ⚠ HUMAN AUTH — PARTIALLY COMPLETE / BLOCKED**
  - Files: `.github/workflows/ci.yml`, `.gitlab-ci.yml`, `.pre-commit-config.yaml` (gitleaks)
  - Anchors: §12 · Map: enables GitHub-based CI (M1), Railway deploy-from-GitHub (M1), tdd-swarm · Deps: P8 · Est: M
  - **Repository URLs:** GitHub `https://github.com/worldofhacks/headshot` (**private**) · GitLab `<pending — Gauntlet Labs auth/project not yet available>`.
  - **Status (2026-07-21):** ✅ gitleaks-before-push (proven on an ephemeral fixture, never committed) · ✅ GitHub repo created + `origin` + `main` pushed · ✅ GitHub CI green (checks `test`, `secret-scan`) · ✅ `.gitlab-ci.yml` parity authored · ✅ dual-remote law added to `CLAUDE.md`/`AGENTS.md` · ⛔ **GitHub `main` protection blocked** — HTTP 403 *"Upgrade to GitHub Pro or make this repository public"* (private repo on a free account; not weakened, repo stays private) · ⛔ **GitLab remote/push blocked** — no Gauntlet Labs auth (`glab` absent, no token, SSH publickey denied); project `headshot` (private) not yet created.
  - Accept: (a) gitleaks before first push ✅; (b) GitHub repo + remote + push ✅; (c) protected `main` ⛔ (account capability); (d) required CI checks ✅ (exist+green, not enforceable-as-required without protection); (e) GitLab remote + push + green pipeline ⛔ (auth); (f) tdd-swarm prereqs — see §tdd-swarm; (g) does **not** block D1/target-readiness ✅; (h) secret pre-push blocks push ✅
  - **Recorded honestly:** "GitHub remote + CI complete; GitLab remote pending Gauntlet Labs auth; GitHub branch protection blocked by private-repository account capability." **Not fully complete; tdd-swarm not ready.**
  - **⚠ HUMAN AUTHORIZATION REQUIRED — remaining:** (1) GitHub Pro **or** make repo public → enables protection; (2) Gauntlet Labs GitLab auth + private project `headshot` → enables the GitLab remote/push.

---

## Phase D — Architecture Defense  (gate: 2026-07-20)

**Spec anchors:** §1–§21 + the D2/D4 diagram. **Exit:** diagram corrected (D3 gate) *before* it is used; `ADR-0001` clean; `DEFENSE_SCRIPT.md` dry-run done; Langfuse Cloud Hobby stood up for the demo; deployed target URL in hand.

- [ ] **D1 — Target-readiness investigation  ⚠ HUMAN AUTH (live probing)**  ∥ (independent — blocks on nothing here)
  - Files: extend `README.md` (deployed URL), NEW `docs/target/READINESS.md`
  - Anchors: §2, §17 · Map: **PRD-01/02/03** (hard gate), S8 · Deps: none · Est: M
  - Accept: (a) deployed OpenEMR Co-Pilot URL reachable + recorded; (b) **OQ1** auth mode + **OQ2** API shape/rate-limits/**ZAP web-surface** resolved from the running target; (c) **OQ3** seeded data confirmed synthetic + whether the platform can **plant canaries** (S8); (d) **edge:** every change to make the target testable is logged in `READINESS.md` + README; (e) **error:** if unreachable, escalate — do **not** substitute a mock and call it the live gate
  - Verify: adapter/`curl` smoke hit returns a target response; ZAP-surface decision recorded · Test: smoke hit against the live URL · Skills: threat-model (P2, feeds M7)

- [ ] **D2 — Defense packet confirmation + dry-run**  ∥
  - Files: none new · Anchors: §16, §1 · Map: PRD-12/OPT-02/OPT-04 · Deps: none · Est: S
  - Accept: (a) `ADR-0001` clean incl. F12 Promptfoo + F3 Langfuse-Cloud corrections; (b) `THREAT_MODEL.md` summary + `USERS.md` confirmed; (c) dry-run S2–S4 aloud; (d) **edge:** every `DEFENSE_SCRIPT` claim carries `[implemented|selected|measured|planned]`; (e) **error:** no beat asserts a built platform that does not exist. **Uses the diagram only if D3 has landed** (else present without it).
  - Verify: read-through checklist; Langfuse Cloud Hobby project live with a sample trace · Test: — · Skills: grilling (optional)

- [ ] **D3 — Complete the D2/D4 trust-boundary diagram  [ISOLATED on `wip/d3-diagram`; PRE-PRESENTATION GATE ONLY — blocks nothing else]**
  - **Isolation:** all diagram work lives on branch **`wip/d3-diagram`** (WIP commit `47e7209` — partial hand-edit: `POLICY GATEWAY` present, `EXECUTION RECORDER` label + SVG/PNG exports still missing). **Never restore the `.excalidraw` into `main`** (no `git checkout <branch> -- <file>` — it would re-dirty `main`). To export, use a dedicated worktree: `git worktree add ../headshot-d3 wip/d3-diagram` (path handed to the human).
  - Files (on `wip/d3-diagram` only): `docs/diagrams/D2-D4-agent-interaction-trust.{excalidraw,svg,png}`, NEW render sidecar `…render.json`, NEW `scripts/check_diagram_stale.*`, `docs/planning/DIAGRAM_PLAN.md` (terminology), spec banner removal
  - Anchors: §3, §5, D14 · Map: PRD-12 (diagram), **F2** · Deps: none · Est: M
  - **Label requirement:** the trusted blue component must communicate **both** responsibilities — **`POLICY GATEWAY + EXECUTION RECORDER`**. "POLICY GATEWAY + RECORDER" is acceptable **only if the legend explicitly expands Recorder → Execution Recorder**. A box containing only "POLICY GATEWAY" is **incomplete**.
  - Close-out artifacts (**all** required — not an arbitrary "four files"): (1) corrected `.excalidraw` source; (2) regenerated **SVG**; (3) regenerated **PNG**; (4) render **sidecar** `{spec_sha256, rendered_at}`; (5) **provider-neutral staleness-check script**; (6) a **test proving a match passes and a deliberate drift fails**; (7) **local pre-commit integration** of the staleness check; (8) **stale-banner removal** from the spec; (9) remaining **`DIAGRAM_PLAN.md` terminology correction**; (10) **visual verification** against `ARCHITECTURE.md` §3/§5 and `DEFENSE_SCRIPT.md` S3/S4c.
  - Flow: open a **normal PR from the completed `wip/d3-diagram`**; **do not delete the WIP branch** until the PR is merged, **both remotes are synchronized**, and the rendered artifacts are verified.
  - **GATE:** the stale diagram must **not** be used in any presentation while it contradicts the binding architecture. **D3 is a pre-presentation gate, NOT an MVP implementation blocker** — it does not block foundations, repo setup, skills, target-readiness, or MVP work. **Not executed in the current pass.**

---

## Phase M — MVP  (gate: Tue 2026-07-21 23:59)

**Spec anchors:** §2–§12, §16, §18. **Exit:** platform deployed (staging + prod) with health check; `contracts/v1` both-sided-green; Policy Gateway enforces allowlist/creds/budget/abort (verified against the fake, then live); Red Team + Judge run live vs the target; `./evals/` ≥3 categories with results; `THREAT_MODEL.md` deepened; observability shows inter-agent traces + per-agent cost; requirements matrix committed.

- [ ] **M1a — Local runtime & deployment foundation**  (no external authorization)
  - Files: NEW production-style `Dockerfile`, `compose.yaml` (app + PostgreSQL), `src/config.py` (env-separated config model), `src/health.py` (`/health` liveness + `/ready` DB-connectivity + migration/schema readiness); CI extends P11's `ci.yml` with an ephemeral PostgreSQL service
  - Anchors: §12, **D16**, **O1** · Map: PRD-34 (local half) · Deps: P8 · Est: L
  - Accept: (a) production-style `Dockerfile` builds; `compose.yaml` runs app + PostgreSQL locally; (b) config model with **explicit environment separation** (local/staging/prod); (c) `/health` (process liveness) + `/ready` (DB connectivity + migration/schema readiness); (d) CI runs against an **ephemeral PostgreSQL service**; (e) **invariant (O1):** an **environment-isolation test proves a staging/local config cannot resolve production target credentials**; (f) the **fake TargetAdapter (P9) is the only target available locally** — **no live URL, no live credential, no hosted-model secret**; (g) **MUST NOT contain** domain/data-model migrations, per-agent DB roles, append-only permissions, or queue migrations — those are **M2/M3**
  - Verify: `docker build` + `compose up` healthy; `/ready` reflects DB/migration state; env-isolation test green in CI on the ephemeral PG · Test: **invariant** — staging/local config cannot resolve prod target creds (O1) · Skills: —
  - **Local-complete does NOT satisfy the deployed-URL gate** (that is M1b).

- [ ] **M1b — Full-platform Railway topology + deployment  ⚠ HUMAN AUTH (Railway, secrets)** — DEFERRED (external)
  - Files: Railway config / deploy manifests (future integration work; not changed by M1c)
  - Anchors: §12, **D16** · Map: PRD-34 (deployed half) · Deps: **M1a**, **P11** (deploy-from-GitHub) · Est: M
  - Accept: (a) Railway project with isolated **staging and production** environments; (b) one
    Internet-reachable **Web** service plus private **Runner**, private **Scheduler**, and private managed
    **PostgreSQL** per environment; (c) no public Runner/Scheduler/Postgres endpoint; (d)
    environment-scoped sealed variables by reference, never inline; (e) pre-deploy migrations complete
    before Web/worker promotion; (f) deploy-on-green plus `/health` and `/ready` promotion gates; (g)
    rollback to a previously healthy deployment is rehearsed; (h) deployed URLs are recorded honestly;
    (i) **edge:** staging cannot resolve production target, Clerk Organization, origin, or database
    bindings; (j) **error:** migration or readiness failure blocks promotion without exposing another
    service publicly
  - Verify: staging + production topology inventory; public-port scan; pre-deploy migration, health,
    readiness, and rollback smokes; URLs recorded only after a successful deploy · Test: environment
    isolation + deploy/rollback smoke on Railway · Skills: — · **⚠ HUMAN AUTH (Railway)**

- [x] **M1c — Clerk authentication + custom-permission RBAC foundation**  (local/offline implemented; not deployed)
  - Files: NEW `src/agentforge/auth/`, NEW `tests/auth/`, `pyproject.toml`, authentication/security docs
  - Anchors: identity ADR + `docs/security/AUTHENTICATION.md` · Map: **USR-02/03/04/05/07** · Deps:
    **M1a** · Est: M
  - Accept: (a) official `clerk-backend-api` verifies only `session_token` values networklessly with
    `CLERK_JWT_KEY`; (b) explicit, wildcard-free `CLERK_AUTHORIZED_PARTIES` and exact
    `CLERK_REQUIRED_ORG_ID`; (c) staging rejects production Organization/origin values and production
    rejects HTTP origins; (d) immutable Principal contains only verified user/session/Organization/role
    and custom-permission claims—never a token/header; (e) backend authorization uses custom permissions,
    never role text or client-supplied data; (f) missing/invalid/expired auth → 401, valid identity lacking
    Organization/permission → 403, verifier/config failure fails closed; (g) distinct-approver invariant
    requires `org:campaign:authorize` and a user different from the launcher; (h) authentication never
    constitutes live-campaign authorization; (i) `CLERK_SECRET_KEY` is not required for request auth
  - Verify: deterministic offline RSA-token suite covers missing/malformed/expired/not-yet-valid/bad
    signature/algorithm/authorized-party claims, Organization and permission enforcement, redaction,
    environment isolation, verifier failure, and same-user rejection; prove the suite makes no network
    calls · Test: boundary + invariant cases in `tests/auth/` · Skills: security-best-practices

- [ ] **M1d — Authenticated Railway Web/API/console integration  ⚠ HUMAN AUTH (Clerk + Railway)** — PLANNED
  - Files: future `src/agentforge/app.py` wiring, `console/**` Clerk integration, Railway environment
    variables/configuration (explicitly outside M1c's isolated foundation)
  - Anchors: identity ADR + Railway deployment guide · Map: **USR-01–07** · Deps: **M1b**, **M1c** · Est: M
  - Accept: (a) Clerk restricted/invitation-only access; one required **Headshot** Organization; personal
    accounts and user-created Organizations disabled; MFA required with TOTP plus backup codes available
    (SMS is not the sole factor); (b) backend and frontend publishable keys match the environment; (c)
    only `/health`, `/ready`, and the minimal sign-in/authentication shell and its static assets are
    public; all meaningful console/API/event-stream routes require the backend Principal and exact custom
    permissions; (d) Web is the only public Railway service; (e) the browser never supplies authoritative
    role/permission data; (f) token/header values do not reach logs, traces, errors, event streams, or
    private worker messages; (g) staging cannot authenticate a production origin or Organization; (h)
    live launch/abort/approval still passes the separate campaign Policy Gateway and two-person controls;
    (i) **error:** Clerk outage or invalid configuration cannot make a protected route public
  - Verify: Clerk Dashboard checklist + protected-route matrix + two identities in staging; unauthenticated,
    wrong-org, missing-permission, XSS/log-redaction, SSE leakage, and fail-closed outage tests; inspect
    Railway service exposure and then record actual deployment/CI status · Test: integration/e2e tests
    against staging · Skills: security-best-practices · **⚠ HUMAN AUTH (Clerk + Railway)**
  - **M1 is complete only when M1a–M1d all pass.** M1c can complete offline; M1b/M1d remain incomplete
    until authorized Railway/Clerk configuration and staging verification occur.

- [ ] **M2 — Data model + migrations + per-agent DB roles + indexes**
  - Files: NEW `src/storage/models.py`, `migrations/` (Alembic), `src/storage/roles.sql`
  - Anchors: §6, §7, D6, D7, **D14** · Map: **S1, S2**, PRD-OPT-13/14/15/16 · Deps: **M1a** · Est: L
  - Accept: (a) entities + state machines from **`docs/planning/PRESEARCH.md` §5.2**; (b) **per-agent DB roles** — Red Team INSERT-only staging (no read-back); **Execution Recorder role INSERT-only** on the authoritative append-only AttemptResult table with **append-only enforced by DB permissions (no UPDATE/DELETE grant to any role, Recorder included)**; Judge SELECT-only; (c) indexes on severity/category/target-version; (d) **edge:** adding a VulnReport field migrates existing rows without loss (**expand/contract migrations, destructive ones forbidden alongside their consumers**); (e) **error:** a Red Team (or Recorder UPDATE/DELETE) write to the authoritative AttemptResult table is **DB-rejected**
  - Verify: migration up/down on a fixture DB; role-permission suite · Test: **invariant** — Red-Team write / any UPDATE/DELETE on the append-only AttemptResult table → DB rejection (S1/S2); migration round-trip preserves rows · Skills: —

- [ ] **M3 — SKIP LOCKED queue with full delivery semantics**
  - Files: NEW `src/storage/queue.py`, migration for `jobs` · Anchors: §6, §11, D6, **F6** · Map: PRD-OPT-14 · Deps: M2 · Est: M
  - Accept: (a) `SKIP LOCKED`, two logical queues + priority; (b) at-least-once, lease expiry, heartbeat, reaper, dead-letter, idempotency+dedup on `{campaign_run_id, attempt_id}`, cancellation, poison handling; (c) no long work in the claim txn; (d) **edge:** depth via `count(*)` + backpressure (cost governor throttles); (e) **error:** expired lease reaped + re-queued (not lost); poison → dead-letter after N
  - Verify: concurrency test (no double-claim); reaper test (kill mid-lease → reappears) · Test: **invariant** — no job zero-delivered or double-committed · Skills: —

- [ ] **M4 — Policy Gateway + Execution Recorder (verified against the fake)**
  - Files: NEW `src/policy/gateway.py`, `src/policy/recorder.py`, `src/policy/allowlist.py`, `src/policy/credentials.py`
  - Anchors: §5, **D14**, F2, F5 · Map: **S1, S2, S3**, PRD-27, PRD-OPT-12 · Deps: M2, **P9** (fake), **P10**, **P5** · Est: L
  - Accept: (a) enforces allowlist + per-target scoped creds + synthetic-data + budget + rate + **hard abort**, in **runtime code independent of trigger** (Claude/direct/cron); (b) emits a **canonical-hash, append-only AttemptResult** with a per-dispatch `campaign_run_id`; (c) the Red Team path holds **no credentials**; (d) **edge:** `UNIQUE(campaign_run_id, attempt_id)` rejects a replay (S3); gated publish idempotent; (e) **error:** target-unreachable/budget/rate raise typed errors → backoff→queue→abort; off-allowlist denied + audited. **Verified against the deterministic fake (P9)** — live target only after M5.
  - Verify: fake campaign passes the gate; off-allowlist denied; a cron-triggered run enforced identically to a Claude-triggered one · Test: **invariant** — no call without the gate; **boundary** — budget/rate trip abort; **error** — replayed AttemptResult rejected · Skills: **authorized-live-campaign** (P5)

- [ ] **M5 — OpenEMR TargetAdapter + live integration  ⚠ HUMAN AUTH (live target, creds)**
  - Files: NEW `src/target/openemr_adapter.py`, allowlist entry · Anchors: §2, §5 · Map: PRD-01 · Deps: **P9**, **M4**, **D1** · Est: M
  - Accept: (a) OpenEMR impl of the P9 interface, target #1 only; (b) reached **only** through the gateway; API-primary + thin UI/e2e; (c) per-target credential binding, secrets by reference; (d) **edge:** live integration performed **only after** both the interface/fake (P9) and the gateway (M4) exist and pass against the fake; (e) **error:** adapter errors → typed `adapter-error`
  - Verify: a real attempt round-trips generator→gateway→adapter→target→recorder→AttemptResult · Test: adapter contract test (same suite as the fake); **error** — injected failure → typed error · Skills: — · **⚠ HUMAN AUTH**

- [ ] **M6a — Provider-neutral local observability core**  (no external account)
  - Files: NEW `src/observability/tracing.py` (OTEL interfaces + local/no-op/console exporter), `src/observability/coverage_view.sql`, `src/observability/alerts.py` (interfaces), `src/observability/reconcile.py`
  - Anchors: §9, §13, **D5** · Map: **S6, S9, O3, O6, O7**, PRD-25/26 (local half) · Deps: M2 · Est: L
  - Accept: (a) **OpenTelemetry instrumentation + interfaces** with a **local/no-op/console exporter** for tests (no external account); (b) durable `campaign_id/attempt_id/finding_id` correlation IDs as span attributes **and** row columns (O6); (c) **Postgres authoritative source-of-record views** (Q3/Q4 SoR split); (d) **S9:** hash reconciliation between the authoritative `AttemptResult.content_hash` and the trace representation — **a mismatch marks the run degraded**; (e) coverage from **hash-verified, nonce-deduped verdicts only** + sanity invariants (S6); (f) **alert interfaces + deterministic tests**; (g) **Langfuse-unavailable fallback (O7)** → Postgres-derived coverage/priority (never random/blocked); (h) **synthetic data only**
  - Verify: tests run with the console/no-op exporter (no account); kill-Langfuse fallback derives coverage from Postgres; hash mismatch → degraded; alert fires deterministically · Test: **invariant** — coverage can't flip "covered" without N verified attempts + ≥1 oracle/human case (S6); **invariant** — hash mismatch → degraded (S9) · Skills: —

- [ ] **M6b — Langfuse Cloud integration  ⚠ HUMAN AUTH (Langfuse account)** — DEFERRED (external)
  - Files: extend `src/observability/tracing.py` (Langfuse OTEL exporter)
  - Anchors: §9, **D5** · Map: PRD-25/26 (cloud half) · Deps: **M6a** · Est: M
  - Accept: (a) **Langfuse Cloud (Hobby)** project; (b) credential binding **by secret reference** (never inline); (c) OTEL export to Langfuse; (d) **live trace verification** (inter-agent order); (e) **per-agent cost visibility**; (f) **cloud-unavailable fallback verified** (degrades to M6a's Postgres path); (g) **no PHI or secret leakage into traces**
  - Verify: a live run shows inter-agent traces + per-agent cost in Langfuse; cloud-outage falls back to Postgres; traces carry no PHI/secret · Test: fallback + no-leak checks · Skills: — · **⚠ HUMAN AUTH (Langfuse)**
  - **M6 is complete only when BOTH M6a and M6b pass.** M9 may build against **M6a** locally (fake-backed); the **MVP observability gate still requires M6b**.

- [ ] **M7 — Deepen the threat model against the live target  ⚠ HUMAN AUTH (live probing)**
  - Files: extend `THREAT_MODEL.md` · Anchors: THREAT_MODEL, §5 · Map: PRD-04/05/06, **F8** · Deps: M5, **P2** · Est: M
  - Accept: (a) each of the 6 categories gets measured surface/impact/difficulty/existing-defenses from live probing; (b) OWASP **2021** web tags + LLM 2025 tags as `{framework,version,id,name}`; (c) **edge:** not-exercisable categories marked with reason; (d) **error:** no unobserved defense asserted as present
  - Verify: ~500-word summary; every category has a live-probe note or not-exercisable tag · Test: — · Skills: **threat-model** (P2) · **⚠ HUMAN AUTH**

- [ ] **M8 — Red Team agent (generation + coverage-driven mutation loop)  ⚠ HUMAN AUTH (hosted-OSS account/creds/budget)**
  - Files: NEW `src/agents/red_team/` · Anchors: §3, §8, §16, F2 · Map: PRD-14/17, **F7** · Deps: **P10**, **M4**, **P3** · Est: L
  - Accept: (a) generates + **autonomously mutates** partial successes across multi-turn sequences; (b) **MVP inference = hosted-OSS uncensored** (per decision 2026-07-20; OpenRouter/Together, behind a scoped credential + gateway budget/rate cap) — local Mac remains the F7 config switch; (c) reaches the target **only** via the gateway, no creds of its own, no evidence; (d) **edge:** a partial spawns N variants toward the least-covered category; hosted-OSS spend is bounded by the gateway budget cap (M4); (e) **error:** a refusal/empty generation is retried/switched, not a silent stall; a budget-cap breach aborts, not overruns
  - Verify: a seeded partial produces mutated variants; no direct target call bypasses the gateway · Test: **boundary** — multi-turn, not single-prompt; mutation raises targeted-category coverage · Skills: **adversarial-eval-lifecycle** (P3)

> ### 🔒 MVP Judge non-oracle safety rule (binding — do not weaken for schedule)
> Because the full M10 calibration/drift system is **FINAL-COMMITTED**, the MVP Judge operates under a
> phased, fail-closed constraint:
> 1. **Deterministic oracle/canary evidence may still produce `EXPLOIT_CONFIRMED`** — this path is
>    unaffected and always available.
> 2. The MVP Judge **must NOT issue an LLM-only `EXPLOIT_LIKELY` or `NO_EXPLOIT_OBSERVED` from
>    uncalibrated thresholds.**
> 3. A **minimum ground-truth calibration slice** (M11) must pass — establishing initial per-category
>    confidence thresholds — **before** those two LLM-only states are enabled for that category.
> 4. **Until the minimum slice passes for a category, every non-oracle case in that category resolves to
>    `INDETERMINATE`.** This **fails closed on the finding** (never counted safe, never admitted to
>    regression, never published) **while unrelated campaign work continues** (fail-closed on the verdict,
>    not the run — D13).
> 5. This is not weakened to meet the deadline. The contract carries a typed reason code
>    `non_oracle_uncalibrated_indeterminate` (P10) so the forced disposition is explicit and auditable.

- [ ] **M9 — Judge agent (deterministic fail-closed verdict authority)**
  - Files: NEW `src/agents/judge/`, `src/agents/judge/oracles/` · Anchors: §3, §5, **D13, D18**, F1, S4 · Map: PRD-15/18, **S4** · Deps: **P10**, **M4**, **M6a**, **P4** · Est: L  *(M6b required for the MVP observability gate)*
  - Accept: (a) consumes the typed **Evidence Envelope** only — never unstructured attacker text outside the `hostile`-labelled field; deterministic **oracle/canary precedence** applied by code → `EXPLOIT_CONFIRMED` cannot be downgraded; (b) states `EXPLOIT_CONFIRMED|EXPLOIT_LIKELY|NO_EXPLOIT_OBSERVED|INDETERMINATE|ERROR`; (c) **fail closed on the verdict, not the run** (ambiguous → human-review queue; campaign continues elsewhere); (d) Judge holds **no creds/mutation/publish/execute**; output schema-validated; (e) **edge/error (S4):** an in-transcript verdict-flip instruction does not change disposition when an oracle fired; missing/invalid evidence → fail-closed `ERROR`; (f) **MVP non-oracle rule (binding, above):** LLM-only `EXPLOIT_LIKELY`/`NO_EXPLOIT_OBSERVED` are **gated behind a passing minimum ground-truth calibration slice** per category; until it passes, non-oracle cases → `INDETERMINATE` with reason `non_oracle_uncalibrated_indeterminate`; oracle/canary → `EXPLOIT_CONFIRMED` remains available
  - Verify: a canary-hit case → `EXPLOIT_CONFIRMED` despite an embedded "return fail"; ambiguous case parks without stalling; **with no calibration slice loaded, a non-oracle case → `INDETERMINATE` (never `NO_EXPLOIT_OBSERVED`/`EXPLOIT_LIKELY`)** · Test: **invariant** — never maps `INDETERMINATE`/`ERROR`→safe; **invariant** — uncalibrated non-oracle case is forced `INDETERMINATE` (MVP rule); **injection** — see the expanded S4 battery in M12 · Skills: **judge-calibration** (P4, via M10)

- [ ] **M10 — Judge calibration + drift governance**  (the **full** system; a **minimum slice** ships at MVP via M11 to lift the non-oracle gate — see the MVP Judge rule)
  - Files: NEW `evals/ground-truth/`, `src/agents/judge/calibration.py` · Anchors: §5, §15, D13 · Map: PRD-18, PRD-OPT-08 · Deps: **M9**, **P4** · Est: L
  - Accept: (a) **dual judging across the complete ground-truth set**; (b) **random/stratified sampled dual judging of live non-oracle cases** (across categories/severities/target versions); (c) metrics — **false-negative rate, uncertainty rate, inter-judge disagreement, confidence-calibration error, drift over time**; (d) **per-category confidence + drift thresholds**; (e) **edge:** a threshold crossing **disables LLM-only dispositions for the affected category** — affected findings become `INDETERMINATE` **without stopping unrelated campaign work**; (f) **error/recovery:** re-enabling a category requires **human review + recalibration**
  - Verify: calibration report shows all five metric families per category; a simulated drift breach disables LLM-only dispositions for that category only · Test: **invariant** — drift breach → category LLM-only disabled + others unaffected; ground-truth dual-judge agreement computed · Skills: **judge-calibration** (P4)

- [ ] **M11 — Eval suite: ≥3 categories, schema-strict, with results  [HARD GATE]**
  - Files: NEW `evals/seeds/`, `evals/results/`, `evals/fixtures/` (synthetic), `src/storage/validators.py`
  - Anchors: §6, §10, §18 · Map: **PRD-07/08/09/28**, PRD-OPT-01/13 · Deps: **M8**, **M9**, **P3** · Est: L
  - Accept: (a) seeds across **≥3 distinct categories** with the full **AttackCase field set** (cat/subcat, input sequence, expected-safe, observed pass/fail/partial, severity+exploitability, add-to-regression flag, OWASP tags, boundary|invariant|regression class); (b) `validate-eval-case` + `detect-duplicate-sequence` in the agent **and** CI; (c) **edge:** every case exercises a boundary/invariant/regression — **no happy-path-only**; (d) **error:** a case missing a field or duplicating a sequence is rejected; (e) **minimum ground-truth calibration slice (MVP Judge rule):** a labelled per-category slice sufficient to establish initial confidence thresholds ships here — it is the gate that lifts the non-oracle `INDETERMINATE` fallback (M9); a category with no passing slice stays gated
  - Verify: `./evals/` produces pass/fail/partial for ≥3 categories vs the **live** target; validator rejects a malformed case in CI; the minimum calibration slice establishes per-category thresholds (or the category remains `INDETERMINATE`-gated) · Test: **invariant** — Judge never approves a confirmed exploit across the suite; **invariant** — a category without a passing calibration slice yields only oracle-`EXPLOIT_CONFIRMED` or `INDETERMINATE` (MVP rule); **regression** — a fixed case that reappears is caught · Skills: **adversarial-eval-lifecycle** (P3), **judge-calibration** (P4)

- [ ] **M12 — Platform testing + CI substrate + invariant/injection battery (S2, S3, S4, S5, S9)**
  - Files: NEW `tests/{unit,integration,invariant,injection}/`, uses `src/target/fake_adapter.py` (P9), cassettes
  - Anchors: §18, **O4, O8** · Map: **S2, S3, S4, S5, S9**, PRD-24 · Deps: **M1a**, **P10**, **P9**, **M9** (Judge injection battery) · Est: L
  - Accept: (a) the **CI substrate first** (ephemeral Postgres + the P9 fake + cassette model responses — SLO measured on fixtures, never the live target/paid APIs) — this substrate has no SUT dependency and lands early; (b) unit/boundary tests for the four BUILD capabilities; (c) **Judge-side S4 battery (needs M9):** (i) non-oracle hostile transcripts with fixed ground truth; (ii) rubric-rewrite + confidence-manipulation instructions; (iii) attempts to populate `trusted` Evidence-Envelope fields from hostile content; (iv) oversized/truncated hostile content; (d) **each invariant/injection test lands with its system under test** — S2 DB-rejection→M2, S3 replay→M4, S4-Judge→M9, S5 vendor-disjoint→M13, S9 hash-mismatch→M6; **the S4 Documentation doc-control tests (report fields/status/severity/remediation/publication/operator instructions) land with F2 at Final** (not here — Documentation does not exist until F2); (e) **error:** CI fails on any invariant regression
  - Verify: `pytest` matrix green on fixtures; no CI job hits the live target/paid APIs · Test: the invariant/injection suite (Judge-side at MVP; Documentation-side at F2) · Skills: bug-hunt (as needed)

- [ ] **M13 — Run-start guards (S5 vendor-disjoint)**
  - Files: NEW `src/policy/run_guards.py` · Anchors: §8, D8 · Map: **S5** · Deps: **P10** (config); exercised by M9/F1 · Est: S
  - Accept: (a) at run start, enforce **`Judge.vendor != Documentation.vendor`**; (b) on violation, **fail closed** or select a **vendor-disjoint fallback** (Judge→third vendor, or move Documentation off the shared vendor); (c) **edge:** the Judge→GPT-5.4 fallback with Documentation=GPT-5.4 triggers the guard; (d) **error:** an unresolved vendor collision aborts the run + emits an alert
  - Verify: a forced collision aborts or re-routes; disjoint config passes · Test: **invariant** — no run proceeds with `Judge.vendor == Documentation.vendor` (S5) · Skills: —

- [ ] **M14 — Requirements matrix**  ∥
  - Files: NEW `docs/requirements/REQUIREMENTS_MATRIX.csv` · Anchors: gap-audit §2 · Map: PLAN §6 · Deps: none · Est: S
  - Accept: (a) every PRD requirement → artifact/test/checkpoint/evidence; (b) **edge:** no blank cell; (c) **error:** a graded deliverable with no producing task flagged · Verify: rows = 37 + 18; machine-readable · Test: — · Skills: evidence-audit (P7, at Final)

- [ ] **M15 — README + deployed URL  ⚠ HUMAN AUTH (Railway URL)**  ∥
  - Files: extend `README.md` · Anchors: §2, §19 · Map: PRD-29/34 · Deps: **M1d**, M5 · Est: S
  - Accept: (a) setup + arch overview + **deployed link** only after M1d verification + run-vs-live-target
    instructions; (b) public/protected route model and Clerk prerequisites documented; (c) **edge:**
    synthetic-data + no-real-PHI stated and authentication distinguished from campaign authorization;
    (d) **error:** pending/degraded deployment is never described as live or green · Verify: clean-checkout
    reproduction after **M1d**; until then the deployed URL remains explicitly pending · Test: — · Skills:
    — · **⚠ HUMAN AUTH**

---

## Phase F — Final  (gate: Fri 2026-07-24 12:00)

**Spec anchors:** §3, §9–§15, §18, §19. **Exit:** Orchestrator + Documentation live; regression harness with tiered runs + SLO in CI; ≥3 vuln reports; measured cost analysis; triage report; ATO packet; integration packet; perf baselines + load test; two-person human gate; demo video; social post.

- [ ] **F1 — Orchestrator (governor) + S5 enforcement**
  - Files: NEW `src/agents/orchestrator/` · Anchors: §3, §9, §11, §13 · Map: PRD-14/19, **S5, S6** · Deps: M3, **M6a**, M8, M9, **M13** · Est: L
  - Accept: (a) reads **verified** coverage/findings/budget → prioritizes; triggers regression; **cost governor + circuit-breaker**; (b) does **not** generate attacks or render verdicts; (c) enforces the **S5 run-start vendor-disjoint guard** (M13) before dispatch; (d) **edge:** no-priority → fallback (least-covered → oldest open → regression sweep); (e) **error:** no-signal spend → breaker halts/redirects + alert; Langfuse-down → Postgres fallback (O7)
  - Verify: overnight-style loop prioritizes least-covered; a no-signal spend trips the breaker; a vendor collision aborts the run · Test: **invariant** — never trusts an unverified coverage aggregate (S6); **error** — breaker fires at threshold · Skills: —

- [ ] **F2 — Documentation agent (gated, sanitized)**
  - Files: NEW `src/agents/documentation/` · Anchors: §3, §6, §14, **D18** · Map: PRD-20/21/22, **S4** · Deps: M9, **P10**, **P6** · Est: L
  - Accept: (a) confirmed exploit → **VulnReport** with all 6 PRD-21 fields; (b) renders from **validated Verdict + sanitized excerpts by default** — raw evidence quarantined behind a warned operator action; (c) data-quality validated before write; (d) **edge (PRD-22):** reproducible by a senior engineer from the report alone; (e) **error:** **human approval required before a critical publish**; hostile content cannot control any report field/status/severity/remediation/publication/operator instruction (S4 doc battery, M12)
  - Verify: a confirmed exploit → schema-valid report; a critical report blocks on the gate; a doc-injection attempt controls no field · Test: **invariant** — no critical publish without approval; **injection** — hostile content laundering blocked (S4) · Skills: **vuln-report** (P6)

- [ ] **F3 — Human approval gates + two-person rule**
  - Files: NEW `src/policy/approval.py`, audit-log wiring · Anchors: §14, **S7** · Map: PRD-27,
    **USR-03/04/07** · Deps: M3, F2, **M1c, M1d** · Est: M
  - Accept: (a) critical-publish + remediation gates runtime-enforced; (b) authenticated Principal has the
    exact Headshot Organization and `org:campaign:authorize` custom permission; (c) **two-person rule** —
    `approver_user_id != launcher_user_id`, with both verified identities in the append-only audit log;
    (d) role labels and client-supplied identity/permission text have no authority; (e) there is no
    single-operator bypass—lack of a distinct authorized Approver leaves the operation blocked; (f)
    authentication alone never authorizes the campaign; (g) **error:** self-approval is rejected even when
    that user has the Approver role and permission
  - Verify: launcher-only critical action rejected; a different authenticated Approver succeeds + both
    identities are audited · Test: **invariant** — self-approval rejected for critical (S7) · Skills:
    security-best-practices

- [ ] **F4 — Regression & validation harness (tiered) + SLO-in-CI promotion**
  - Files: NEW `src/regression/`, `evals/regressions/` · Anchors: §10, **O5** · Map: PRD-23/24, PRD-OPT-16 · Deps: M3, M9, M11, **P3** · Est: L
  - Accept: (a) versioned store + deterministic replay; auto-run on Orchestrator trigger / **cron** / target change (new `campaign_run_id`, re-executes live — never reuses a verdict); (b) detects a reappearing fixed vuln + a cross-category regression; (c) **admission invariant** — admitted only if it reproduces deterministically **and** passes for the right reason; (d) **edge (O5):** **stratified** — every critical + recently-reopened case on every target change; sample lower/older; full suite on cadence; verdict caching bounded by `target_version` + case-content hash; (e) **error:** a wrong-reason pass is **not** admitted; **two-number SLO (full-suite + per-change critical subset) is the promotion gate verified in CI** (moved here from deploy)
  - Verify: a re-introduced vuln caught; a wrong-reason pass rejected; SLO check green in CI on fixtures · Test: **regression** — fixed→reappear caught; **invariant** — wrong-reason pass rejected (PRD-24) · Skills: **adversarial-eval-lifecycle** (P3), eval-triage

- [ ] **F5 — Cost analysis @ 100/1K/10K/100K runs (deterministic script/template — NOT a skill)**
  - Files: NEW `docs/cost/COST_ANALYSIS.md`, `scripts/cost_model.py` (template) · Anchors: §11, **D17** · Map: PRD-33, **F4-finding** · Deps: **M6a**, F1 · Est: M
  - Accept: (a) **two independent line families** — hosted = measured tokens × current rates (cache+batch adjusted); local = amortized capacity; hosting/storage/egress separate; **never tokens × N**; (b) per-tier architectural change named at each of 100/1K/10K/100K; (c) **measured** per-agent token profiles + Mac tok/s + `exploit_rate` from real traces + CI/dev line (O8); (d) **edge:** the invalid `list_price ÷ throughput` framing is absent; (e) **error:** no placeholder presented as measured
  - Verify: numbers trace to real trace records; dimensional sanity per line · Test: — · Skills: — *(deterministic cost script + template, not a skill)* · **Blocked-until:** token profiles / Mac tok/s / exploit_rate measured (`open question` §17)

- [ ] **F6 — ≥3 vulnerability reports**
  - Files: NEW `docs/vulnerabilities/*.md` · Anchors: §6, §19 · Map: PRD-32 · Deps: F2, M11, **P6** · Est: M
  - Accept: (a) ≥3 distinct reports in the VulnReport schema with clinical impact + minimal repro; (b) **edge:** each reproducible by a senior engineer not present (PRD-22); (c) **error:** no duplicate attack-sequence report · Verify: independent reproduction of each · Test: reproduction check per report · Skills: **vuln-report** (P6)

- [ ] **F7 — Triage exercise (10+ findings)**
  - Files: NEW `docs/triage/scan_report.md` · Anchors: §19 · Map: PRD-OPT-03 · Deps: F2, **P6** · Est: M
  - Accept: (a) simulated scan report with **≥10 findings across critical/high/medium/false-positive**; (b) validate/remediate/defer/document per finding; (c) **edge:** false positives explicitly dispositioned; (d) **error:** reuses the VulnReport schema · Verify: 10+ findings, all four categories, each dispositioned · Test: — · Skills: **vuln-report** (P6, triage mode)

- [ ] **F8 — ATO-style evidence packet**
  - Files: NEW `docs/evidence/ato/` · Anchors: §19 · Map: PRD-OPT-07 · Deps: **M1d**, M12, F2,
    **P7** · Est: L
  - Accept: (a) arch + data-flow diagram, **two distinct auth-model matrices** (human Principal → route →
    Clerk custom permission, and workload/agent → callable target → credential via the Policy Gateway),
    **dependency list with versions**, **self-scan** (Semgrep + the platform's eval suite run against
    itself), authentication/deployment test evidence, **incident/postmortem** from §13; (b) **edge:**
    distinct artifact from `ARCHITECTURE.md`; (c) **error:** no unversioned dependency or unverified
    authentication/deployment claim · Verify: packet assembled after M1d + cross-checked vs the matrix ·
    Test: self-scan produces real evidence · Skills: **evidence-audit** (P7)

- [ ] **F9 — Integration packet**
  - Files: NEW `docs/integration/` · Anchors: §4, §19 · Map: PRD-OPT-05/09 · Deps: **P10**, M11, **P1** · Est: M
  - Accept: (a) interface diffs incl. the **F2 `RedTeam→Judge`→mediated-chain** correction + migration note; (b) both-sided contract-test results; dependency map; **e2e trace** proving end-to-end correctness; (c) **edge:** demonstrates consuming an agent via the published contract alone; (d) **error:** any contract correction has an ADR + migration note · Verify: e2e trace reconstructs a finding's full lineage (§6) · Test: both-sided contract tests attached · Skills: **contract-steward** (P1), **evidence-audit** (P7)

- [ ] **F10 — Perf baselines + load/stress test  ⚠ HUMAN AUTH (live load testing)**
  - Files: NEW `docs/performance/{baselines,load_test}.md`, `scripts/loadtest.py` · Anchors: §11, §19 · Map: PRD-OPT-17/18 · Deps: M11, F1, **P5** · Est: L
  - Accept: (a) **baselines** CPU/mem/latency/throughput under a representative run (100 cases + full regression), on Railway; (b) **load test** 100 consecutive cases vs the live target recording agent-orchestration latency, LLM-call latency, exploit-storage throughput; (c) identify the bottleneck + name the §11 remediation; (d) **the run goes through `authorized-live-campaign`** — acceptance **must include target authorization, allowlist validation, synthetic-data confirmation, scoped credentials, budget cap, rate cap, timeout, monitoring, and hard abort**; (e) **error:** exceeding a cap aborts the run
  - Verify: baseline + load metrics committed; bottleneck named; the run shows the full authorized-live-campaign gate trace · Test: — (measurement) · Skills: **authorized-live-campaign** (P5) · **⚠ HUMAN AUTH**

- [ ] **F11 — Observability dashboards (the six questions, live)**  ∥
  - Files: extend `src/observability/`, NEW dashboard config · Anchors: §9 · Map: PRD-25/26, O3 · Deps:
    **M6a**, **M6b**, F1, **M1d** · Est: M
  - Accept: (a) all six questions answerable for an authenticated, custom-permission-authorized human
    **and** the Orchestrator; resilience trend live; (b) console/event streams expose no token, header,
    secret, or unauthorized finding/evidence; (c) **edge:** alert conditions active (approval-pending SLA,
    regression/reopen, budget breaker, target-unreachable, queue-depth, emission failure); (d) **error:**
    alerts tied to the durable source, not Langfuse alone · Verify: each question returns a real authorized
    answer; an alert fires end-to-end; observer/auditor boundaries tested · Test: access-control + no-leak
    tests · Skills: security-best-practices

- [ ] **F12 — AI-use disclosure + evidence-audit completeness**  ∥
  - Files: verify `ARCHITECTURE.md` §15 current; NEW `docs/evidence/AUDIT_SUMMARY.md` · Anchors: §15 · Map: PRD-OPT-08 · Deps: F8, F9, **P7** · Est: M
  - Accept: (a) AI-use disclosure lists every AI role + its verification/human gate + residual incl. how a drifting Judge is detected/corrected; (b) **edge:** ATO + integration packets audited complete vs the matrix; (c) **error:** any missing graded deliverable surfaced before submission · Verify: completeness report shows no missing graded item · Test: — · Skills: **evidence-audit** (P7)

- [ ] **F13 — Demo video + social post  ⚠ HUMAN AUTH (social publication)**
  - Files: NEW `docs/submission/` · Anchors: §19 · Map: PRD-31/35 · Deps: F1, F4, F6 · Est: M
  - Accept: (a) 3–5 min video demonstrating **live attacks against the deployed target** + key decisions; (b) social post on X/LinkedIn tagging **@GauntletAI**; (c) **edge:** the demo shows the loop learning, not a single jailbreak; (d) **error:** no real PHI on screen · Verify: video runs the live platform; post published · Test: — · Skills: interview-prep (adjacent) · **⚠ HUMAN AUTH (publication)**

- [ ] **F14 — Devlog / project story (cross-cutting)**  ∥
  - Files: `docs/DEVLOG.md`, `docs/PROJECT_STORY.md` · Anchors: — · Map: process · Deps: runs at every phase boundary · Est: S
  - Accept: (a) every decision/pivot/finding logged; (b) **edge:** grounded in git history; (c) **error:** the story reads coherently start-to-finish · Verify: story reconstructs the build · Test: — · Skills: **devlog**

---

## F/S/O control → implementing + verifying task (runtime findings)

| Finding | Implementing task(s) | Verifying task/test | Status |
|---|---|---|---|
| **F1** Judge deterministic invariant | M9 | M9 invariant + M12 | mapped |
| **F2** Trust split / recorder | M4 (P9 interface) | M4 + M12 | mapped |
| **F3** Langfuse Cloud MVP | M6b (config) | M6b | mapped |
| **F4** Cost two-line model | F5 | F5 | mapped |
| **F5** Runtime live-campaign gate | M4 | M4 invariant | mapped |
| **F6** Queue delivery semantics | M3 | M3 invariant | mapped |
| **F7** Hosted-OSS Red Team default | M8 (config), M1a | M8 | mapped |
| **F8** OWASP 2021 tags | M7, M11 | M11 schema check | mapped |
| **F9** PLAN.md stale content | — | — | **COMPLETED (doc-only)** |
| **F10** tdd-swarm gated | — | — | **COMPLETED (doc-only)** |
| **F11** Defense status labels | — | D2 review | **COMPLETED (doc-only)** |
| **F12** Promptfoo owasp:web | — | D2 review | **COMPLETED (doc-only)** |
| **S1** Evidence integrity (hash, no sign) | M2, M4 | M2/M4 + M12 | mapped |
| **S2** Per-agent DB roles (append-only) | M2 | M2 invariant + M12 | mapped |
| **S3** Run-nonce / replay | M2 (UNIQUE), M4 | M4 + M12 | mapped |
| **S4** Evaluator-injection containment | M9, F2, P10 (envelope) | M12 Judge battery (4 cases) + F2 Documentation doc-control battery | mapped |
| **S5** Judge.vendor ≠ Doc.vendor | M13, F1 | M12 + F1 | mapped |
| **S6** Verified coverage only | M6a, F1 | M6a invariant | mapped |
| **S7** Two-person rule | M1c (identity separation), F3 (runtime gate) | M1c/F3 invariants | mapped |
| **S8** Canary provisioning / honesty | D1, M5, M9/M10 | M7 + M10 | mapped |
| **S9** Hash reconciliation | M6a | M6a invariant | mapped |
| **O1** Environments | M1a (local) + M1b/M1d (Railway + Clerk) | M1a + M1c/M1d isolation tests | mapped |
| **O2** Expand/contract + drain + PITR | M2 (expand/contract), M1b (drain/PITR) | M2 migration test | mapped |
| **O3** Alerting | M6a, F11 | M6a/F11 | mapped |
| **O4** Platform testing | M12 | M12 | mapped |
| **O5** Stratified regression | F4 | F4 | mapped |
| **O6** Correlation IDs | M6a | M6a | mapped |
| **O7** Langfuse-down fallback | M6a, F1 | M6a invariant | mapped |
| **O8** CI substrate + cost line | M12 (+ M1a ephemeral PG), F5 | M12 | mapped |

Every **runtime** F/S/O finding has an implementing + verifying task. F9–F12 are documentation-only and already **COMPLETED** (committed `6e592ea`/`2557e4b`/`bca61e2`).

## Deliverables map (graded deliverable → producing task)

| Deliverable | PRD | Phase · Task |
|---|---|---|
| Deployed target URL (every checkpoint) | PRD-01/34 | D·D1, M·M1b/M5/M15, F |
| `THREAT_MODEL.md` (6 cats + OWASP) | PRD-04/05/06 | D (first pass ✓) · M·M7 |
| `ARCHITECTURE.md` + diagram | PRD-10/11/12/13 | ✓ finalized · diagram D·D3 |
| `USERS.md` | PRD-30 | ✓ (arch-draft) |
| Eval suite ≥3 cats + ≥1 live agent | PRD-07/08/09/28 | M·M8/M9/M11 |
| Contracts + typed errors + tests | PRD-OPT-04/06/10/11 | M·P10 |
| Build-vs-configure ADR | PRD-OPT-02 | ✓ · confirm D·D2 |
| Boundary/invariant/regression test design | PRD-OPT-01 | M·M11/M12 |
| Data-quality checks | PRD-OPT-13 | M·M2/M11, F·F2 |
| Migrations / queue / workflow state | PRD-OPT-14 | M·M2/M3 |
| Data model + access control | PRD-OPT-15 + USR-02/03 | M·M1c/M1d/M2, F·F3 |
| SQL indexes + regression SLO in CI | PRD-OPT-16 | M·M2, F·F4 |
| ≥3 vulnerability reports | PRD-32 | F·F6 |
| Triage report (10+ findings) | PRD-OPT-03 | F·F7 |
| ATO evidence packet | PRD-OPT-07 | M·M1d → F·F8 |
| Integration packet | PRD-OPT-05/09 | F·F9 |
| Baselines + load test | PRD-OPT-17/18 | F·F10 |
| Cost analysis @ runs | PRD-33 | F·F5 |
| Observability layer (6 questions) | PRD-25/26 | M·M6a+M6b, F·F11 |
| Regression harness | PRD-23/24 | F·F4 |
| AI-use disclosure | PRD-OPT-08 | ✓ §15 · verify F·F12 |
| Rate limits / auth / backoff-queue-abort | PRD-OPT-12 | M·M4 (+ §5/§11) |
| Human approval gates | PRD-27 + USR-04/07 | M·M1c/M1d → F·F3 |
| README (deployed link) | PRD-29 + USR-01/02 | M·M1d → M15 |
| Demo video · social post | PRD-31/35 | F·F13 |

## Critical path & parallel workstreams

- **Critical path → MVP (local):** `P8 → M1a → M1c` (runtime + authentication foundations) and
  `P8 → P10` (needs `P1`) `→ M2 → M4` (needs `P9`,`P5`) `→ M9` (needs `M6a`,`P4`) `→ M11`
  **[hard gate]**. After `M2`: `M3` and `M6a` proceed in parallel.
- **External halves are deferred (do not block local foundations):** `M1b` (Railway ⚠) + `M1d`
  (authenticated integration ⚠), `M6b` (Langfuse ⚠), `M5`/`M7` (live target ⚠, need `D1`), `M8`
  (hosted-OSS ⚠).
- **Critical path → Final:** `M1c → M1d → F3/F8/F11`; independently, `M9/M11 → F4` and `→ F1`
  (Orchestrator) `→ F2` (Documentation) `→ F6/F8/F10 → F13`.
- **Fully parallel, done or start-now (local, no ext auth):** `P1–P7` skills ✅, `P8` scaffold ✅, `P9` fake ✅, `P10` contracts ✅, `M14` matrix, `D2` dry-run, `F14` devlog. `D1` target-readiness (⚠) unblocks `M5`/`M7`. **`D3` is off the critical path** — a pre-presentation gate on `wip/d3-diagram`.
- **Bottlenecks:** `P10` (contracts ✅) gates all agents; `M1a` gates `M2` and `M1c`; `M1c` gates
  every meaningful human-facing route and two-person approval; `M4` (gateway) gates all live work; `M6a`
  gates the Judge's evidence-integrity + the Orchestrator's learning signal. Land
  `M1a → M1c/M2 → M4/M6a` first.
- **The DEPLOYED MVP gate (authenticated deployed URL + live traces + live eval results) needs the
  EXTERNAL halves — `M1b`, `M1d`, `M6b`, `M5`, `M8` — and stays incomplete until those authorizations
  land.** Local foundations (`M1a`, `M1c`, `M2`, `M3`, `M4`, `M6a`) are fully buildable now,
  fake-backed/offline as applicable.

## Account & external blockers (classified — 2026-07-21)

Each blocker is scoped to exactly what it blocks; none is used to claim the **local** architecture is
technically blocked. The GitHub-protection requirement imposed by `CLAUDE.md`/`tdd-swarm` is **not**
bypassed.

| Blocker | Blocks | Does NOT block |
|---|---|---|
| **GitHub branch protection** (private repo needs Pro/public — 403) | the repository-approved **`tdd-swarm` execution workflow** | local design/plan work |
| **Gauntlet Labs GitLab auth** | **dual-remote checkpoint parity** (a repo policy, `CLAUDE.md` dual-remote law) | **intrinsic `tdd-swarm` prerequisites** — GitLab parity is a policy gate, not a swarm precondition |
| **Railway authorization** | **M1b/M1d** (private-service topology, authenticated deploy, deployed URLs) | **M1a/M1c** local runtime + auth foundations |
| **Clerk Dashboard authorization** | **M1d** (restricted mode, Headshot Organization, MFA, role/permission assignments, environment keys) | **M1c** offline verification/RBAC foundation |
| **Langfuse authorization** | **M6b** (cloud traces, per-agent cost) | **M6a** local observability core |
| **D1 inputs / live authorization** | **D1, M5, M7, and live eval results** | fake-backed foundations `M1a/M2/M3/M4/M6a` |
| **Hosted-OSS credentials/budget** | **live M8 inference** | building M8's mutation loop against the fake |

**GitLab, Railway/Clerk access, and D1 are NOT reasons to call the local architecture blocked.** Local
foundations (M1a, M1c, M2, M3, M4, M6a) are fully buildable now; only their *external halves* and the
*deployed/live* gate are deferred.

## `tdd-swarm` local-MVP-foundations epic (pre-approved scope; NOT invoked)

The human pre-approved the **epic scope M1a · M2 · M3 · M4 · M6a** and the M1a/M1b + M6a/M6b boundaries —
but **not** unseen detailed tickets. **`tdd-swarm` cannot run until GitHub `main` protection is active**
(`CLAUDE.md`/`tdd-swarm` require it). When protection lands, invoke `tdd-swarm` and present, at the
**mandatory human checkpoint before any production code**:
- **Phase 0:** production-grade posture · clean baseline · current passing-test count · gate commands ·
  protected-`main` status · CI status · the existing **P9/P10** contract baseline.
- **Phase 1:** the epic decomposed into **≤ ~½-day tickets** with stable acceptance-criterion IDs, **frozen
  failing tests before implementation**, file ownership, requirement/architecture traceability, dependency
  waves, **no same-wave file-scope collisions**, and independent plan review.

The swarm proceeds through approved waves without routine interruptions, stopping only for the four
escalation classes (safety/correctness · blocked-after-retry-cap · deferral/posture change · load-bearing
architecture/contract change), and **never merges its final PR to `main`** — it stops with the PR open and
checks green for human review.

## Minimal MVP hard-gate subset (committed for Tue 2026-07-21 23:59)

Per the 2026-07-20 scope decision (refined): the committed MVP is a **secure end-to-end vertical slice** —
the smallest slice that satisfies the four MVP hard gates **while keeping the full security spine live**.
All **other graded requirements are FINAL-COMMITTED** (scheduled into the Fri Final gate — **not optional,
not stretch, not cut**).

**Security spine — non-deferrable, in the MVP slice:** the Clerk authentication/custom-permission
foundation and authenticated deployment (M1c/M1d); the trusted **Policy Gateway + Execution Recorder**
(M4); **live-target authorization controls** (M5 + `authorized-live-campaign` P5 + the gateway's
allowlist/scoped-creds/synthetic-data/budget/rate/hard-abort); the **independent Red Team *and* Judge**
(M8 + M9); **deterministic fail-closed verdict handling** (M9 / D13); and the **security-invariant tests
that prove them** — S1/S2 DB-role append-only (M2), S3 replay rejection (M4), S4 Judge-injection (M9/M12),
S9 hash reconciliation (M6a). None of these may be deferred out of MVP. (Local halves M1a/M1c/M6a
are buildable now; the *deployed* MVP gate additionally needs the external halves
M1b/M1d/M6b/M5/M8.)

| Hard gate | Committed tasks |
|---|---|
| Deployed platform + URL | P8 · P11 (GitHub✅; protection⛔/GitLab⛔) · **M1a/M1c** (local) · **M1b/M1d**⚠ · M5⚠ · M15⚠ (+ D1⚠ readiness) |
| Threat model deepened | D1⚠ → M7⚠ (+ P2) |
| `./evals/` ≥3 categories + ≥1 live agent (**full loop** per decision) | P1 → P10 · P9 · P3 · P5 · M1a → M2 → M3 → M4 · **M6a** · **M8⚠ + M9** → M11 (+ M12 **CI-substrate portion** for validation; P4 for the Judge's calibration hook) |
| `contracts/v1` + typed errors | P10 (needs P1) |
| Requirements matrix | M14 |

**MVP inference (decision):** Red Team runs **hosted-OSS** (M8 ⚠) for MVP; local Mac is the F7 switch.

**FINAL-COMMITTED (graded — committed for Fri, not optional/stretch):** M10 (deep calibration/drift
governance — the Judge already runs at MVP with deterministic oracle precedence + fail-closed handling;
systematic dual-judging/drift metrics complete at Final), the **additional M12 injection variants** beyond
the MVP security-invariant tests, M13 (S5 vendor-disjoint guard — only *bites* once the Documentation agent
runs at Final), P6/P7 (Final skills), and all F1–F14. These are scheduled into Final, **not dropped**.

## Grilling findings & resolutions

| # | Finding | Type | Resolution |
|---|---|---|---|
| G1 | P8 acceptance ("CI fails on lint error") forward-assumed a GitHub remote that only exists after P11 | objective | Fixed — P8 uses a **local pre-commit gate** (`ruff`+`pytest`); GitHub-Actions CI is wired in M1 after P11 |
| G2 | M12's S4 battery case (v) tested the Documentation agent, which does not exist until F2 (Final) — a hidden forward dependency in an MVP task | objective | Fixed — M12 scoped to the **Judge-side** battery (4 cases); the **Documentation doc-control battery lands with F2**; matrix row updated |
| G3 | M12's injection battery tests the Judge but M12 did not depend on M9 | objective | Fixed — added **M9** to M12 deps; CI-substrate portion (no SUT) still lands early |
| G4 | MVP live-agent scope was unstated (product choice) | product | **User: full loop (Red Team + Judge)** — M8+M9+M11 is the MVP target |
| G5 | Red Team MVP inference was unstated (hosted-OSS vs local Mac) | product | **User: hosted-OSS now** — M8 tagged ⚠ HUMAN AUTH (account/creds/budget); external-state list item 8 |
| G6 | 43-task plan vs ~1.5-day solo MVP — scope-realism unstated | product | **User: secure end-to-end vertical-slice MVP** (refined) — the security spine (Policy Gateway/Recorder, live-target authorization controls, independent Red Team **and** Judge, deterministic fail-closed verdicts + their invariant tests) is **non-deferrable** in MVP; all other graded requirements are **FINAL-COMMITTED**, not optional/stretch |
| G7 | Dependency-cycle + forward-dep sweep after G1–G3 | objective | No cycles; no remaining acceptance criterion requires an unfinished later task (validated in §Verification) |

## Cut / deferred

- **2026-07-20 — Wrapping PyRIT/Garak/Giskard seed sources → post-MVP** (D12, `proposed`). MVP ships a
  hand-authored corpus + the custom mutation loop (M8); contract JSON keeps seed sources hot-swappable.
- **2026-07-20 — D2/D4 diagram render → D3**, a pre-presentation gate off the critical path. Rendered
  artifacts + `DIAGRAM_PLAN.md` legend remain **stale/non-binding** until D3; `ARCHITECTURE.md` +
  `DECISIONS.md` are authoritative. **Not executed in the current pass.**
- **2026-07-20 — Type checking** deferred: `P8` claims lint (ruff) only; no type-error CI gate is asserted
  until a checker (e.g. mypy) is configured in a dedicated task.

## Needs architecture

None. Every task traces to an `ARCHITECTURE.md` § + a `DECISIONS.md` D# + a PRD/F/S/O mapping. Two
values remain measured-not-invented and gate their tasks: cost numbers (F5, `open question` §17) and the
target's exact auth/API shape (D1, OQ1/OQ2). Route any new scope through `/arch-finalize` (or a dated ADR
addendum) before adding a task.
