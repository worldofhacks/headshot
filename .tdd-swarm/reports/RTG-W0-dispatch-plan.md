# RTG W0 dispatch plan — WP-11 (oracles) + WP-14 (100-case corpus) — FIRE-READY

**Status:** PREP ONLY — held; base not pinned. Grounded on on-disk HEAD `971dd98`
(branch `codex/platform-observability-followup`, sole Alembic head `0017`). Line numbers may
shift when the base pins; re-verify the anchors marked ⚓ at fire.
**Honest bar (enforced):** decisive verdicts (pass/fail/confirmed/held), never fabricated passes;
oracle-not-ready case stays INDETERMINATE; no case authored against a non-existent oracle.

---

## A. KEY FINDING — most oracle *evaluators* already exist

WP-11 is mostly **wire + collect observations + contracts + 2 new oracles**, not build-from-scratch.
Existing evaluators (`registry.py` registers them `runtime_wired=False`, `availability=pending_runtime|local_fixture_only`):

| Oracle family | Evaluator today | Gap to close in WP-11 |
|---|---|---|
| tool-call | `ToolAuthorizationOracle` ⚓`oracles/category.py:155-171` | add `arguments_hash`+`scope_hash` to observation; wire collection |
| patient/tenant-scope | `RetrievalScopeOracle` ⚓`category.py:76-98` | wire retrieval-scope observation collection |
| state-diff/write | `StateCorruptionOracle` ⚓`category.py:116-134` | wire state_diff observation collection |
| consumption | `ResourceLimitOracle` ⚓`category.py:208-229` | **add request-count dimension**; wire meter from gateway |
| system-prompt / cross-patient canary | `CanaryOracle` ⚓`oracles/base.py:59-78` (2 canaries exist) | **extend** cross-patient canary with scope binding |
| **RAG-source** | **none — NEW** `RagSourceOracle` | build (reuse RetrievalScope hash-set pattern) |
| **output-sink** | **none — NEW** `RenderSinkOracle` (6 sink predicates) | build — **biggest gap**, needs WP-12 sink surface to leave `pending_runtime` |
| identity-role (adjacent) | `IdentityRoleOracle` ⚓`category.py:247-265` | wire identity_scope observation |

`Judge.evaluate` deterministic precedence ⚓`judge/judge.py:80-146` (RULE1 fail-closed ERROR →
RULE2 any trusted canary/oracle hit → EXPLOIT_CONFIRMED → RULE3 INDETERMINATE). WP-11 **extends**
it with INCONCLUSIVE/contradictory + a **required-oracle-policy gate for NO_EXPLOIT_OBSERVED** —
must preserve the "reads only the trusted block, never the hostile transcript" property.

## B. WP-11 dispatch (T1) — order within the single package

**(0) contract-steward FIRST** (before any producer writes; else frozen P10 contracts silently
break existing tests). Schemas in `src/agentforge/contracts/v1/`:
- NEW `trusted_observation.json` (8 kinds: response_canary, tool_call, retrieval_scope, state_diff,
  render_sink, resource_usage, identity_scope, grounded_fact — append-only, content-addressed,
  bound to org/target/surface/campaign/attempt/authorization-scope-hash/collector-identity).
- NEW `oracle_evaluation.json` (4-state `VIOLATION|SATISFIED|INCONCLUSIVE|ERROR` + availability +
  completeness + scope binding + evidence content-hash).
- NEW `required_oracle_policy.json` (immutable ordered required-oracle IDs bound to case/risk/
  surface/corpus/target/authorization-scope hashes; the hash the Judge checks for NO_EXPLOIT).
- NEW `calibration_review.json` (ground-truth-v2 review manifest: human labeler + distinct reviewer,
  guide hash, train/dev/holdout split).
- BUMP `evidence_envelope.json` — add `trusted.oracle_evaluations[]`; extend `trusted_signal` to
  carry `state`+`availability` (today only `{id,provenance∈code|human,hit,detail}` ⚓`:39-49`).
- register all new IDs in `contracts/registry.py` SUCCESS_SCHEMAS ⚓`:44-62`; **WP-19B** owns final
  registry/manifest parity AFTER WP-11.

**(1) serialized migration lane** (ONE Alembic rev, rebased on sole head `0017`, never a parallel
head): `migrations/versions/<REV>_trusted_observations.py` — append-only TrustedObservation
table(s) + oracle_evaluation table + required_oracle_policy table + collector-attestation table;
`storage/models.py`; `storage/roles.sql` grants (recorder INSERT-only, judge SELECT-only, red_team
NONE). Must pass `tests/test_migrations.py` single-head assertion.

**(2) ≤3 parallel implementation workers** (Test→Test-Review/freeze→Implement→Code+Security):
- **Worker A** — observations layer + Recorder: `src/agentforge/observations/**` (new), `policy/recorder.py` (append-only observation persistence + collector attestation).
- **Worker B** — oracle families: `agents/judge/oracles/**` — new `render_sink.py` (6 predicates), `RagSourceOracle`, request-count on `ResourceObservation`, cross-patient canary scope binding.
- **Worker C** — Judge + calibration + bindings: `judge/judge.py` (4-state + required-oracle gate), `judge/envelope.py` (oracle_evaluations block), `scripts/run_judge_calibration.py`, **and solely owns `evals/validation.py` + `oracles/registry.py`** (kept in ONE worker to avoid write-scope collision).
- **Human Ground-truth Reviewer gate** (not agent-writable) blocks any model-Judge enablement.

**Migration reserve:** at fire, reserve the WP-11 rev on the sole head; serialize behind any
WP-02/WP-10 migration if those are ever run (not in the locked de-scoped plan, so WP-11 is first).

## C. WP-14 dispatch (T2) — 100-case six-category matrix

**Existing:** 9 active seeds (PI/DX/TM ×3) + 7 drafts (SC/DS/IR) already on disk; a FROZEN
`headshot-live-100-v1` exists but is **3-category only** (PI34/DX33/TM33, 79/21 turns, 121 phys) —
**do not reuse or mutate it.** New corpus needs a **NEW id** (e.g. `headshot-full-spectrum-100-v1`).

**Matrix to 100 (86 new), each subcategory bound to a WP-11 oracle:**

| Category | Total (new) | OWASP Web · LLM (·ASI v2) | Bound oracle(s) | Gate |
|---|---|---|---|---|
| prompt_injection | 20 (+17) | A03/A04 · LLM01/07/04 · ASI01 | canary + retrieval_scope | **READY** |
| data_exfiltration | 18 (+15) | A01/A02 · LLM02/08/06 | canary(encoded) + patient_scope | **READY** |
| tool_misuse | 18 (+15) | A01/A08 · LLM06/05 · ASI02 | forbidden_tool + patient_scope (+state_diff/render_sink subcases) | **mostly READY** |
| state_corruption | 15 (+13) | A04/A08 · LLM04/01 · ASI06 | state_integrity_violation | **WP-11-GATED** |
| denial_of_service | 14 (+12) | A04/A05 · LLM10 · ASI08 | resource_limit (+WP-01 send-ledger) | **WP-11-GATED** |
| identity_role_exploitation | 15 (+14) | A01/A07 · LLM06 · ASI03/09/10 | identity_role_violation | **WP-11-GATED** |

**Authoring batches** (each waits on its bound oracle existing; per-batch Test→freeze):
- **Batch A** (dispatch once WP-11 canary+retrieval packs green): PI(17)+DX(15) = **32**.
- **Batch B** (once WP-11 tool_call pack green): TM(15); side-effect subcases held `blocked_missing_surface` until state_diff/render_sink land.
- **Batch C** (do NOT dispatch until WP-11 state_diff/resource_usage/identity_scope packs merge): SC(13)+DS(12)+IR(14) = **39**. Until then author as `lifecycle=draft`, `execution_state=blocked_missing_surface` (schema-valid, excluded from frozen manifest).

**Turn balance / physical count (REVIEW-LOCKED knob — pick ONE at freeze):** 76 single + 24 two-turn
→ **124 physical**, or keep 79/21 → **121 physical**. Manifest content-hash binds it; loader must
assert `count(1)==single, count(2)==multi, sum==physical` (mirrors ⚓`corpus.py:499-502`).

**Review gates before hash freeze:** (1) Test-review/freeze per batch; (2) schema/contract
`validate-eval-case`+`validate-corpus`; (3) **Ground-truth** (human labeler+distinct reviewer);
(4) **Applicability** (distinct Headshot human approves each N/A); (5) **dedup+content-address** —
`detect_duplicate_sequences` ⚓`validation.py:1018`, **plus add NFKC/confusable rejection**
(current `_normalize_turn` ⚓`:662` is NFC-only — WP-14 requires homoglyph rejection: a real gap);
(6) freeze manifest → corpus hash. Every case `NOT_EXECUTED / pending_live_campaign /
add_to_regression=false`.

## D. GROUND-TRUTH LABELS — the exact set needing human sign-off

AI never fabricates these. Needed:
1. **6 per-category calibration slices** (`evals/ground-truth/*.v1.json`) — PI/DX/TM exist as v1 +
   SC/DS/IR authored-not-run; ALL 30 current labels are `label_source=deterministic_canary|policy_rule`,
   **none human-reviewed**. Each label needs an **identified human labeler + a DISTINCT human
   reviewer** under a frozen guide. Label classes per slice: deterministic_confirmation,
   negative_control, ambiguous/contradictory, evaluator_injection, non_oracle_positive.
2. **Applicability / NOT_APPLICABLE records** — a handful, only for ASI risks with no matching WP-12
   surface (e.g. ASI04 supply-chain, ASI05 code-exec, SSE-streaming). Missing surface =
   `blocked_missing_surface`, **not** auto-N/A. Each needs a **distinct authorized Headshot human**
   approving the exact record hash.
3. **train/dev/holdout split + frozen labeling-guide hash** — 1 split manifest + 1 guide hash; a
   **human integrity attestation** that no label/threshold changed in response to candidate-Judge output.

→ Owner to decide: self-review vs. assign an independent reviewer (owner offered this).

## E. SEAM COORDINATION — integration manager (hand off before/at fire)

| Seam | WP | In-flight? | Required sequencing |
|---|---|---|---|
| `target/catalog.py` | WP-12 | ⚠️ **YES** — in-flight already added `CatalogEntry.surfaces`/`resolve_target()`/`register()` | **HARD**: pin base WITH these edits; WP-12 rebases on top, never re-derives the surface shape. (WP-12 is later, but flag now.) |
| MVP floors: `postgres.py:2631 (>=9)`, `runner.py:1072 (MVP_CASE_COUNT/MVP_CATEGORIES)`, `birdseye.py:385/406` | WP-14 output | ⚠️ **YES** & **not in any WP write-list** | **Cross-lane**: integration manager (WP-20A/B) must retarget these floors to the full-spectrum manifest hash/category set, or the new corpus is invisible/uncovered. WP-14 cannot edit them. |
| `runner.py:1140` LIVE_100 exact-caps special-case | WP-14 default | ⚠️ YES | Generalize exact-caps enforcement off the reviewed 100-case **manifest hash**, not the literal `LIVE_100_CORPUS_ID`. Integration-file edit, outside WP-14. |
| `judge/judge.py` verdict enum | WP-11 | judge.py not in-flight; `hosted.py` is | WP-11 preserves the public verdict API `hosted.py` consumes; re-run `tests/test_hosted_role_adapters.py` after. Flag enum change. |
| `runner.py/postgres.py/birdseye.py/read_models.py/router.py` (consume WP-11/12/14 outputs) | WP-20A/B | YES, all in-flight | Land WP-11/12/14 libraries **before** the integration manager finalizes this wiring, so it targets shipped contracts not stubs. |

PR **#29** = release scaffolding only (`.tdd-swarm/**`, `.env.example`, `.gitignore`) — **no code
seam**; ignore for collision purposes.

## F. OPEN DECISIONS needing owner / integration-manager input BEFORE fire
1. **attack-case v1 vs v2 fork.** WP-14 mandates NEW `attack-case.v2.json` + `corpus-manifest.v1.json`
   + `applicability-record.v1.json` + `taxonomy.py`/`full_spectrum.py` (none exist). Only v1 exists
   (case_id `^AF-M11-*`, fixed subcat enum). Either build the v2 stack first (adds a prerequisite
   sub-package; needed for full LLM+ASI taxonomy) **or** author 100 against v1 with AF-M11 prefix.
   **Recommend: build v2** (WP-14 requires it; ASI mapping needs it).
2. **Turn balance** 79/21→121 vs 76/24→124 (§C). Review-locked; pick at freeze.
3. **Ground-truth labeling ownership** (§D) — self-review vs independent reviewer.
4. **Floors handoff** (§E) — confirm the integration manager owns retargeting the MVP floors +
   LIVE_100 caps generalization.

## G. FIRE SEQUENCE (the instant the base pins clean+GitHub-green)
1. Verify pinned SHA is clean + GitHub-green; lock `<RED_TEAM_GAP_BASE_SHA>`; re-verify ⚓ anchors.
2. Reserve WP-11 Alembic rev on sole head (`0017` today).
3. Dispatch **WP-11 contract-steward** (5 schemas) → freeze → migration lane → Workers A/B/C
   (Test→freeze→Implement→Code+Security) → Ground-truth Reviewer gate.
4. On WP-11 canary/retrieval/tool packs green → dispatch **WP-14 Batch A/B**; hold **Batch C** for
   the state_diff/resource_usage/identity_scope packs.
5. Freeze the six-category 100-case manifest (new corpus_id) with the locked physical count; hand
   the floors/caps retarget to the integration manager (§E); coordinate the corpus + coordinator-
   default seam. (WP-12 wire-default is the following wave.)

---

## H. DECISIONS LOCKED (owner) — supersede §F

1. **Schema = attack-case v1** for the 100-case corpus (six categories + OWASP Web 2021 + LLM 2025,
   oracle-bound). **Do NOT** build the v2 schema stack as a prerequisite. Case IDs keep the v1
   `AF-M11-*` prefix; NEW corpus_id (not `headshot-live-100-v1`). Document **v2 / ASI agentic
   taxonomy as a planned enhancement** (ASI is not in the graded requirement) in the coverage matrix.
   At fire, verify v1 schema accepts all six categories' subcategory enums + the full owasp[] set
   (validation.py:151-160 already knows all six).
2. **Turn balance = 79 single / 21 two-turn → 121 physical** (matches the locked plan & the
   "exactly 121" assertions). Review-lock at manifest freeze; loader asserts `count(1)==79,
   count(2)==21, sum==121`. Six-category redistribution keeps the 121 physical envelope so the caps
   machinery generalizes with minimal churn.
3. **Ground-truth labels = owner-attested.** Sequence: the swarm PROPOSES expected labels **from the
   designed-in synthetic case outcomes** (candidate labels + a frozen labeling guide) → owner reviews
   + attests **BLIND to model/Judge outputs** under the frozen guide. Distinct second reviewer used
   if available; **if not, single-human-attested and DOCUMENTED as a stated limitation — never faked
   as two people.** Concrete per-case labels + guide **hash** are surfaced for sign-off **during
   WP-11/WP-14 execution** (Worker C authors the guide/candidate labels); the label-set STRUCTURE is
   §D and is locked now.
4. **Floors-retarget owned by A** (integration/release lead, WP-20A/B): retarget `postgres.py:2631`
   (`>=9`), `runner.py:1072` (MVP floor/categories), `runner.py:1140` (LIVE_100 exact-caps
   special-case), `birdseye.py:385/406` to the full-spectrum 100-case manifest hash/category set.
   Outside all WP write-lists; A is being told.

**Base + coordination (owner):** pinned base comes from **A**, pinned WITH the `catalog.py` surface
edits included (so WP-12 rebases, not forks). When landing the WP-11 4-state gate, **preserve the
Judge verdict-enum public API that `hosted.py` consumes** — coordinate that contract change with A.
**Fire W0 on A's pinned SHA; hold until then.**
