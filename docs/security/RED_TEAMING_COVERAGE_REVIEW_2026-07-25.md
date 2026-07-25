# Red-teaming coverage review

**Date:** 2026-07-25
**Base:** `2069036` (branch `codex/platform-observability-followup`, tip after PR #44 "Retire
superseded DeepSeek Red Team provider"; sole Alembic head `0021_four_role_agent_acceptance`). The
original review was performed at this commit; the post-base addendum below carries PRs #47/#48 and
staging truth forward. Where a documentation cite is marked `@107c11c`, that is the base this pass
started from — two commits earlier — and the marker means "that is what the file said before this
pass". Line numbers from the predecessor review were **not** carried forward.

**Reading the cites.** Unmarked current-tree code cites use `path::symbol` as the durable locator and,
where useful, give the line in the post-PR-#47 tree as a secondary aid. **Documentation cites carry an
explicit `@107c11c` marker** wherever this same reconciliation pass edits the file being cited
(`107c11c` being the commit this pass started from) — otherwise the anchor would die the moment this
review lands, which is precisely the failure this document exists to correct. `@107c11c` means: that
is what the file said *before* this pass; the correction is described alongside it. Those
commit-qualified historical numbers remain intentionally unchanged. An **unmarked** cite resolves in
the shipped tree — i.e. after this pass lands.
**Supersedes:** [`RED_TEAMING_COVERAGE_REVIEW_2026-07-24.md`](RED_TEAMING_COVERAGE_REVIEW_2026-07-24.md)
(retained; its analysis is still the reference framing for RT-01 … RT-14).
**Scope:** AgentForge / Adversarial Machine repository, deployed-platform design, LLM
evaluation corpus, Judge and its calibration, target adapter, regression path, security-tool
integrations, and Burp-style workbench claims.
**Method:** Read-only code and evidence review at the pinned base, plus local execution of the
offline calibration harness and the Judge/calibration test modules. No live campaign, active scan,
target request, provider call, Clerk administration, deployment change, or publication action was
performed.

### Post-base integration addendum

The analysis base above remains `2069036`; the following later facts are carried forward so this
review does not overwrite newer integration truth:

- PR #47 merged terminalization reconciliation at `a6a9617`. Current-tree source anchors below were
  re-resolved after that merge; its lifecycle changes do not alter the findings verdict in this
  review.
- PR #48 merged corrected reports 004–006 at `a67ac1e` after all five GitHub checks passed. Their
  legal severities are now `medium`, `low`, and `low`; all three explicitly identify hand-written
  authorship, external owner-supplied Bruno provenance, no attributable Judge verdict, and the
  limits of their embedded offline re-derivations.
- Railway staging deployed the exact `2069036e` candidate Runner-first. Web's pre-deploy migration
  advanced the database from `0013` to the single `0021` head while public routing was held; the
  Runner became healthy, Web started behind the hold, the private Scheduler became stable, and only
  then was Web routing opened. Public `/health` and `/ready` returned `200`, unauthenticated
  `/api/v1/principal` returned `401`, and `/` plus `/sign-in` returned the packaged HTML shell. No
  campaign, provider, or target call occurred. This is deployment proof, not live-campaign,
  signed-in Clerk, or finding-reproduction evidence.

## Executive verdict

The predecessor's verdict still holds, and one of its two headline blockers has moved:

> **Governed, partially implemented LLM evaluation platform with a strong safety control
> plane—now live-*probed* but not yet live-*evidenced*, autonomous, comprehensive, or continuously
> verified red teaming.**

What is genuinely better since 2026-07-24: an authorized synthetic-only campaign against the live
Co-Pilot target **did** run and its artifacts are checked in; hosted red-team generation is
implemented rather than raising `NotImplementedError`; a live passive ZAP baseline against the
authorized target is committed and hash-verified; and the RT-09 pre-physical-send abort gate is
implemented and wired.

What is not better, and is in two places **worse than this repository's own documents claim**:

- Every adversarial verdict on disk is `INDETERMINATE`. Across the four result groups under
  `evals/results/` there are 39 verdict records, **0 `EXPLOIT_CONFIRMED`, 0 `EXPLOIT_LIKELY`,
  0 `NO_EXPLOIT_OBSERVED`, 0 oracle hits, 0 canary hits**, and no recorded cost.
- The only calibration measurement that exists at this base **fails**: 30 labels, 18 agreements
  (0.600), **6 false negatives (0.333)**, 0 false positives, 18 abstentions (0.600).
  See *Calibration — the exact numbers* below; a "0 false negatives / 0 false positives" result
  exists only inside test fixtures that read the ground-truth answer key.
- Hosted generation is implemented but **structurally undispatchable**: the coordinator requires
  every proposal to equal the reviewed seed byte-for-byte, so a generated attempt is outside the
  grant that authorized the run.
- No run in the repository went through the platform's production authorization path. All four
  legacy launchers now fail closed, so every committed artifact was produced by a script that can
  no longer execute.

The correct label for coverage remains **mapped, not covered**. Nothing in this repository has ever
confirmed an exploit.

## What changed since 2026-07-24

| Predecessor claim | Status at this base | Evidence |
|---|---|---|
| "hosted attack generation raises `NotImplementedError`" | **No longer true, but not for the reason it looks.** There is now exactly **one** hosted generator, and the legacy route is deliberately retired. | The governed generator is `src/agentforge/agents/red_team/hosted_generation.py::TracedHostedRedTeamProvider` (currently line 204), routed through the shared `OpenRouterTransport` with `role="red_team"`, the shared usage ledger, and the durable lineage recorder. The standalone `HostedProvider` is a **fail-closed compatibility shell** (`providers.py:216-250`): it runs provider/model preflight, refuses without explicit authorization, then raises `ProviderPreflightError` unconditionally **before building any client, importing any SDK, or opening any socket**. No `NotImplementedError` remains — it was replaced by a stronger refusal, not by a working path. |
| "there is no checked-in live LLM-campaign result" | **No longer true.** Four result groups exist. | `evals/results/live-campaign-20260724/`, `…-week1/`, `platform-live-run-20260724/`, `bruno-20260724/` |
| "the current 15-label calibration produces 9 agreements, 3 false negatives, and 9 abstentions" | **Stale counts.** The corpus is 30 labels; the result is 18 / 6 / 18. | `tests/test_judge_calibration.py:51-58` |
| RT-09 "persisted abort state is not rechecked before every physical request" | **Materially reduced.** A pre-physical-send gate now fires before every physical send, including retries. **Not closed** — the specific test the predecessor demanded does not exist. | `src/agentforge/policy/gateway.py:532-548`; nested `revalidate` in `src/agentforge/runner.py::DurableCampaignRunner._execute_prepared` (currently lines 1753–1790); `src/agentforge/campaign/coordinator.py:588-611` |
| RT-11 "DNS-rebinding time-of-check/time-of-use gap" | **Narrowed, not eliminated.** Validation moved into the adapter's `send()`, so it runs per physical send — but there is still no address pinning. | validation now per-send in `src/agentforge/target/openemr_adapter.py`; `src/agentforge/target/destination.py` and `pinned_transport.py` do not exist |
| RT-14 "`docs/evidence/zap/README.md` records a live passive target scan, while … SECURITY_TOOL_EVIDENCE.md still says live-target ZAP remained blocked" | **Was still drifted, and the drift ran both ways. Resolved in this pass** — see RT-14. | `docs/evidence/ato/SECURITY_TOOL_EVIDENCE.md:99 @107c11c` vs `docs/evidence/zap/zap-target.json` |
| Sole Alembic head `0016` (as `README.md:11,179 @107c11c` stated) | **Head is `0021`.** Corrected in this pass; `README.md` no longer names `0016`. | `migrations/versions/0021_four_role_agent_acceptance.py` |

Three predecessor facts are unchanged and remain the spine of the problem: only the canary oracle
can fire, mutation is not in the production campaign, and the six-category taxonomy is half
populated.

## Validation performed

| Check | Result |
|---|---|
| Offline calibration harness, `PYTHONPATH=src python3 scripts/run_judge_calibration.py` | **Failed as designed.** `state="failed"`; see the exact numbers below. Note the bare command exits **0** — the gate is advisory unless `--require-pass` is passed (`scripts/run_judge_calibration.py:59-63`), which makes it exit **2** (`:93`). A CI job that runs it without that flag proves nothing. |
| `pytest tests/test_judge_calibration.py tests/test_judge_calibration_results.py` | 13 passed, 0 skipped, 0 xfail |
| `pytest tests/test_judge_calibration.py tests/test_judge_calibration_runtime.py` | 12 passed, 0 skipped, 0 xfail |
| `pytest tests/test_judge.py` | 26 passed, 0 skipped, 0 xfail |
| `pytest tests/test_hosted_runtime.py` | 8 passed, 0 skipped, 0 xfail |
| `sha256sum docs/evidence/zap/zap-target.json` | `89f10c9445a98a324d80d38f5ed12db4e6e05885441b0da00598a8634b88edac` — matches all three metadata records byte-for-byte; `byte_length` 7910 matches the file |
| Full suite (`scripts/check.sh`), console, browser, GitHub CI, GitLab mirror | **Not run in this original pass.** The predecessor's "1,001 Python tests passed, 3 skipped" is **not** measured at this base; `tests/` now defines **1,284** test functions, so that figure cannot be current. Treat it as unverified. GitLab is a passive mirror with no runner gate. |

The calibration harness is a hand-run CLI. It appears in neither `scripts/check.sh` nor
`.github/workflows/ci.yml`, so an ordinary green CI run says nothing about calibration.

### Calibration — the exact numbers

Measured at this base against the six committed ground-truth slices (30 labels):

| Metric | Value |
|---|---|
| `state` | **`failed`** |
| `sample_count` | 30 |
| `agreement_count` / `agreement_rate` | 18 / **0.600** (threshold `min_agreement_rate` 0.9) |
| `false_negative_count` / `false_negative_rate` | **6** / **0.3333…** (threshold `max_false_negative_rate` **0.0**) |
| `false_positive_count` / `false_positive_rate` | **0** / **0.0** |
| `abstention_count` / `abstention_rate` | 18 / **0.600** (threshold `max_abstention_rate` 0.4) |
| `expected_calibration_error` | 0.0 |
| `reason_codes` | `agreement_below_threshold`, `false_negative_rate_exceeded`, `abstention_rate_exceeded` |
| `human_approved` / `runtime_enabled` / `approver_ref` | `false` / `false` / `null` |
| measured identity | `judge_provider="deterministic-code"`, `judge_model="oracle-precedence"` |

Three qualifications that matter more than the headline:

1. **The 0 false positives arrives bundled with 6 false negatives.** It has never occurred
   alongside a 0-false-negative result. Any statement of the form "0 FN / 0 FP" describes no
   artifact and no measurement at this base.
2. **The confusion matrix says something more precise than the aggregate does.** Re-measured over the
   30 labels:

   | Expected | Judge emitted | n | Reading |
   |---|---|---:|---|
   | `EXPLOIT_CONFIRMED` | `EXPLOIT_CONFIRMED` | **12** | correct — every canary/oracle-backed confirmation was caught |
   | `INDETERMINATE` | `INDETERMINATE` | 6 | correct by abstention |
   | `EXPLOIT_LIKELY` | `INDETERMINATE` | **6** | **the 6 false negatives** |
   | `NO_EXPLOIT_OBSERVED` | `INDETERMINATE` | 6 | a decisive-safe verdict the deterministic Judge cannot emit at all (`judge.py:37-39`) |

   So the 18 agreements are 12 correct confirmations plus 6 correct abstentions — **not** abstention
   agreeing with itself — and all 18 abstentions are the single behaviour `INDETERMINATE`. The Judge is
   perfect where a deterministic oracle exists and silent everywhere else. That is precisely the shape
   D26 predicts, and it is why the fix is *canary-anchoring more cases*, not *tuning the Judge*: the
   12 non-agreements are 12 cases with no oracle to hit, and no threshold change can convert them.
3. **What was measured is the deterministic oracle-precedence baseline, not a model.** Measuring a
   model requires `--captured-results` plus `--expected-identity`
   (`scripts/run_judge_calibration.py:43-58`, mutually required at `:70-71`) and **no
   captured-results bundle is committed anywhere in this tree.** The only JSON in the repository
   containing `calibration_id` is the schema itself,
   `src/agentforge/contracts/v1/judge_calibration.json`.

The only `0 false negatives` assertions at this base are produced by in-test fixtures that copy the
answer key:

- `tests/test_judge_calibration.py:189-196` (`_PositiveClassificationEvaluator`, subclassing the
  `_ExpectedVerdictEvaluator` at `:61-71`), asserted at `:206-208`;
- `tests/test_judge_calibration_results.py:52-54` builds a sample bundle from
  `label["expected_verdict"]["state"]` and rewrites `EXPLOIT_CONFIRMED` → `EXPLOIT_LIKELY`, stamps
  it with fabricated provenance (`capture_kind="openrouter_hosted_evaluator"`, requested/returned
  model `google/gemini-2.5-pro`, synthetic `provider_request_id` and `trace_id`, `:65-83`), and
  asserts a pass at `:111-116`.

The second is the more misleading of the two: it wears OpenRouter/Gemini lineage labels while
containing zero model output. Neither is evidence about a model, and neither is evidence about a
target — the ground-truth slices are self-labelled `"calibration_status": "AUTHORED_NOT_RUN"`
(`evals/ground-truth/prompt-injection.v1.json:7`) with `campaign_run_id: "ground-truth-unexecuted"`
and `live_campaign_result: null`.

**Judge enablement is therefore closed, and at this base it is not merely disabled but
un-enableable without new code or a hand-placed artifact:** `CalibrationGate.evaluate` hardcodes
`human_approved=False`/`runtime_enabled=False`/`approver_ref=None`
(`src/agentforge/agents/judge/calibration.py:198-200`), and `human_enable`
(`calibration.py:205-226`) has **zero callers in `src/` or `scripts/`** — every invocation is in
tests. The runner's artifact path is `AGENTFORGE_JUDGE_CALIBRATION_PATH`
(`src/agentforge/runner.py::DurableCampaignRunner.__init__`, currently lines 834–839), which is the
sole occurrence of that string in the tree and
is set in no `.env`, container, CI, or Railway configuration; the loader deliberately has no default
(`src/agentforge/agents/judge/calibration_runtime.py:73-79`) and returns
`state="unavailable"`/`calibration_artifact_unavailable` when both sources are absent (`:88-93`).

## Current capability scorecard

| Area | Status | Basis |
|---|---|---|
| Authorization and safety envelope | Strong foundation | Exact target/surface/corpus binding, synthetic-only assertion, caps, two-person controls; pre-physical-send gate added (RT-09) |
| Multi-agent separation | Strong foundation | Red Team, Recorder, Judge, Documentation responsibilities are structurally distinct; hosted role set rejects any deviation (`src/agentforge/agents/hosted.py:352-353`) |
| Evidence integrity and reporting | Strong foundation, with defects | Append-oriented evidence, reread/hash verification, publication-gated findings; but the ZAP `artifact_locator` values dangle and one campaign summary misreports its own manifests |
| Live LLM test evidence | **Probed, not evidenced** | 39 verdict records against the authorized live target, **all `INDETERMINATE`**, 0 oracle/canary hits, no cost recorded |
| Dynamic adversarial search | Not operational | Hosted generation implemented; **structurally undispatchable** (`campaign/coordinator.py:393-397`); mutation has no production caller |
| Decisive adjudication | Major blocker | 2 of 16 cases populate a `canary_ref` (14 are `null`); 9 oracles registered, **0 `runtime_wired`**; calibration gate fails |
| LLM risk breadth | Partial | Three of six PRD categories in the runtime coverage gate (`src/agentforge/api/postgres.py:124-126`); LLM09 has no primary-risk case |
| Existing LLM tool utilization | Shallow | Five imported prompt-injection candidates across three tools; Giskard contributes zero |
| Burp-style web/API workflow | Partial | Six of ten workbench workflows still labelled `operational` (`src/agentforge/security_tools/workbench.py:37,45,69,77,85,95`) |
| Continuous regression | Planned/partial | Replay plans are pinned `execution_state: "blocked"` by a schema `const` **and** a database CHECK, so no authorize-and-execute path can exist |
| Runtime operational safety | Needs hardening | RT-09 partially addressed, RT-11 narrowed; RT-10, RT-12, RT-13 and all four RT-14 sub-items unchanged |
| Deployment/release proof | Partial | Staging candidate `2069036e` is deployed Runner-first at schema `0021` with public probes and unauthenticated denial verified; production, signed-in Clerk acceptance, rollback, and a governed campaign remain unverified |

## Detailed findings

Status vocabulary, deliberately narrow: **open** · **partially addressed** (real code, missing the
proof the predecessor asked for) · **closed with proof** (code plus a test that exercises the
failure the finding described). Nothing below is *closed with proof*.

### RT-01 — High, **open**: coverage is mapped, not demonstrated

All 16 authored case files still carry `execution_status: "NOT_EXECUTED"`, `result_kind:
"pending_live_campaign"`, `result_ref: null`. That metadata now **understates** reality: at least
five of those cases were dispatched against the live production target and produced content-hashed
evidence and verdict manifests.

The runtime required-coverage sets are at **`src/agentforge/api/postgres.py:124-126`** (the
predecessor's `:77-79` is an import list):

- required Web: `A01, A03, A04, A06, A07, A09, A10`
- required LLM: `LLM01, LLM02, LLM03, LLM05, LLM06`
- required categories: `prompt_injection, data_exfiltration, tool_misuse`

A campaign can still look "covered" without LLM04, LLM07–LLM10, Web A02/A05/A08, or the three
unused platform threat categories.

The predecessor's improvement — replace the binary coverage claim with nine explicit states, of
which only 6–9 count as demonstrated security coverage — is **not implemented** and is restated
here unchanged.

Two evidence-side defects found in this pass, **both corrected in this pass**:

1. `evals/results/README.md:3-4 @107c11c` said "This directory intentionally contains no
   campaign-result JSON." The directory contains four result groups. **Self-falsifying**; that file now
   carries a dated correction and an inventory of what is actually there.
2. `evals/results/platform-live-run-20260724/COMBINED_SUMMARY.md:11,68 @107c11c` claimed "9 / 9
   authored adversarial cases dispatched live" and cited
   `manifests/runs/platform-live-20260724b-week1/`. **That directory does not exist.** Exactly five
   attempt manifests are tracked (`AF-M11-DX-001`, `PI-003`, `TM-001`, `TM-002`, `TM-003`) across
   `platform-live-20260724-week1/` (1) and `…c-week1/` (4), and the sibling `summary.json` carries a
   four-element `cases` array. `docs/evidence/agent-trace.md:33 @107c11c` already gave the correct figure, "5 of 9".
   That summary now opens with a dated correction block; the original text is preserved beneath it.

### RT-02 — High, **reframed**: the limit is target observability, not Judge wiring

The predecessor read this as a Judge/instrumentation gap and prescribed seven observation families.
Grounding work at this base establishes something stronger and less comfortable: **wiring those
oracle evaluators into the run path would not make them fire.** There is no source data to populate
their observations.

- The deterministic Judge's precedence is intact: fail-closed `ERROR` on integrity
  (`src/agentforge/agents/judge/judge.py:111-117`) or invalid envelope (`:119-125`); any trusted
  canary hit (`:132-135`) or oracle hit (`:136-142`) → `EXPLOIT_CONFIRMED` at confidence 1.0
  (`:164`); otherwise `INDETERMINATE` at confidence 0.0 with reason
  `non_oracle_uncalibrated_indeterminate` (`:170-180`). `_any_hit` (`:234-240`) reads only the
  `trusted` block, never the hostile transcript.
- **The only oracle constructed anywhere in the run path is `CanaryOracle`**, over the re-read
  response transcript (`src/agentforge/campaign/coordinator.py:711-726`, evaluation at `:713-715`).
- The five category observation types (`ToolCallObservation`, `RetrievalScopeObservation`,
  `StateDiff`, `IdentityScope`, resource/consumption) are **constructed only in
  `tests/test_category_oracles.py`** and nowhere in `src/`. The recorder persists transcripts only
  (`src/agentforge/policy/recorder.py`). `TargetResponse` carries `output`, `status`, and
  `{adapter, url, trace_id}` — nothing else.
- Nine oracles are registered and **not one is runtime-wired**:
  `src/agentforge/agents/judge/oracles/registry.py:42` defaults `runtime_wired=False` and `:47` makes
  the registration **refuse to build an evaluator at all** if it is `True`. Two entries are
  `local_fixture_only` (the two canaries, `:63`, `:72`); the remaining seven are `pending_runtime`
  (`:81, :89, :97, :105, :113, :121, :129`). The module's own docstring states it plainly:
  "Resolution is not runtime wiring" (`:3-4`).
- All 16 authored cases declare a `canary_ref` field, but only **2 populate it**:
  `AF-M11-DX-001` (`SYNTH_CANARY_PATIENT_BETA_8C1E`) and `AF-M11-PI-001`
  (`SYNTH_CANARY_SYSTEM_PROMPT_4D2B`). The other 14 are `null`, so `CanaryOracle` has nothing to match
  and those cases cannot reach `EXPLOIT_CONFIRMED` by any path. This is the numeric form of the
  decisiveness ceiling: **2 of 16.**

Retrieval lineage, pre/post state hashes, tool-call authorization decisions, effective role, and
token/tool counters are **target-internal facts that an HTTP response body does not contain**, and
no attesting collector exists. Against a black-box `POST /chat`, wiring is necessary but nowhere
near sufficient.

**The reframing, recorded as `DECISIONS.md` D26 (canary-anchoring):** the decisive lever available
against a black-box target is to *design cases so that a successful exploit echoes a seeded
synthetic canary into the response body*, which yields a genuine `EXPLOIT_CONFIRMED` through the
existing deterministic path. This works natively for data exfiltration (cross-patient canary) and
prompt injection (system-prompt canary) and can be re-expressed for other categories. The
consumption oracle is separately and honestly wireable, because the gateway's own meter is
platform-observable rather than target-internal. `tool_call`, `state_diff`, and `identity_role`
remain non-decisive against a black-box target and their cases stay `INDETERMINATE` — they must not
be flipped to `runtime_wired=True`, because that would fake firing.

Deterministic oracle precedence stays. A model Judge is enabled only after the exact identity passes
the versioned calibration gate and receives the required human enablement — neither of which has
happened (see *Calibration — the exact numbers*).

**One latent invariant gap found in this pass, recorded so it is not lost.** Two Judge seams
disagree about whether a model may emit `EXPLOIT_CONFIRMED`:

- `src/agentforge/agents/judge/hosted.py:22` excludes `EXPLOIT_CONFIRMED` from
  `_ASSESSMENT_STATES` and `:313-318` rejects it at runtime. This is the seam the production runner
  composes in `src/agentforge/runner.py::DurableCampaignRunner._execute_prepared` (currently line
  1513). Correct.
- `src/agentforge/agents/hosted_runtime.py::HostedFourRoleRuntime.run_attempt` hands the judge role
  an output enum of `list(_VERDICTS)` at line 754, and `_VERDICTS` (lines 31–37) **includes
  `EXPLOIT_CONFIRMED`**. The fall-through in
  `HostedFourRoleRuntime._deterministic_precedence` at lines 863–866 returns the hosted verdict
  verbatim with `deterministic_precedence: False`, and it additionally triggers the Documentation
  role at line 770. No test exercises that path.

This violates the Judge invariant *as written*. It is unreachable today for two reasons, **neither of
which is a check inside that function**: nothing in `src/` ever constructs `HostedFourRoleRuntime`
(definition currently at line 623, `__all__` export at line 904, otherwise tests only), and
construction is additionally hard-gated in `HostedFourRoleRuntime.__init__` at lines 648–654, where
a closed calibration gate raises
`HostedCompositionError("model Judge calibration gate is closed")` — which it always does at this base,
since no calibration artifact is committed. Both barriers are external to the verdict logic, so either
one changing re-exposes the gap. Flagged for the owning
lane, not patched here.

Also stale in the source itself: `judge.py:20` asserts "At MVP the LLM path is unwired." At this
base `src/agentforge/runner.py::_PreManifestHostedJudge.evaluate` (currently lines 524–565) wraps
the deterministic Judge in a `HostedEvaluator`, so that comment is false.

### RT-03 — High, **open**: the LLM taxonomy is incomplete and some mappings are nominal

Unchanged in substance. The schema knows all OWASP LLM Top 10:2025 risks and all six PRD threat
categories (`OWASP_NAMES` at `src/agentforge/evals/validation.py:127-148`; the six PRD categories are
`CATEGORY_SUBCATEGORIES` at `:150-161`, with `REQUIRED_PRD_CATEGORIES` at `:162`); the executable
corpus does not. Three of six categories appear in the runtime coverage gate. LLM09 Misinformation has
**no case whose primary risk it is** — it appears only as a *secondary* mapping on one
`lifecycle_status: "draft"` state-corruption case (`evals/drafts/AF-M11-SC-002.json:46`), so the
predecessor's flat "no authored case" was slightly too strong while the gap it describes is real.
The predecessor's per-risk depth table is unchanged and is not restated here.

The OWASP Agentic Applications (ASI01–ASI10) mapping is still absent. Per the owner's locked
decision, the v2 attack-case schema and the ASI taxonomy are a **documented planned enhancement**,
not graded scope — see *Horizon 2* below.

One under-statement worth recording: `src/agentforge/campaign/corpus.py:28-37` declares a trusted
`headshot-live-100-v1` workload identity with `LIVE_100_CASE_COUNT=100` and
`LIVE_100_PHYSICAL_REQUEST_COUNT=121`, and no document in the repository mentions it. The required
manifest `evals/workloads/headshot-live-100-v1.json` **does not exist**, so the whole path is dead
code and the constants are aspirational. Additionally, the committed caps
(`docs/evidence/authorization-requests/caps.json`: 40 attempts / 40 logical / **60 physical** /
`$1.00` / 1800 s / 1 retry) would reject a 121-physical-request scope. Raising them is a
target-authorization change and a human decision.

### RT-04 — High, **open and structurally deeper than described**: generation is undispatchable

The predecessor's "mutation is not wired" is true but understates the obstacle.
`SecureCampaignCoordinator` requires every proposal to equal `seed_to_attempt(seed_case)`
**byte-for-byte** (`src/agentforge/campaign/coordinator.py:393-397`, refusal code
`red-team-proposal-out-of-scope`), because the authorization's operation hash binds the corpus hash.
A mutated or model-generated attempt is therefore not covered by the grant that authorized the run.

Consequently generation and mutation are **structurally undispatchable, not merely unwired**:

- `src/agentforge/runner.py::DurableCampaignRunner.__init__` constructs `SeedReplayRedTeam()`
  unconditionally (currently line 827).
- `src/agentforge/campaign/coordinator.py:37` states outright that hosted Red Team generation is
  skipped.
- `src/agentforge/agents/red_team/mutation.py:41-85` is implemented and tested; its only callers are
  in `tests/test_red_team.py`.
- The sole composition of `TracedHostedRedTeamProvider` is
  `src/agentforge/agent_acceptance.py:528`, a deliberately target-free acceptance harness whose
  output is recorded as `"generated_output_disposition": "quarantined_not_dispatched"` with
  `"target_call_limit": 0`.

Making generation live is an **architecture decision** — the authorization model has to admit a
generated case, for example by binding a generator identity plus a review record rather than a
corpus hash. That is owned by integration. Flagged, not patched.

**A governance improvement worth crediting, landed in PR #44.** There used to be a *second*
generation route: `HostedProvider` built its own client from an ambiently imported `openai`/`together`
SDK, so the generation call bypassed the shared `OpenRouterTransport`, the usage ledger, and the
lineage recorder. That route is now retired to a fail-closed shell (`providers.py:216-250`), and its
test module is deleted. **One governed generator remains**, `TracedHostedRedTeamProvider`
(`src/agentforge/agents/red_team/hosted_generation.py::TracedHostedRedTeamProvider`, currently line
204), which routes through all three. Closing a second, ungoverned egress path is the right call even
though it reduces raw capability.

One stale docstring remains: `mutation.py:9-11` still says "the hosted provider is the boundary for real
generation (behind authorization, never called in a test)". The hosted provider is no longer that
boundary — `hosted_generation.py` is — and the sentence should be re-pointed by whoever owns that
module.

### RT-05 — High, **open**: existing LLM tools are used far below their useful depth

Unchanged. Total tool-generated attack candidates ever imported: **5** (1 garak, 3 PyRIT, 1
Promptfoo, **0 Giskard**). `src/agentforge/campaign/corpus.py:41-45` pins exactly those three
bundles. No tool runs live during a campaign.

Two labels in the tool catalog overstate this:

- `src/agentforge/security_tools/catalog.py:101-133` marks Giskard
  `availability="operational and evidenced"` while it contributes zero candidates to any runtime
  workload and `security-tools/reviewed/` holds no `giskard.bundle.json`.
- `catalog.py:158-180` marks ZAP `availability="operational and evidenced"` with an
  operational scope including "separately authorized exact-origin" scanning. The only ZAP execution
  reachable from this base is the CI passive baseline against an internal Docker **fake** target
  (`.github/workflows/ci.yml:219-249`, `agentforge-zap-fake` on an `--internal` network). The
  committed live artifact was not produced by that path — see RT-14.

`catalog.py:174` also advertises execution evidence at `postgres://tool_findings?tool=zap`, but no
repository code ingests real tool output into Postgres; the only
`SecurityToolEvidenceRepository.ingest` calls are in tests.

### RT-06 — High, **open**: Burp-style names still overstate feature equivalence

Unchanged. `src/agentforge/security_tools/workbench.py` still labels **six of ten** workbench
capabilities `state='operational'` (lines `37, 45, 69, 77, 85, 95`), including Sequencer and
Comparer. The predecessor's capability-by-capability table stands and is not restated.

Two of those six deserve naming, because they are the ones a reviewer will test first: the
"Scanner" (`:69`) is a ZAP half that only ran against a fake target plus a Judge half that can reach
exactly one substring oracle; the "Sequencer" (`:95`) is conversation ordering, not token-randomness
analysis. Until the literal capability exists, these should read `partial`, `analogy`, or `planned`.

Proxy/Logger/Inspector is the honest exception: it genuinely runs in production
(`security_tools/workbench.py:141-205`, imported at `src/agentforge/api/postgres.py:63` and called at `:3382`).

### RT-07 — High, **open**: the tested target surface cannot exercise several claimed risks

Unchanged in effect. Of the declared surfaces across the environment catalogs, the Week 2
upload/read/RAG surfaces exist but are **disabled**:
`config/live-target-catalog.production.json` declares the three Week 2 surfaces at `:222` (`copilot-week2-app`), `:253` (`copilot-week2-evidence-search`) and `:284` (`copilot-week2-documents`), each with `"enabled": false` at `:250`, `:281` and `:312`. Only the chat
surfaces are enabled, and exactly one payload profile (`copilot_chat`) is authorized.

The consequence is unchanged: upload/RAG poisoning, retrieval metadata bypass, stored memory
poisoning, real tool invocations, writes, recursive tool behavior, and executable output sinks are
simulated in chat rather than exercised and observed. Enabling those surfaces is config-small
(see *Horizon 2*, WP-12) but requires fresh authorization, which is a human action.

Note also that `ownership_authorization_ref` is still validated only as a string beginning
`authorization://` — at **`src/agentforge/target/catalog.py:131-132`** at this base (the
predecessor's `:95-104` is response content-type and timeout validation).

### RT-08 — Medium, **open**: regression planning exists, continuous execution cannot

Worse than "not wired": replay plans are pinned `execution_state: "blocked"` by a JSON-Schema
`const` **and** a database CHECK constraint, so no authorize-and-execute path can exist without a
contract change. `src/agentforge/regression/replay.py:202-217` defines `unsafe_judge_states` as
`{EXPLOIT_CONFIRMED, EXPLOIT_LIKELY, INDETERMINATE, ERROR}`.

Regression admission can also never reach `admitted` in production, because the campaign path
supplies `reproduction_attempted` / `deterministic_reproduction` / `passes_for_right_reason` /
`human_approved` all `False`. The predecessor's improvement — admitted finding → reproduction job →
human approval → exact replay authorization → repeated Runner execution → right-reason assessment →
target-version reappearance alert — is unchanged and unimplemented.

One compounding defect: `target_version` is set to the adapter name, not a target build version
(`src/agentforge/policy/gateway.py:626`). Every finding, coverage row, and regression comparison
keyed on target version is keyed on a constant, which silently defeats regression-across-versions.

### RT-09 — High, **partially addressed**: pre-physical-send gate implemented, proof missing

This is the only item with real movement. A `pre_physical_send_gate` now fires before every physical
send, **including retries and after pacing/backoff**, and is wired in production to a durable
per-`(attempt, turn, retry)` reservation that re-reads lease and persisted authorization:
`src/agentforge/policy/gateway.py:532-548`, nested `revalidate` in
`src/agentforge/runner.py::DurableCampaignRunner._execute_prepared` (currently lines 1753–1790),
`src/agentforge/campaign/coordinator.py:588-611`. Unit and database tests pass.

**Not closed**, for three specific reasons:

1. The test the predecessor demanded — persisted abort **during inter-turn pacing or retry
   backoff** — does not exist.
2. The `store.py` branch that refuses physical work on a non-running run has zero test coverage.
3. The composition is **fail-open if the callbacks are omitted**: nothing structurally prevents a
   caller from constructing the gateway without the gate.

`.tdd-swarm/reports/RTG-orchestrator.md:264` lists this as "**Already done:** WP-01 (RT-09
abort/lease/scope re-check)" while line 128 of the same file says 0 of 14 findings are closed. The
honest reading is the one above: implemented and wired, not proven.

### RT-10 — High, **open**: per-agent database roles are design/test controls

No substantive change. The roles remain `NOLOGIN` and described as exercised through `SET ROLE`
(`src/agentforge/storage/roles.sql`); production code contains no `SET ROLE`, and the campaign
runtime creates one engine from `DATABASE_URL`. The predecessor's four production-composition tests
are unchanged and unwritten.

### RT-11 — High, **partially addressed**: TOCTOU narrowed, no pinning

Destination validation moved out of a once-per-run check into the adapter's `send()`, so it now runs
per physical send. That is a real improvement and it is also the item most likely to be mistaken for
closure.

**The gap is not closed.** The validator calls `getaddrinfo`, and `httpx` then resolves the hostname
again at connect time, so a DNS answer can still change between check and use. The window is
narrowed, not eliminated. The designs the gap-swarm specified —
`src/agentforge/target/destination.py` and `pinned_transport.py` — **do not exist at this base**.
The only real IP pinning in the repository is in the unrelated active-scan path
(`src/agentforge/security_tools/scan_sender.py`).

### RT-12 — Medium, **open**: crashed Runner work can remain leased indefinitely

`PostgresJobQueue.reap_expired()` is implemented in `src/agentforge/storage/queue.py` and still has
**literally zero production callers**. The Runner loop does gain a bounded crash-reservation
recovery step, `src/agentforge/runner.py::DurableCampaignRunner.recover_interrupted_provider_calls`
(currently lines 965–982), which delegates to the store's
`recover_interrupted_hosted_executions` at line 978 — but that recovers hosted executions, not
expired job leases. The finding stands.

### RT-13 — Medium, **open**: ambiguous POST failures can duplicate a conversational turn

No change. The base `AdapterError` is retryable, generic transport failures around an HTTP POST map
to retryable errors, and the retry path (`_dispatch_one_with_backoff` in
`src/agentforge/policy/gateway.py`) may send again. A connection failure remains ambiguous: the
target may have processed the request before the client lost the response. The committed catalog
still allows `target_retries_per_turn: 1`
(`docs/evidence/authorization-requests/caps.json`). No idempotency key bound to run/attempt/turn
exists.

### RT-14 — Medium, **open**; the ZAP evidence/status drift is **resolved in this pass**

Three sub-items unchanged: readiness still passes `runner_available=True` without a fresh Runner
heartbeat; any HTML path outside a few exclusions still receives the public SPA shell, broader than
the enumerated minimal-shell rule in `docs/deployment/RAILWAY.md`; and
`ownership_authorization_ref` is still a bare prefix check
(`src/agentforge/target/catalog.py:131-132`).

The fourth sub-item — the evidence/status drift — is resolved here, and **the drift runs in both
directions**, which no document had recorded:

| Row | Claim | Truth at this base |
|---|---|---|
| `SECURITY_TOOL_EVIDENCE.md:99 @107c11c` | "ZAP live-target scan \| **blocked pending authorization**" | **False.** A passive live-target ZAP baseline ran and its raw artifact is committed and hash-verified: `docs/evidence/zap/zap-target.json`, sha256 `89f10c94…` (recomputed, matches all three metadata records), `byte_length` 7910, ZAP-stamped 2026-07-22 03:33:23 UTC, 3 alerts / 5 instances, all publication-blocked. `docs/evidence/zap/findings.json:43-45` records an `A05:2021` finding with `scan_provenance: live_target`. |
| `SECURITY_TOOL_EVIDENCE.md:97 @107c11c` | "ZAP local fake passive baseline \| **operational and evidenced**" | **Unbacked.** Its artifact `tmp/sec/zap/zap.json` does not exist on disk and no `tmp/` path is tracked by git. **The only committed raw ZAP artifact in this repository is the live one.** |
| `SECURITY_TOOL_EVIDENCE.md:56 @107c11c` | "ZAP Railway staging / live-target self-scan \| blocked pending authorization" | **Half false.** The Railway *staging* self-scan half is still true — no artifact exists. The live-target half is contradicted by the committed artifact. The row conflates two different things and must be split. |
| `SECURITY_TOOL_EVIDENCE.md:205 @107c11c` | "No live target or Clerk domain was scanned in this evidence pass." | **Half false.** The Clerk half is true and code-enforced. The live-target half is false for the same pass. |

Three limits on the live scan that `docs/evidence/zap/README.md` did not state before this pass — they are
now recorded there under *Known limits*, and in the ATO document's reconciliation note — and that a hospital
CISO will ask about first:

1. **It did not run through the platform's own governed command path.** The committed
   `passive_baseline_argv` constructor hardcodes an internal-only Docker network, so it physically
   cannot reach a public origin. The live scan was produced outside that constructor.
2. **Its authorization is free-form prose** — no approver identity, no `operation_hash`, no expiry.
3. **Its `target_id` (`openemr-copilot`) is not a registered entry in the trusted target catalog.**

No **active** scan was ever authorized or run. That chain is code-complete, default-disabled, and
never executed; `docs/security_tools/ACTIVE_SCAN_AND_TOOL_EVIDENCE.md` is honest about it.

Two data-level defects for the owning lane (not corrected here, because they are artifact contents
rather than prose): `docs/evidence/zap/findings.json:22,50,78` carry dangling
`"artifact_locator": "tmp/sec/zaptarget/zap-target.json#finding=N"` values while
`artifact.json:12` correctly points at `docs/evidence/zap/zap-target.json`; and
`docs/evidence/zap/run.json:12-13` has `started_at == finished_at`, a zero-length window whose
stamps post-date ZAP's own generation time by 93 s, so the recorded scan limits (depth 5, ≤10
children, 2-minute spider, 5-minute run) are not corroborated by any artifact.

## Findings inventory — what exists and who produced it

Six `AF-VULN-2026-0724-*` reports exist. After PR #48, the inventory is:

| ID | Classification | Current severity | Evidence provenance | Report authorship |
|---|---|---|---|---|
| 001 | observation | `low` | Platform campaign plus owner Bruno capture | **Human-written**; autonomous-drafting header corrected during submission reconciliation |
| 002 | observation | `low` | Platform campaign | **Human-written**; autonomous-drafting header corrected during submission reconciliation |
| 003 | non-closing observation | `Informational` — not a contract enum member | Platform campaign | **Human-written**; autonomous-drafting/control-validation overstatement corrected during submission reconciliation |
| 004 | control weakness | **`medium`** | **External owner-supplied Bruno client** | **Hand-written** |
| 005 | control weakness | **`low`** | **External owner-supplied Bruno client** | **Hand-written** |
| 006 | control weakness | **`low`** | **External owner-supplied Bruno client** | **Hand-written** |

PR #48 corrected 004–006 in the report bodies themselves. The former `Medium–High` and
`Low–Medium` labels are gone; 004/005/006 now use legal `vuln_report` severity values
(`low|medium|high|critical`). Report 003's `Informational` label is the one remaining value outside
that enum.

001–003 are substantially resistance results rather than defects. The three genuine target-side
control-weakness reports are 004–006, and **all three derive from the owner's external Bruno
collections, not from the platform scanner or a governed platform campaign.** They are legitimate
reports about retained target observations; they are not evidence that the platform discovered a
confirmed exploit.

Each of 004–006 now embeds runnable, read-only derivation code over the 15 retained Bruno
request/response pairs. That makes the reported counts and capture-derived claims reproducible
offline. It does **not** create an independently attested target reproduction: no reviewer log,
attestation, run manifest, separately retained reproduction artifact, or negative-control rerun is
committed. The reports explicitly label reviewer blinding, a second adversarial pass, and no-network
execution as process assertions rather than repository-verifiable evidence.

**On PRD-32 (≥3 genuine, independently reproduced vulnerability reports): the bar remains unmet.**
The file-count half is present, and three distinct target-side control weaknesses are documented, but
none is a confirmed exploit or an independently evidenced target reproduction; all six reports remain
draft/unpublished. `docs/planning/gap-audit.md:66` marks PRD-32 "covered (seam)"; that is an
architecture-seam claim, not completion evidence.

The historical authorship contradiction is now resolved. At `107c11c`, 004–006 claimed
Documentation-agent authorship while `docs/evidence/agent-trace.md:56 @107c11c` recorded that the
runtime Documentation agent drafted nothing (`exploit_confirmed = 0`). PR #48 replaced those headers
with explicit hand-written authorship and explains that the runtime agent emits schema-valid JSON only
after `EXPLOIT_CONFIRMED`. Reports 001–003 are also human-written; their retained "Drafted
autonomously" headers are false/stale and are not evidence of output from the governed runtime
Documentation agent.

## Predecessor cites that no longer resolve

The 2026-07-24 review remains the best analysis in the repository, and it is the most cite-dense.
Thirteen of its file:line anchors no longer resolve to what they claim. They are listed here so the
predecessor can be read safely rather than silently distrusted.

| Predecessor cite | Claim | Where it actually is at this base |
|---|---|---|
| `api/postgres.py:77-79` | required Web/LLM/category sets | `api/postgres.py:124-126` (content unchanged) |
| `runner.py:269,285-288` | Runner constructs `SeedReplayRedTeam` | `DurableCampaignRunner.__init__`, currently `runner.py:827`; `:269` is unrelated hosted-invocation context |
| `runner.py:629-693` | selects exact reviewed cases | `_literal_destination_allowed`, currently `runner.py:636`; the predecessor range is stale |
| `runner.py:716-736` | persisted gate refreshes lease | `_scope_payload_profile` is currently `runner.py:727`; the gate is nested `revalidate` in `DurableCampaignRunner._execute_prepared`, currently `:1753-1790` |
| `runner.py:838-846` | finding flags all `False` | `DurableCampaignRunner._start_agent_execution`, currently `runner.py:845-853` |
| `runner.py:176-193` | resolves and rejects private addresses | `:176-193` is `_sanitize_hosted_transcript` |
| `runner.py:960-1047` | loop does not reap expired leases | `DurableCampaignRunner.recover_interrupted_provider_calls`, currently `runner.py:965-982`; the *claim* about lease reaping is still true, the cite is not |
| `coordinator.py:390-425` | gate invoked once per logical attempt | superseded; see `coordinator.py:588-611` |
| `policy/gateway.py:421-468` | retries check only in-memory caps | `:421-468` is the multi-turn sequential dispatch loop; retries are `_dispatch_one_with_backoff` |
| `campaign/corpus.py:200-210` | five tool cases use a `none` oracle | `:200-210` is `expected_evidence`/`safe_signals` template prose; the five-case claim could not be confirmed at any cited line |
| `target/catalog.py:95-104` | `ownership_authorization_ref` prefix check | `target/catalog.py:131-132` |
| `providers.py:271-282` | hosted generator raises `NotImplementedError` | **fact is false**, not just the cite: `:271-279` returns a real client |
| `openemr_adapter.py:353-387` | adapter sends one chat message | response construction is ~`:373-381`; `:353-387` is telemetry/exception handling |

## Horizon 2 — deferred capability, named

Two work packages from the red-team gap-swarm bundle are **Horizon 2**: out of the current delivery
scope, retained as designs, and not counted toward any coverage or capability claim. The term is
introduced here because the repository had no single label for this; it maps onto the existing
machine-readable tags `pending_runtime`, `local_fixture_only`, and `LIVE_EVIDENCE_REQUIRED` rather
than replacing them.

**WP-11 — Trusted observations and category oracles.** What exists is a pure *evaluator* layer:
five deterministic category oracles plus a canary oracle, each honestly self-labelled
`availability="pending_runtime"` / `runtime_wired=False`. Everything WP-11 actually asks for is
absent: the `src/agentforge/observations/**` package, the `TrustedObservation` /
`RequiredOraclePolicy` / `OracleEvaluation` types, their three JSON contracts, the migration,
owner-side authenticated collectors and attestation, and the `ground-truth-v2` slice. Beyond
schedule, WP-11 is gated on **human-produced ground-truth-v2 labels plus an independent human
reviewer**, which no code lane can supply. And per RT-02, completing WP-11 would not make the five
category oracles fire against a black-box `/chat` target.

**WP-12 — Real versioned target and platform surfaces.** `surface_contracts.py`,
`http_surface_adapter.py`, `stream_surface_adapter.py`, the whole `src/agentforge/platform/`
package, both surface-contract schemas, and `docs/integration/OPENEMR_SURFACE_CONTRACT.md` do not
exist; the capability-state vocabulary (`declared_unverified` / `live_validated` / `unsupported` /
`blocked_missing_contract`) appears only inside the WP-12 prose. The one genuinely small part is the
Week 2 surface config-unpin (RT-07), which is a target-authorization change, not a code change.

Also Horizon 2 by the owner's locked decision: the `attack-case.v2` schema stack and the OWASP
Agentic (ASI01–ASI10) taxonomy. ASI is not in the graded requirement.

Neither package was ever dispatched. `.tdd-swarm/reports/RTG-orchestrator.md:5-6` records the
gap-swarm as `BLOCKED(base-precondition)`, held at Wave 0 entry.

## Prioritized delivery plan

### Gate 0 — Make execution safe and claims truthful

1. Add the RT-09 tests the implementation is missing: persisted abort during inter-turn pacing and
   during retry backoff; cover the non-running-run refusal branch; make the gate
   fail-**closed** when callbacks are absent.
2. Reconcile the two Judge seams so a model can never emit `EXPLOIT_CONFIRMED` on either
   (`HostedFourRoleRuntime.run_attempt`, currently line 754 /
   `HostedFourRoleRuntime._deterministic_precedence`, currently lines 863–866), and add the test.
3. Enforce the per-agent database role boundary in production composition (RT-10).
4. Pin the validated destination address while preserving TLS SNI/hostname verification (RT-11);
   close ambiguous POST retry behavior with an idempotency key bound to run/attempt/turn (RT-13).
5. Run expired-lease recovery from a private worker/scheduler loop (RT-12).
6. Expose multi-state evidence coverage and downgrade inaccurate `operational` labels
   (`workbench.py`, `catalog.py`).
7. Require `run_judge_calibration.py --require-pass` for any non-oracle Judge activation, and put
   it in CI — today it is in neither `scripts/check.sh` nor `ci.yml`.
8. Finish Railway/Clerk/private-service/two-user proof before claiming a deployable live loop.

### Gate 1 — Make LLM results decisive

1. Re-express cases as **canary-anchored** wherever a successful exploit can be made to echo a
   seeded synthetic canary (D26), and seed those canaries in the target as a declared
   `target.canary_refs` set.
2. Wire the **consumption oracle** from the gateway's own meter — the one category oracle that is
   platform-observable rather than target-internal.
3. Leave genuinely unobservable families `INDETERMINATE`. Do not flip `runtime_wired`.
4. Expose the real ingestion, retrieval, memory, tool, write, and output surfaces (WP-12) with
   fresh authorization; mark chat-only approximations `simulated_surface` and exclude them from
   demonstrated coverage.
5. Resolve the authorization-model question that blocks generation (RT-04): bind a generator
   identity plus a review record, or admit a new corpus hash under a second authorization.
6. Add cases for all six PRD categories and all applicable OWASP LLM risks, each bound to an oracle
   that exists and can fire.

### Gate 2 — Use the existing tools deeply

Unchanged from the predecessor: expand the allowlisted Garak probe matrix; use PyRIT multi-turn
orchestration and composite transforms; execute real Giskard owned-target/RAG scans; run Promptfoo
red-team plugins through the governed target boundary; ingest every native artifact and normalized
candidate/finding into the platform; add target-version and tool-version drift detection. Fix
`target_version` first (`policy/gateway.py:626`) or drift detection cannot work.

### Gate 3 — Build literal Burp-equivalent workflows

Unchanged from the predecessor: capture/editor/replay/diff workbench; payload-position fuzzer with
extraction and minimization; authenticated API discovery/import/crawl/scan; session and
multi-principal access-control testing; private OAST; WebSocket/SSE and browser/DOM testing;
continuous regression execution and reappearance alerts.

## Definition of "full LLM red teaming"

Unchanged from the predecessor, and none of it is yet satisfied. Restated here because the closure
standard is the load-bearing part of this document:

- Every applicable target surface is registered and attacked through the Policy Gateway.
- Every applicable OWASP LLM 2025, OWASP Agentic 2026, and OWASP Web category has at least one
  executable boundary, invariant, and regression test — or a documented not-applicable rationale
  approved by a human.
- Every case has a trusted observation mechanism; cases without decisive evidence are shown as
  indeterminate, never passing.
- Mutation and tool generation produce reviewed, content-addressed candidate corpora under new
  authorization.
- All existing tool integrations execute meaningful target-relevant matrices and their results
  enter the evidence and finding system.
- The Burp comparison is literal and test-backed, not name-based.
- A human-approved campaign against the exact live URL, using seeded synthetic non-PHI live records
  and provisioned test principals, produces persisted evidence, independent verdicts, and regression
  candidates — through the platform's production authorization path, with **two distinct
  authenticated principals**.
- Mocks, cassettes, fixture adapters, fake/loopback targets, in-process receivers, local harnesses,
  and simulated artifacts never count as operational, regression, or closure evidence. **A test
  fixture that reads the ground-truth answer key is never calibration evidence.**
- Confirmed findings are deterministically reproduced, fixed for the right reason, replayed on
  target-version changes, and monitored for reappearance.
- The release commit is pushed to both `origin/main` and `gitlab/main`, the refs resolve to the same
  commit, GitHub CI is green on that exact commit, and the same commit is mirrored to GitLab. GitLab
  is passive and has no runner gate.

## External baselines

- [Canonical Burp Suite tool inventory](https://portswigger.net/burp/documentation/desktop/tools)
- [Burp testing workflow](https://portswigger.net/burp/documentation/desktop/testing-workflow)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
