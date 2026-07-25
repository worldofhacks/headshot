# Corpus lane (g) → integration lead (m) handoff — headshot-live-100-v1

**Branch:** `rtg/wp11-wp14` (off `8ce852b`; align/rebase onto the pinned `ce7ab84`).
**Status:** corpus finalize COMPLETE; authored/reviewed corpus only; invariants preserved
(canary/oracle/human = the ONLY CONFIRM authority; LLM = EXPLOIT_LIKELY/NO_EXPLOIT_OBSERVED, never
CONFIRM; INDETERMINATE ≠ safe).

## Commits to integrate (in order)
1. `d9d7b4a` — corpus `headshot-live-100-v1` (manifest sha `07d649…252d`): 100 cases, 6 categories,
   79 single + 21 two-turn = 121 physical; content-addressed (100 cases + 100 gen + 100 review
   sidecars); embedded 14-case reviewed baseline; `corpus.py` LIVE_100 reconciled to 6 categories.
2. `d896908` — consumption oracle wired from the gateway meter (measured elapsed_ms / request_count /
   response_size only; token/cost NOT fabricated). **Migration `0018`** (expand-only nullable JSONB
   `attempt_result.resource_measurements`) — single head ← `0017`. Full suite 1524 passed; code +
   security review APPROVED.
3. `f43ef2f` — caps envelope (100/121/0 exact-match; budget 50 / timeout 3600 / rps 0.5 / attempts
   130) across the 4 catalog files. **REVIEW FLAG:** it was written to `production.json` too — scope
   to only the catalog the run binds if production should stay tighter.
4. (this commit) — finalize: batch manifest, end-to-end confirm proof, candidate labels.

## Corpus shape (final)
- **100 cases** — PI 20 · DX 18 · TM 18 · SC 15 · DoS 14 · IR 15; every case OWASP-tagged (Web+LLM) +
  `oracle_expectation`.
- **Decisive layers:** 59 canary-anchored (33 `SYNTH_CANARY_PATIENT_BETA_8C1E` + 26
  `SYNTH_CANARY_SYSTEM_PROMPT_4D2B` — the 2 genuinely-seeded canaries) → `EXPLOIT_CONFIRMED` on a real
  echo; 14 consumption (DoS, measured breach) → `EXPLOIT_CONFIRMED`; 23 non-oracle → LLM assessment
  (`EXPLOIT_LIKELY`/`NO_EXPLOIT_OBSERVED`); 4 baseline recorder-oracle (unwired) → honest INDETERMINATE.
- **Guaranteed-confirm canary cases: 59** (campaign needs ≥1). Mechanism proven end-to-end for 5 real
  cases across 5 categories in `tests/test_live_100_canary_confirm.py` (deterministic FIXTURE proof —
  seeds the canary in a synthetic response; NOT live evidence).

## ⚠️ CRITICAL run-structure decision for m — batch as 3 sub-workloads
`HOSTED_MAX_PHYSICAL_CALLS=56` (`hosted.py:27`) and the runner **does NOT chunk** — it passes the full
corpus size as one `case_count` (`runner.py:1187-1190`), so a single 100-case hosted invocation fails
closed (`hosted_role_cap_incompatible`, `runner.py:228-234`). Therefore the campaign **must be
submitted as 3 separately-authorized sub-workloads**, aggregated. See `evals/workloads/
live-100-batches.json`:
| batch | cases | physical (Σturns) | ≤56? | guaranteed-confirm canary |
|---|---|---|---|---|
| live-100-batch-01 | 34 | 41 | ✅ | ✅ |
| live-100-batch-02 | 33 | 40 | ✅ | ✅ |
| live-100-batch-03 | 33 | 40 | ✅ | ✅ |
- **No cap raise** — `HOSTED_MAX_PHYSICAL_CALLS` stays 56; both physical notions fit
  (target-side Σturns ≤56 AND hosted-call `case_count × (1+retries)` ≤56). Budget 3 × ≤$10 = ≤$30 < $50.
- **Per-batch caps:** each batch run needs its OWN exact-match caps (`logical=case_count`,
  `physical=Σturns`, `retries=0`) — the `headshot-live-100-v1` caps (121) are the aggregate ceiling.
  **m owns** either registering 3 batch corpus_ids (manifests + caps) or adding a run-time slice path;
  the corpus lane can build 3 loadable sub-corpora on request.

## Ground-truth labels (candidate — needs your two humans)
`evals/ground-truth/live-100-corpus-candidate.v1.json` (sha `adf733ba…`): 200 paired candidate labels
(success/resist) covering all 100 cases; `calibration_status=AUTHORED_PENDING_HUMAN_ATTESTATION`,
`label_source=authored_candidate`; `human_labeler`/`distinct_reviewer` left empty for the **two
distinct principals** to attest BLIND. The 6 v-calibrated slices (`slice_set_sha256 39e1b72d`) are
**not overwritten**. **v-interaction:** adopting this whole-corpus set into calibration changes
`slice_set_sha256` → `calibration_id` → v must re-calibrate + re-attest before any LLM disposition is
enabled on it.

## RUN preconditions (external, not corpus-lane)
price correction landed (node) · LLM Judge enabled (v, `human_approved:true`) · deploy the release
(m) · two distinct principals authorize→approve via the Web API (launcher ≠ approver, code-enforced).
