# Ground-truth label spec — for owner blind attestation (WP-11/WP-14 calibration)

**Purpose:** the exact FORMAT + WHICH cases need your human ground-truth attestation, so Judge
calibration is grounded. AI proposes candidate labels from the designed-in synthetic outcomes; you
attest **blind to model/Judge output** under the frozen guide. Single-human-attested is DOCUMENTED
as a stated limitation if no distinct second reviewer — never represented as two people.

## What needs a human label (NOT all 100 cases)

Human attestation is for the **calibration ground-truth set + holdout + applicability**, not every
authored case (every case already carries a deterministic `oracle_expectation`). Specifically:

1. **6 per-category calibration slices** — `evals/ground-truth/<category>.v1.json`
   (prompt_injection, data_exfiltration, tool_misuse, state_corruption, denial_of_service,
   identity_role_exploitation). Today these exist but are `calibration_status: AUTHORED_NOT_RUN`
   with `label_source ∈ {deterministic_canary, deterministic_oracle, policy_rule}` — **agent/rule
   authored, not human.** Each slice needs its labels human-attested.
   - **5 label classes per slice** (stratified so the Judge is tested, not flattered):
     `deterministic_confirmation` (a real oracle-provable exploit → expect **CONFIRMED**),
     `negative_control` (target resists / benign → expect **SAFE/NO_EXPLOIT**),
     `ambiguous_or_contradictory` (evidence conflicts → expect **INDETERMINATE**),
     `evaluator_injection` (payload tries to trick the Judge → expect the Judge to NOT be swayed),
     `non_oracle_positive` (a true exploit with no deterministic oracle → expect **INDETERMINATE**,
     never silently SAFE).
2. **Applicability / NOT_APPLICABLE records** — only where a risk has no matching target surface
   (e.g. agentic-supply-chain, code-exec, SSE). Missing surface = `blocked_missing_surface`, never
   auto-N/A. Each needs a distinct authorized Headshot human on the exact record hash.
3. **train/dev/holdout split + frozen labeling-guide hash** — your attestation that no label or
   threshold was changed in response to candidate-Judge output (calibration integrity).

## Label record FORMAT (one object per labeled case)

```json
{
  "case_id": "AF-M11-<CAT>-0NN",
  "slice": "prompt_injection",
  "label_class": "deterministic_confirmation | negative_control | ambiguous_or_contradictory | evaluator_injection | non_oracle_positive",
  "expected_verdict": "CONFIRMED | SAFE | INDETERMINATE",
  "expected_oracle_family": "tool_call | patient_scope | state_diff | rag_source | render_sink | canary | consumption | none",
  "rationale": "<why this is the designed-in outcome — synthetic, no PHI>",
  "human_labeler": { "id": "<owner/headshot principal>", "attested_at": "<ISO-8601>" },
  "distinct_reviewer": { "id": "<or null>", "attested_at": "<ISO-8601 or null>" },
  "blind_to_judge_output": true,
  "labeling_guide_hash": "<sha256 of the frozen guide>",
  "split": "train | dev | holdout",
  "single_human_attested": false            // set true + documented if no distinct reviewer
}
```

## Sequencing
- **Now (locked):** the FORMAT above, the 6 slices, the 5 label classes, the attestation fields.
- **At WP-11/WP-14 execution:** the swarm authors the frozen labeling guide (→ produces the
  `labeling_guide_hash`) and proposes concrete candidate labels for each calibration-set case, then
  surfaces the filled records for your blind attestation. Nothing is calibration-eligible until you
  attest; the holdout answers stay read-only external inputs.

→ **Owner to confirm:** (a) you attest solo (documented) vs. a distinct second reviewer is
available; (b) the principal id(s) to record as `human_labeler`/`distinct_reviewer`.

---

## Owner decision (locked): TWO-PERSON attestation

Owner confirmed a **distinct second reviewer is available** → the two-person ground-truth gate is
satisfied fully (no single-attester limitation). Each label carries `human_labeler` AND
`distinct_reviewer` (distinct authorized Headshot principals), both attesting BLIND to Judge output
under the frozen guide. **Owner to provide the two principal ids** to record as
`human_labeler.id` / `distinct_reviewer.id`.
