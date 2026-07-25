# Judge re-attest runbook — bind calibration to the deployed identity

**Status: harness wired, re-attest NOT run.** The measurement below is blocked on two inputs that
do not exist yet (§1). Nothing in this document reports a result; it is the procedure the result
will come from.

The prior measurement (`RESULT_2026-07-24.md`, commit `8ce852b`) is **superseded and must not be
carried forward** — see §5 for exactly why, and for what part of it was and was not sound.

---

## 1. Blocked on — ONE input remains

| # | Input | Owner | Status |
|---|---|---|---|
| B1 | Staged **production** hosted configuration set + its attested `configuration_sha256` | **integrator** | **STILL BLOCKING.** The Judge identity is derived from it. No staged payload exists anywhere on the integration head — production role configs live in the Postgres `hosted_configuration_sets` table. Without it there is nothing to bind to, and a capture would again attest a configuration production does not run. |
| B2 | Two-person human ground-truth attestation | g + a distinct approver | **LIFTED for the deadline** (owner). Enablement now accepts a weaker, explicitly-named baseline — see §1b. |
| B3 | OpenRouter usage export | — | **OPTIONAL** (owner). Enablement now accepts `lineage_consistent` — see §1b. |

A further constraint is not a blocker but changes the plan — see §4 (56-call ceiling).

## 1b. Graded provenance — accept a weaker baseline, never disguise one

Provenance is **computed from the evidence supplied**, never declared
(`src/agentforge/agents/judge/provenance.py`). The approving human names the weakest tier they
accept; enablement refuses if the real tier is weaker, and the accepted tiers are encoded into
`approver_ref` so the downgrade travels **inside** the artifact.

| Ground-truth tier | Meaning |
|---|---|
| `human_two_person` | two distinct identified principals, blind to Judge output |
| `model_labeled` | every label names the model that proposed it |
| `rule_derived` | **what is on disk today** — labels derived in code from a static design table |
| `unattested` | no label provenance at all |

| Provider tier | Meaning |
|---|---|
| `usage_export_reconciled` | every sample matched to the provider's own usage export |
| `lineage_consistent` | **what the committed bundle earns** — unique provider-shaped request ids, provider-reported distinct costs and token counts. Strong circumstantial evidence, *not proof* |
| `unverified` | shape-valid only |

**The committed corpus classifies as `rule_derived`, not `model_labeled`.** The 54 labels come from
`_LABEL_TABLE[slug]` in `scripts/build_calibration_corpus.py` — resolved in code from the sample
slug, with no model involved. Reporting them as "automated-labeled (model X)" would name a model
that does not exist. The `model_labeled` tier is implemented and waiting for a set that genuinely
has one.

The disclosure the report must carry at the current tiers, verbatim:

> Ground truth: automated-labeled baseline — labels derived in code from a static design table
> (`scripts/build_calibration_corpus.py`), NOT model-labeled and NOT human ground truth. The labels
> encode what the corpus author intended each sample to be, so the measurement shows agreement with
> that intent, not with an independent judgement of the evidence. Provider calls: consistent with a
> real provider run, NOT reconciled against the provider's records — unique provider-shaped request
> ids, provider-reported per-sample costs and distinct token counts. Strong circumstantial evidence;
> it is not proof the calls occurred.

Relaxing label provenance does **not** relax the human approver: `--approver-ref` and `--confirm`
are unchanged, and enablement remains a separate, attributable human act.

## 2. What m hands over

One file in `HostedConfigurationSet.canonical_payload()` shape — the four-role set **as deployed**:

```json
{
  "schema_version": "1",
  "roles": [ { "role": "judge", "provider": "openrouter", "model_id": "...",
               "upstream_provider": "...", "credential_reference": "...",
               "prompt_sha256": "...", "policy_sha256": "...",
               "prices": {...}, "limits": {...} }, ... ],
  "global_limits": { ... }
}
```

plus the `configuration_sha256` the deploy attested. The secret behind `credential_reference` is
**not** handed over — only the reference string is identity-bearing, and the capture resolves the
value locally from `OPENROUTER_API_KEY`.

Reconstruction is itself a check. `HostedRoleConfiguration` rejects a `prompt_sha256` that is not
this release's server-owned role prompt, so a prompt change between deploy and calibration is a
refusal, not a silent pass.

### What the identity does and does not cover

Stated precisely, because "model/prompt/limits" is only mostly true:

| Covered by `judge_model_version` | **Not** covered |
|---|---|
| `model_id`, `provider`, `upstream_provider` | per-call generation envelope — `HostedCallBounds` (`max_tokens`, reasoning budget, timeout) lives outside `JudgeIdentity` |
| `prompt_sha256` (and it must match the served prompt) | the Judge output JSON schema |
| `policy_sha256` | the 24,000-char evidence truncation bound |
| budget limits: `max_calls`, `max_usd`, token caps, retries, rps, concurrency | temperature / top_p — never sent on the Judge path at all |
| `prices`, `credential_reference` | |

So a change to the per-call token budget or the assessment schema will **not** invalidate a
calibration, even though it can change model behaviour. Two consequences for m: pin
`HostedCallBounds` alongside the configuration set when attesting, and treat a schema change to
the Judge assessment as requiring recalibration by convention, since the identity hash will not
catch it. Extending `JudgeIdentity` to cover them is a `judge_calibration` contract change and
belongs with `contract-steward`, not here.

Note also that `policy_sha256` is an unvalidated free hex label. In the superseded capture it was
`sha256("judge-calibration-capture:judge:v1")`, which resolves to no registered policy. m should
stage the real policy identity.

## 3. Procedure

Let `R=evals/results/judge-calibration-<run-id>`.

```bash
# (a) plan — free, no provider call. Prints the batch split and the derived identity.
PYTHONPATH=src python scripts/capture_judge_calibration.py \
  --hosted-configuration-set <staged-prod-config.json> \
  --expected-configuration-sha256 <sha-m-attested> \
  --output-dir "$R" --capture-run-id <run-id> --plan-only

# (b) capture — REAL, BILLED. One invocation per batch; the SAME staged config every time.
for i in $(seq 0 $((BATCHES-1))); do
  PYTHONPATH=src python scripts/capture_judge_calibration.py \
    --hosted-configuration-set <staged-prod-config.json> \
    --expected-configuration-sha256 <sha-m-attested> \
    --batch-index "$i" \
    --output-dir "$R/batch-$i" --capture-run-id "<run-id>-b$i" \
    --confirm-provider-spend
done

# (c) merge — refuses on identity drift, overlap, or an uncovered label
PYTHONPATH=src python scripts/merge_calibration_batches.py "$R"/batch-* --output-dir "$R"

# (d) provenance — reconcile against OpenRouter's own record. Without this the artifact is
#     shape-valid, not measured.
PYTHONPATH=src python scripts/verify_calibration_provenance.py \
  --captured-results "$R/captured-results.json" \
  --usage-export <openrouter-usage-export.csv> \
  --ledger-total-usd "$(jq -r .measured_usd_total "$R/batch-manifest.json")" \
  --output "$R/provenance-attestation.json"

# (e) measure — network-free, over the merged bundle
PYTHONPATH=src python scripts/run_judge_calibration.py \
  --captured-results "$R/captured-results.json" \
  --expected-identity "$R/judge-identity.json" \
  --threshold-policy accepted --require-pass \
  > "$R/calibration-accepted.json"

# (f) restate over the stratum the model governs, with per-batch visibility
PYTHONPATH=src python scripts/analyze_judge_calibration.py \
  --calibration "$R/calibration-accepted.json" \
  --batch-manifest "$R/batch-manifest.json" \
  --output "$R/stratified-report.json" \
  --require-non-oracle-pass

# (g) human enablement — refuses unless every gate in §6 holds.
#     Full-strength form:
PYTHONPATH=src python scripts/enable_model_judge.py \
  --calibration "$R/calibration-accepted.json" \
  --hosted-configuration-set <staged-prod-config.json> \
  --expected-configuration-sha256 <sha-attested> \
  --ground-truth-attestation <two-person-attestation.json> \
  --provenance-attestation "$R/provenance-attestation.json" \
  --accept-ground-truth-tier human_two_person \
  --accept-provider-tier usage_export_reconciled \
  --approver-ref <authorized-human> \
  --output "$R/calibration-enabled.json" --confirm

#     Deadline form — weaker baseline, explicitly named and recorded in the artifact:
PYTHONPATH=src python scripts/enable_model_judge.py \
  --calibration "$R/calibration-accepted.json" \
  --hosted-configuration-set <staged-prod-config.json> \
  --expected-configuration-sha256 <sha-attested> \
  --captured-results "$R/captured-results.json" \
  --accept-ground-truth-tier rule_derived \
  --accept-provider-tier lineage_consistent \
  --approver-ref <authorized-human> \
  --output "$R/calibration-enabled.json" --confirm
# -> approver_ref becomes "gt=rule_derived;prov=lineage_consistent;by=<authorized-human>"
```

Steps (a)–(f) report whatever the numbers are. Step (g) is the only one that grants authority, and
it is a separate human act.

### Batching, and why not just raise the cap

`limits` is inside the Judge role's `configuration_sha256`, which *is* `judge_model_version`. So
raising `max_calls` to fit a bigger corpus changes the identity being attested — the batches would
measure different evaluators and could not be aggregated at all. Batching keeps one identity and
splits the work instead; `merge_calibration_batches.py` refuses unless every sub-run carries a
byte-identical `judge_identity`, the batches are disjoint, and their union covers the corpus
exactly. Coverage is checked against the slice directory rather than the batch manifests, so a
sub-run that was never captured cannot hide behind a smaller, easier corpus.

`generation_policy_sha256` is bound to the campaign (corpus size + batch size), not the per-batch
sample count, so it too is constant across sub-runs and the merged bundle has one coherent value.

The aggregate over all batches is the number that governs. Per-batch metrics are reported alongside
so a degraded sub-run stays visible instead of being averaged away.

> **Carry this into the real run.** On the rehearsal split of the committed 54-sample bundle, the
> two halves were not equivalent: batch-0 scored non-oracle agreement **0.9524** and batch-1
> **0.8571**, against a 0.9048 aggregate that shows neither. That spread is a property of which
> labels landed in which half — batches are cut from the corpus sorted by `label_id`, so a batch
> can concentrate one category's hard cases. **Report the per-batch table with the real numbers,
> and if one batch sits near or under `min_agreement_rate` while the aggregate passes, say so
> explicitly rather than letting the aggregate speak for it.** A batch that fails on its own is
> not automatically disqualifying — the aggregate is the defined gate — but it is a finding, and
> it is the kind of thing an aggregate is designed to hide.

**Cost:** one physical Judge call per label. The 54-label slice set measured $0.75823375, so budget
**~$0.014/label** — about **$2.80 for a 200-label corpus** across 4 batches of 56/56/56/32.

## 4. The 56-call ceiling — the corpus cannot be captured in one run

`HostedLimits.max_calls` is capped at `HOSTED_MAX_PHYSICAL_CALLS = 56`
(`src/agentforge/agents/hosted.py:27,56,230`). One label costs one physical Judge call, so:

- the **54-label** slice set fits in a single capture (~$0.76 measured previously);
- the **200-label** candidate corpus (`GT-CAND-M11-LIVE100`, 100 cases × 2 labels) **cannot be**,
  under any valid configuration.

`_require_capacity` refuses rather than relaxing the staged limits — and relaxing them would be
self-defeating, because `limits` are inside `judge_model_version`, so a widened cap produces a
*different identity* than the deployed one. A larger corpus must be captured as several
identity-bound batches. That work is not done and is not costed here.

## 5. Why the previous number is superseded

The 8ce852b headline was **agreement 0.9259 / FN 0.0000 / FP 0.0000**. Three separate statements,
kept distinct because they are not equally serious:

**(a) The provider calls were real.** 54 unique OpenRouter request ids, 54 distinct token triples,
53 distinct measured costs summing to $0.75823375. This was not simulated, and the prior evidence
did not claim otherwise.

**(b) The evidence judged was authored, not executed.** Every ground-truth envelope carries
`campaign_run_id: "ground-truth-unexecuted"`, and the trusted canary detail says so in as many
words: *"Authored deterministic confirmation for offline calibration; it is not evidence that a
live target was executed."* That is the correct design for a labelled calibration corpus — you
cannot harvest 54 labelled exploits from a live run — but it means the measurement is about the
**evaluator**, never about the target. The capture manifest now records this explicitly under
`evidence_provenance`.

**(c) The identity it attested does not exist in production — this is the disqualifying defect.**
The old capture built its own `HostedConfigurationSet`, so `judge_model_version` hashed a
capture-invented `credential_reference`, capture-invented `prices`, and `limits` **sized to the
label count**. Two consequences, both verified by test:

- the same evaluator measured over 54 vs 56 labels yields *different* `judge_model_version` values
  (`tests/test_judge_calibration_capture_binding.py`); and
- `load_judge_calibration_status` compares `judge_identity` against the running identity and
  returns `invalidated / identity_drift` when they differ — so the artifact
  `RESULT_2026-07-24.md` offers as *"Frozen identity — hand this to integration"* would have been
  rejected by the runtime it was handed to.

The measurement was honest about its metrics. It was bound to the wrong thing.

**(d) Two definitional blind spots remain in the contract's own counters**, disclosed previously
and now measured rather than only described:

- `false_positive` is `expected NO_EXPLOIT_OBSERVED and actual positive`. An
  `INDETERMINATE → EXPLOIT_LIKELY` over-call scores as neither FP nor FN. The old run had **4** of
  them, invisible behind "FP 0.0000".
- Oracle-backed samples are pooled into the headline even though a trusted hit decides them in
  code. Re-stratifying the committed artifact: pooled agreement **0.9259** over 54, but
  **0.9048** over the 42 samples the model actually decides, with all 12 oracle-backed samples at
  1.0000. The pooled figure is lifted by samples the model cannot influence.

## 5b. The measurement pipeline cannot prove a provider call happened

`scripts/run_judge_calibration.py --captured-results` replays an **operator-supplied JSON file**.
`calibration_results.py` validates its *shape* only: no request-id format check, no cost
re-derivation, no network. A hand-written bundle naming a nonexistent model, with 0 tokens and
$0.00 cost and no `OPENROUTER_API_KEY` set, produces a contract-valid, content-addressed
`state: passed` artifact with agreement 1.0 under the **strict** policy, exit 0. This was
reproduced independently twice during review.

The consequence is not that the previous run was faked — the opposite is more likely. Its
per-sample costs are read from OpenRouter's own `usage.cost` field
(`providers/openrouter.py:647`) and match Gemini 2.5 Pro's real list price (1.25 / 10 per M),
**not** the repo's own 5 / 30 price ceilings; a fabricator working from repo constants would have
produced different numbers. The 54 request ids are unique, OpenRouter-shaped, and their embedded
timestamps rise monotonically over a 650-second window ending 11 seconds before `captured_at`.

The consequence is about **what a passing artifact proves**: the arithmetic, not the provenance.

**This is now closed by requirement, not by convention.** `scripts/verify_calibration_provenance.py`
reconciles the bundle against OpenRouter's own usage export — every sample's `provider_request_id`
must appear in it, with matching model, cost and tokens, and the summed cost must reconcile with the
ledger. A fabricated request id has nothing to match. The resulting
`provenance-attestation.json` is a **required input to `enable_model_judge.py`**, so a bundle that
is merely shape-valid cannot license runtime authority.

The export is CSV or JSON; columns are resolved case-insensitively against a documented alias set,
and if a required column cannot be resolved the tool prints the headers it actually saw and refuses
rather than guessing — a column guessed wrong would "verify" nothing.

What the attestation does **not** prove, and says so in its own body: that the evidence judged came
from a live target. The corpus is authored synthetic ground truth. The attestation establishes only
that the Judge model calls really happened and cost what the bundle claims.

The capture manifest's `identity_binding`, `batch` and `evidence_provenance` blocks record what each
sub-run was bound to and that the evidence was authored, so a reader does not have to infer it.

## 6. Gates on `runtime_enabled = true`

`scripts/enable_model_judge.py` refuses unless **all** hold:

1. `state == "passed"`;
2. the calibration's `judge_identity` equals the identity re-derived from the staged config;
3. the staged config hashes to the operator-attested `configuration_sha256`;
4. the **non-oracle stratum** — not the pooled headline — satisfies the thresholds, and no
   expected-positive sample was scored `NO_EXPLOIT_OBSERVED`;
5. ground truth carries a two-person attestation (`human_labeler ≠ distinct_reviewer`, both
   identified and timestamped) bound to the exact `slice_set_sha256`, `blind_to_judge_output`;
6. a provenance attestation reconciling the bundle against the provider's usage export, bound to
   the same identity and covering **every** scored sample;
7. a named `--approver-ref` and explicit `--confirm`.

The written artifact is then re-checked through `require_model_judge_enablement`, so what lands on
disk is exactly what the runtime will accept.

## 7. What enabling does and does not change

**Unchanged — the Judge still cannot confirm an exploit.** Enforced twice on the
`HostedEvaluator` path: the hosted assessment schema has no `EXPLOIT_CONFIRMED` member
(`agents/judge/hosted.py`), and `verdict.json` restricts an `EXPLOIT_CONFIRMED` verdict's
`confirmation_source` to `oracle | canary | human`, so `calibrated_model` cannot carry one.
`reconcile_judge_assessment` returns the deterministic verdict whenever ground truth is
`EXPLOIT_CONFIRMED` or `ERROR`. **Confirmation stays oracle / canary / human.**

> **This was NOT true on the second model-Judge path, and is repaired in this change — read this
> before landing PR #50.**
>
> `HostedFourRoleRuntime` — the four-role composition `run_attempt` PR #50 builds on — took two
> authorities from the model's own response:
>
> 1. its verdict enum included `EXPLOIT_CONFIRMED`, and `_deterministic_precedence` returned it
>    unchanged when no oracle or canary had fired. Since `run_attempt` drafts a vulnerability
>    report for any `EXPLOIT_CONFIRMED`/`EXPLOIT_LIKELY` verdict, a model that claimed a
>    confirmation produced Documentation output for a finding with **no evidence behind it**; and
> 2. the guard refusing an uncalibrated `NO_EXPLOIT_OBSERVED` was keyed on a `calibrated` boolean
>    **the model emitted about itself** — so a model asserting its own calibration could clear a
>    case. This is the dangerous direction.
>
> Both were reproduced by execution. Repaired here: `EXPLOIT_CONFIRMED` is removed from the model's
> output schema, a model-claimed confirmation is downgraded to `EXPLOIT_LIKELY` with reason
> `model_confirmation_refused`, and calibration status is passed in from the caller's enablement
> gate. Pinned by `tests/test_hosted_runtime_confirmation_authority.py`.
>
> The class had no production composition root before now — only tests constructed it — and its
> `__init__` is itself gated by `require_model_judge_enablement`, which is why this had not yet
> caused a bad finding. PR #50 gives it one.

**Unchanged — `INDETERMINATE` stays visible and is never safe.** `is_safe()` is true only for
`NO_EXPLOIT_OBSERVED`. A model that abstains, errors, or is gated off leaves the case
`INDETERMINATE`; it is never relabelled or collapsed into a pass.

**Changed — and this is the whole of it.** Cases with no trusted hit stop being forced to
`INDETERMINATE` by the MVP rule and instead receive an `EXPLOIT_LIKELY` / `NO_EXPLOIT_OBSERVED`
*assessment*. That is the only stratum enablement touches, which is why §6.4 gates on it.

## 8. Residual risk, stated plainly

Calibration does not prove the Judge cannot be fooled. It measures one evaluator identity against
one authored corpus at one point in time. The containment is structural, not statistical: oracle
precedence, an assessment schema without a confirmation state, `INDETERMINATE` never counting as
safe, and human approval on publication. A non-oracle false negative that this corpus does not
contain will not be detected by this measurement — the thresholds and the drift kill-switch bound
that risk, they do not eliminate it.
