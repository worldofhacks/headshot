export const meta = {
  name: 'm11-integration-review',
  description: 'Read-only integration review of the cherry-picked Codex M11 corpus vs landed M2/M4/M6a/M9 — contract-steward, adversarial-eval-lifecycle, judge-calibration lenses + a validator security/maintainability audit. Findings only; no code changes.',
  phases: [{ title: 'Review', detail: '4 parallel lenses over the 13-item compatibility checklist' }],
}

const REPO = '/Users/quietguy/Documents/Dev/Gauntlet/Adversarial Machine'
const CTX = `
REPO: ${REPO}  BRANCH: swarm/mvp-live-gate (M2+M4+M6a+M9 landed; Codex M11 corpus cherry-picked in: commits
06165c2 + 5ffe0db). READ-ONLY review — do NOT edit any file; do NOT refactor the validator. Activate the venv
for any command you run: \`cd "${REPO}" && . .venv/bin/activate && <cmd>\`.
Corpus files: evals/schemas/{attack-case.v1.json, ground-truth-slice.v1.json, synthetic-fixture.v1.json},
evals/seeds/*.json (9 AttackCase seeds), evals/ground-truth/*.v1.json (15 labels), evals/fixtures/*, evals/results/,
src/agentforge/evals/{validation.py (1942 lines), __main__.py, __init__.py}.
Inter-agent contracts (DO NOT let the corpus duplicate/override these): contracts/v1/{attack_attempt, attempt_result,
verdict, evidence_envelope, campaign_directive, errors, regression_admission}.json.
Landed code to check compatibility against: src/agentforge/policy/{gateway,recorder}.py (M4),
src/agentforge/observability/{tracing,reconcile}.py (M6a), src/agentforge/agents/judge/{judge,envelope}.py (M9),
src/agentforge/storage/models.py (M2). Binding refs: ARCHITECTURE.md (esp. §4/§5, D13/D14/D15/D18),
THREAT_MODEL.md. Report ONLY real issues, each with a severity (critical|important|minor) and a concrete fix.
`

const FIND_SCHEMA = {
  type: 'object', additionalProperties: false,
  properties: {
    verdict: { type: 'string', enum: ['compatible', 'issues_found'] },
    checklist: { type: 'array', items: { type: 'object', additionalProperties: false,
      properties: { item: { type: 'string' }, status: { type: 'string', enum: ['pass', 'fail', 'n/a'] }, evidence: { type: 'string' } },
      required: ['item', 'status', 'evidence'] } },
    findings: { type: 'array', items: { type: 'object', additionalProperties: false,
      properties: { severity: { type: 'string', enum: ['critical', 'important', 'minor'] }, location: { type: 'string' }, problem: { type: 'string' }, fix: { type: 'string' } },
      required: ['severity', 'location', 'problem', 'fix'] } },
    summary: { type: 'string' },
  },
  required: ['verdict', 'checklist', 'findings', 'summary'],
}

phase('Review')
const [contract, evalLC, judgeCal, validator] = await parallel([
  () => agent(
    `CONTRACT-STEWARD lens. ${CTX}
Verify (checklist): (1) the AUTHORING schemas (evals/schemas/*.json) are correctly SEPARATE from the INTER-AGENT
contracts (contracts/v1/*.json) — NO field-for-field duplicate/authoritative second copy of attack_attempt /
attempt_result / verdict / evidence_envelope; compare $id/title/shape and flag any dual authoritative copy that
could drift. (2) The cherry-picks changed NO contracts/v1 file (git show --stat 06165c2 5ffe0db) — so no
inter-agent boundary is a breaking change. (3) attack-case.v1 maps cleanly onto the RedTeam→Gateway attack_attempt
boundary (the fields M8 will need to emit an attack_attempt exist). (4) ground-truth-slice.v1 maps onto the
Judge's evidence_envelope.trusted / verdict boundary (labels align with verdict.json's state enum + reason codes).
(5) OWASP tags in the corpus use {framework,version,id,name} and match D15 (Web=2021 anchor, LLM=2025) as bound in
ARCHITECTURE.md + THREAT_MODEL.md. Run \`python -m pytest tests/contract -q\` to confirm the inter-agent both-sided
contract tests still pass. Return the structured result.`,
    { label: 'review:contract', phase: 'Review', schema: FIND_SCHEMA },
  ),
  () => agent(
    `ADVERSARIAL-EVAL-LIFECYCLE lens. ${CTX}
Verify (checklist): (1) every seed in evals/seeds carries the full field set (category+subcategory, input
prompt/sequence, expected-safe behavior, observed behavior pass|fail|partial, severity+exploitability,
add-to-regression, OWASP tags {framework,version,id,name}, boundary|invariant|regression class) — NO
happy-path-only case. (2) OWASP tags are Web=2021 / LLM=2025 (D15). (3) AttackCase seed records map cleanly into
M8 seed ingestion (the fields M8 needs to select, sequence multi-turn, and dispatch a case are present + typed).
(4) hostile/adversarial seed + fixture content is carried as INERT DATA (never executed/interpreted as
instructions by the validator or ingestion). (5) duplicate normalization preserves MEANING across multi-turn
sequences (run \`python -m agentforge.evals detect-duplicate-sequence evals/seeds\` and read how validation.py
normalizes a sequence — a reorder/paraphrase that changes meaning must not be collapsed, and a trivially-equal
sequence must be caught). Return the structured result.`,
    { label: 'review:eval-lifecycle', phase: 'Review', schema: FIND_SCHEMA },
  ),
  () => agent(
    `JUDGE-CALIBRATION lens. ${CTX}
Verify (checklist), reading src/agentforge/agents/judge/judge.py + envelope.py + evals/ground-truth/*.json +
evals/schemas/ground-truth-slice.v1.json: (1) ground-truth labels map cleanly into M9 (each label's expected
verdict state is one of the M9 verdict-state enum {EXPLOIT_CONFIRMED,EXPLOIT_LIKELY,NO_EXPLOIT_OBSERVED,
INDETERMINATE,ERROR}; the label shape is consumable as trusted.ground_truth_ref / a calibration input). (2)
Oracle/canary evidence ALONE produces EXPLOIT_CONFIRMED (confirm the ground-truth oracle-hit cases expect
EXPLOIT_CONFIRMED and M9 delivers it). (3) A model judgment cannot downgrade an oracle (M9 reads trusted signals
only). (4) Ambiguous / contradictory / missing / uncalibrated / timed-out / below-threshold ground-truth cases
map to INDETERMINATE at MVP (never NO_EXPLOIT_OBSERVED/EXPLOIT_LIKELY). (5) No ground-truth label asserts a
NON-oracle EXPLOIT_CONFIRMED (only oracle/canary/human may confirm). Flag any label whose expected disposition
would violate D13. Return the structured result.`,
    { label: 'review:judge-cal', phase: 'Review', schema: FIND_SCHEMA },
  ),
  () => agent(
    `VALIDATOR SECURITY + MAINTAINABILITY audit of src/agentforge/evals/validation.py (1942 lines) + __main__.py +
evals/results/. ${CTX}
Do NOT refactor for line count. Verify (checklist): (1) validator DIAGNOSTICS / error messages never ECHO
hostile transcript content or a secret-bearing value verbatim (grep for where it prints/raises with case
content; a malformed hostile payload must not be reflected raw into output). (2) NO fixture or local validation
result is presented as a LIVE result (evals/results/ + the CLI make the offline/NOT_EXECUTED status explicit).
(3) All corpus cases remain NOT_EXECUTED until an authorized campaign runs (there is a status field / the results
dir has no fabricated 'observed' results). (4) The validator makes NO network call and reads NO live target /
credential / provider key (grep for http/requests/urllib/socket/env-secret reads). (5) Maintainability: is the
1942-line validator reasonably structured (named checks, clear failure taxonomy) — note real smells but propose
NO line-count refactor. (6) Does the validator re-implement / duplicate an inter-agent contract schema instead of
referencing contracts/v1? Return the structured result.`,
    { label: 'review:validator', phase: 'Review', schema: FIND_SCHEMA },
  ),
])

return { contract, evalLifecycle: evalLC, judgeCalibration: judgeCal, validator }
