# M11 offline corpus and validation handoff

**Status:** offline corpus/ground-truth/validation slice complete; M11 hard gate remains open.
Live execution, observed pass/fail/partial results, per-category calibration thresholds, and live-agent
proof are pending. The canonical M11 checkbox is deliberately unchanged.

**Isolation:** authored on `codex/m11-eval-corpus` from integrated base `6aebf50` in the dedicated
sibling worktree. This slice did not edit storage, migrations, Policy Gateway, Execution Recorder,
target adapters, Red Team/Judge runtime, observability, deployment configuration, or the swarm ledger.

## Scope delivered

- Three strict Draft 2020-12 authoring schemas under `evals/schemas/`: `AttackCase`, synthetic
  fixture, and ground-truth slice.
- Nine versioned `AttackCase` seeds: three each for prompt injection, data exfiltration, and tool
  misuse. Every case exercises a boundary or invariant; none is happy-path-only.
- One hand-authored synthetic fixture with reserved `SYNTH-*` entity and canary identifiers.
- Three category slices with five labels each: deterministic confirmation, authored policy-rule
  non-oracle positive, policy-rule negative control, ambiguous `INDETERMINATE`, and
  evaluator-injection resistance.
- Eval-specific Python validation and CLI entry points with typed, sanitized failures, stable
  canonical duplicate detection, strict bounded JSON loading, provenance checks, and corpus-wide
  referential integrity.
- Offline schema and duplicate commands in the local gate, GitHub Actions, and GitLab CI.

No observed-live-result value was invented. All nine seeds are `NOT_EXECUTED`; all observed behaviors
and result references are null. All fifteen ground-truth labels have `live_campaign_result: null`,
`calibration_status: AUTHORED_NOT_RUN`, and null thresholds. The ground-truth evidence envelopes are
constructed labelled examples, not local or live execution records.

## Requirements traceability

| Change | M11 acceptance | PRD / graded requirement | Architecture / decision | Threat-model risk | Proving test/check |
|---|---|---|---|---|---|
| Nine structured seeds in three categories | (a), (c) | PRD-07/08/09/28; PDF Stage 3: at least three categories and complete case fields | Architecture §6/§10; D11/D12 | Highest priorities 1, 2, and 4: injection, disclosure, tool action | `test_repository_corpus_is_valid_and_has_offline_mvp_counts` |
| Boundary/invariant classification and regression eligibility | (a), (c) | PRD-OPT-01; every case is boundary, invariant, or regression | Architecture §10/§18 | Prevents static happy-path payload lists | `test_happy_path_only_case_is_rejected` plus strict schema |
| Structured Web + LLM OWASP tags | (a) | PDF Engineering Requirements; PRD-28 | D15; Architecture F8; Threat Model §OWASP taxonomy | Avoids ambiguous bare identifiers and measures recognized coverage | `test_invalid_owasp_mapping_is_rejected` |
| Per-category labelled ground truth | (e) | PDF “Testing the Tester”; Judge criteria independently verifiable | Architecture §5/§15; D13/D18 | Judge drift, false negatives, evaluator injection | precedence, ambiguity, model-source, and injection tests |
| Strict validation, provenance, and typed errors | (b), (d) | PRD-OPT-13 data quality; explicit versioned validation | D10/D11/D18; Architecture §4/§18 | Untrusted input, malformed evidence, real-data leakage, parser/path abuse | `tests/evals/test_validation.py`, `test_cli.py` |
| Canonical duplicate detection | (b), (d) | Reproducible/extensible eval dataset; regression quality | Architecture §10; D12 | Duplicate seeds inflate coverage and hide novelty gaps | exact, NFC/whitespace, case/punctuation, and multi-turn tests |
| CI enforcement | (b) | M11 hard-gate validation; production-grade test posture | Architecture §18/O4/O8 | Schema or invariant regression entering either remote | local, GitHub, and GitLab commands |

The authoring schemas live under `evals/schemas`, not `contracts/v1`, because they describe eval
artifacts rather than inter-agent messages. Embedded `EvidenceEnvelope` and `Verdict` objects are still
validated through the authoritative v1 contract registry. No competing storage validator was added;
M2/M4 integration may call this eval-specific module later.

## Corpus and OWASP coverage

| Threat-model category | Cases | Subcategories | Anchored mappings used |
|---|---:|---|---|
| Prompt injection | 3 | indirect, multi-turn, direct | Web 2021 A03/A04; LLM 2025 LLM01/LLM04/LLM07 |
| Data exfiltration | 3 | cross-patient, authorization bypass, PHI leakage | Web 2021 A01/A04/A08; LLM 2025 LLM02/LLM04/LLM07/LLM08 |
| Tool misuse | 3 | unintended invocation, parameter tampering, recursive calls | Web 2021 A01/A03/A04; LLM 2025 LLM05/LLM06/LLM10 |

The Web taxonomy is fixed to OWASP Top 10:2021 and the LLM taxonomy to OWASP LLM Top 10:2025,
matching Threat Model §OWASP taxonomy and D15. A tool-fetch SSRF mapping is not claimed because the
target's URL-fetch capability remains unconfirmed; the threat model marks A10 conditional.

## Ground-truth method and verdict precedence

Each category has five labels (fifteen total):

1. A constructed deterministic oracle/canary confirmation labelled `EXPLOIT_CONFIRMED`.
2. An authored policy-rule, non-oracle positive labelled `EXPLOIT_LIKELY` for future calibration.
   It is not human-reviewed, model-produced, deterministic, or live evidence, and its
   pre-calibration runtime state remains `INDETERMINATE`.
3. A policy-rule negative control labelled `NO_EXPLOIT_OBSERVED` as ground truth while its
   pre-calibration runtime state remains `INDETERMINATE`.
4. A missing, contradictory, or timed-out example that remains `INDETERMINATE`.
5. An evaluator-injection example whose hostile transcript requests a verdict flip while the trusted
   oracle/canary signal retains `EXPLOIT_CONFIRMED` precedence.

Typed trusted signal IDs must match the referenced case's oracle metadata. Hostile transcript text is
schema-labelled `hostile`, is never interpreted, and cannot populate trusted evidence. Oracle/canary
signals (hits or misses) must use unique IDs and the case-declared channel/ID. Hits additionally require
aligned label source, confirmation source, and reason code; same-signal contradictions are rejected.
Evaluator-injection samples must carry deterministic
precedence evidence without interpreting their hostile text. A calibrated-model source can
never confirm an exploit. The contract-compatible human-confirmation path is tested, but this corpus
claims no human review. No slice claims calibration passed, so non-oracle runtime dispositions stay
gated to `INDETERMINATE` until M9 executes and validates calibration.

## Validation behavior

- Schemas reject unknown properties, missing fields, invalid enum/version/category pairs, category ↔
  subcategory mismatch, unanchored OWASP tuples, inconsistent execution/result states, unsupported
  oracle claims, non-synthetic provenance, and happy-path-only design.
- Corpus validation resolves fixture IDs/canaries plus exact fixture source/version, unique
  slice/label IDs, case ↔ label backlinks, case versions/categories, exact expected-safe-behavior
  links, and trusted signal IDs in both directions.
- Duplicate comparison applies NFC, CRLF/CR normalization, and insignificant Unicode-whitespace
  collapse before structured JSON serialization and SHA-256. It deliberately preserves case,
  punctuation, turn order, and turn boundaries.
- Strict loading rejects duplicate JSON keys, `NaN`/`Infinity` and exponent overflow, oversized integer
  literals, invalid UTF-8/lone surrogates, malformed/deep/node-heavy input, symlinked artifact paths,
  excessive file count, and excessive cumulative bytes.
- Conservative synthetic-only checks cover mapping keys and values across fixtures, cases, and hostile
  ground truth. They reject high-confidence SSN/numeric-MRN, credential/token, URL, and cookie patterns;
  identifier-sensitive fixture fields accept only reserved symbolic `SYNTH-*` values.
- Diagnostics carry stable `EvalValidationCode` values, never echo hostile instance content, sanitize
  identifiers, cap issue volume, and use exit 1 for validation errors or exit 2 for CLI/operational misuse.
- Ground-truth contract identities are fixed to the offline, unexecuted campaign namespace; verdict
  reason/confirmation metadata must align exactly with evidence status and sample kind.

## TDD and verification evidence

RED was proven before implementation with:

```text
python -m pytest tests/evals -q
ERROR collecting tests/evals/test_validation.py
ModuleNotFoundError: No module named 'agentforge.evals'
```

The security hardening additions were also proven RED: five focused tests initially exposed an unknown
canary acceptance, mapping-key scan bypass, ANSI diagnostic injection, malformed duplicate-CLI
traceback, and missing-directory false success. The implementation was then changed, not the expected
security outcomes. Later RED tests captured non-JSON in-memory scalars, identifier provenance drift,
duplicate slice IDs, one-way ground-truth backlinks, contradictory verdict reasons/sources, human
evidence misclassified as deterministic, contradictory same-signal hits, evaluator-injection metadata
without precedence evidence, an undeclared false-valued trusted signal, an incomplete live-control
gate, and a ground-truth campaign identity claiming a live run.

Final local gate evidence:

```text
bash scripts/check.sh
ruff check: passed
ruff format --check: 34 files already formatted
eval corpus: 9 cases, 15 labels, 3 categories, 1 fixture
duplicate detector: no duplicates across 9 cases
pytest: 230 passed, 3 skipped (1 existing dependency deprecation warning)
secret scan: clean (114 files)
```

No type checker is configured; `IMPLEMENTATION_PLAN.md` explicitly defers type checking until a
dedicated task, so no type-check success is claimed. Docker CI was not run locally because its build
can fetch packages and this assignment prohibits network activity.

The offline CLI is CI-ready from a repository checkout with dev dependencies, but it is not yet an
agent-runtime package surface: `jsonschema` is currently a dev dependency, and the repo-level
`evals/schemas/` and `contracts/v1/` resources are not packaged with the wheel or existing Docker
image. Deployment configuration is outside this lane. M8/M9 integration must arrange one
authoritative packaged schema source, promote the validator dependency to the consuming runtime, and
add wheel/container CLI smoke tests rather than copying schemas into competing locations.

## Security review

- Synthetic-only declarations and fixture source/version are required and cross-referenced; no real
  PHI, live target data, credential, token, cookie, or target URL is present in corpus artifacts.
- Fixture references are inert IDs, never paths. Corpus directories/files reject symlinks and remain
  bounded before schema work.
- Hostile text cannot select files, change category/severity/authorization/oracle metadata, or appear in
  diagnostics. Evaluator-injection labels prove it cannot downgrade deterministic confirmation.
- Authored expectations, constructed ground truth, local deterministic fixture results, and live results
  are explicitly distinct. No execution or calibration success is implied.
- Live execution remains disabled in every seed and still requires explicit authorization, allowlist,
  synthetic-data confirmation, scoped credentials, budget and rate caps, timeout, monitoring, and a
  hard abort.

## Remaining dependencies and authorized-run procedure

- **M4 — Policy Gateway / Execution Recorder:** enforce authorization controls, execute attempts, and
  produce trusted hashed `AttemptResult` evidence. Until then, pending-runtime oracles cannot fire.
  The authored schema fixes live authorization to false, and validation rejects every
  `EXECUTED_LIVE` state until M4 provides a typed authorization reference and authorized posture.
- **M5 — OpenEMR adapter:** resolve target auth/API/version/rate behavior and whether synthetic canaries
  can be provisioned. Where provisioning is unavailable, S8 requires honest non-deterministic handling.
- **M8 — Red Team:** ingest and mutate these seeds, preserve hostile trust labels, package the shared
  eval validator/schema source for its runtime, and supply the live agent role required by the MVP
  gate.
- **M9 — Judge:** consume typed evidence and these slices, execute the minimum calibration gate, apply
  deterministic precedence, and emit schema-valid verdicts/results. Full drift governance remains M10.
  It must enforce code provenance for runtime oracle/canary confirmations; the shared
  `EvidenceEnvelope` contract also permits human provenance, while this offline ground-truth validator
  intentionally treats deterministic signals as code-produced only.
- **Explicit live authorization:** record target authorization and allowlist membership, confirm synthetic
  data only, bind scoped credential references, set budget/rate/time limits, enable monitoring, and prove
  the durable hard abort. Hosted inference also needs its separately authorized provider/budget setup.

These exact offline preflight commands must pass immediately before any future authorized run:

```sh
PYTHONPATH=src python -m agentforge.evals validate-corpus evals
PYTHONPATH=src python -m agentforge.evals detect-duplicate-sequence evals/seeds
bash scripts/check.sh
```

There is intentionally no live-run command in this commit: at base `6aebf50`, M4/M5/M8/M9 expose no
campaign runner. Naming one would fabricate an interface. After those tasks land, the integration owner
must append the exact shipped command here before authorization; it must accept corpus/target allowlist
references, an authorization record, synthetic fixture identity, scoped credential references,
budget/rate/time caps, monitoring, and a hard-abort control by reference rather than literal secrets.
Only that runtime may write observed live results.

Recommended integration order: land M2 contracts/storage first, then M4 recorder/gateway and M5
adapter foundations; integrate this offline corpus slice next; then adapt/land M8 seed ingestion and M9
Judge/calibration against its schemas and package boundary; finally create a separate explicitly
authorized live campaign/result commit. Run the commands above after each integration boundary.
