# Corpus performance and run-envelope evidence

Status on integration base `f39e227`: **producer ready; corpus-bound artifact blocked on the
incoming reviewed corpus PR and final release SHA**.

An audit of released corpus commit `d9d7b4a` against this base also fails closed with
`live-100 workload category balance is invalid`: the released workload spans six
categories while the f39 loader still pins the legacy three-category balance. The
incoming corpus/runtime integration must reconcile that contract; this platform branch
does not rewrite model-evaluation corpus content.

The repository now has a network-free producer at
`scripts/capture_corpus_performance.py`. It admits only the byte-pinned,
human-reviewed `headshot-live-100-v1` manifest through the existing closed workload
registry. It then produces:

- `run-authorization-envelope.json`: exact logical/physical/retry counts, the $50 hard
  cap and $10–25 expected-spend range, hashes of the four bound cap files, and a
  deterministic batch plan that stays below `HOSTED_MAX_PHYSICAL_CALLS = 56`.
- `local-admission-baseline.json`: observed local latency p50/p95, throughput, CPU time,
  peak RSS, and canonical payload bytes for immutable corpus verification and
  serialization.
- `artifact-manifest.json` and `SHA256SUMS`: byte lengths and content hashes for the
  retained outputs.

The local baseline is deliberately narrow. It measures no Railway service, target,
provider, database-growth, campaign-cost, or end-to-end latency. Those values must come
from the exact deployed release and retained campaign manifests; this producer never
fills them with fixtures or estimates.

## Final-candidate command

Run only after the reviewed corpus is present on the assembled release candidate:

```console
PYTHONPATH=src python scripts/capture_corpus_performance.py \
  --repo-root . \
  --workload-sha256 <reviewed-manifest-sha256> \
  --release-sha <exact-release-commit> \
  --run-id <operator-selected-run-id> \
  --output-dir docs/performance/artifacts/<run-id>
```

The output directory must not already exist. This is an intentional no-overwrite
property for immutable evidence.

## Authorization boundary

The generated envelope is preparation evidence, not a grant. It cannot replace the
application and database checks for a distinct operator and approver. The full
100-case authorization remains bound to:

- logical cases: `100`
- physical target requests: `121` (sum of reviewed turns)
- target retries: `0`
- expected spend: `$10–25`
- hard budget cap: `$50`

The landed four-role generation policy reserves one Orchestrator, Red Team, Judge, and
Documentation call per case: four cumulative hosted calls per case. Therefore the
current safe plan is seven 14-case batches plus one two-case batch, not the illustrative
two 50-case batches. A 50-case batch would require 200 cumulative calls and the current
Runner correctly refuses it. Each executed batch must be aggregated by its retained
result manifest. The hosted ceiling remains `56`; it is not raised to fit the corpus.

This harness does not claim that the current Runner can authorize a subset of the
100-case corpus. The assembled runtime must prove batch-manifest authorization before
the live run; otherwise that is a release blocker rather than a reason to weaken the
call ceiling.
