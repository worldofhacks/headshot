# Corpus performance and run-envelope evidence

Status on integration base `f39e227`: **producer hardened; final artifact blocked on
incoming release inputs**.

No final baseline or run envelope is committed from this lane. Production is fail-closed
until all of these exact inputs exist together on one clean checked release commit:

- the reconciled, byte-pinned reviewed `headshot-live-100-v1` corpus;
- the staged `HostedConfigurationSet` receipt whose `resource_id` equals its canonical
  `configuration_sha256`;
- the registered generation-policy SHA used by that release;
- reviewed per-batch run-budget allocations whose exact sum is no more than `$50`;
  and
- the final release SHA, equal to the clean checked Git `HEAD`.

Released corpus commit `d9d7b4a` still cannot be admitted on this base:
`live-100 workload category balance is invalid`. The released workload spans six
categories while the f39 loader pins the legacy three-category balance. The incoming
corpus/runtime integration must reconcile that contract; this platform lane does not
rewrite model-evaluation corpus content.

The network-free producer is `scripts/capture_corpus_performance.py`. It produces:

- `run-authorization-envelope.json`: exact corpus counts; internally recomputed hashes
  of the four bound cap files; exact staged configuration, generation-policy, and budget
  identities; and a batch plan derived from per-role and global retry, call, token, and
  spend limits.
- `local-admission-baseline.json`: observed local latency p50/p95, throughput, CPU time,
  peak RSS, and canonical payload bytes for immutable corpus verification and
  serialization.
- `artifact-manifest.json` and `SHA256SUMS`: byte lengths and content hashes for the
  retained outputs.

The local baseline is deliberately narrow. It measures no Railway service, target,
provider, database-growth, campaign-cost, or end-to-end latency. Those values must come
from the exact deployed release and retained campaign manifests.

## Final-candidate command

Run only after the exact staged receipt, reconciled corpus, budget plan, and clean final
release commit are available:

```console
PYTHONPATH=src python scripts/capture_corpus_performance.py \
  --repo-root . \
  --workload-sha256 <reviewed-manifest-sha256> \
  --release-sha <exact-clean-HEAD> \
  --run-id <operator-selected-run-id> \
  --staged-configuration-receipt <immutable-stage-receipt.json> \
  --generation-policy-sha256 <registered-policy-sha256> \
  --batch-budget-plan <reviewed-batch-budget-plan.json> \
  --output-dir docs/performance/artifacts/<run-id>
```

Every input and parent must be a regular, non-symlink path. The output must be one new
direct child of `docs/performance/artifacts`; an existing path, broken link, escape, dirty
worktree, mismatched SHA, or all-zero SHA is rejected.

The stage receipt has the exact keys `schema_version`, `resource_id`, and
`configuration`. The budget plan has the exact keys `schema_version`, `target_id`,
`surface_id`, `aggregate_budget_usd`, and `batch_budget_usd`; USD values are decimal
strings, allocations must sum exactly to the aggregate, and each allocation must cover
that batch's worst-case staged hosted-spend reservation.

## Authorization boundary

The generated envelope is preparation evidence, not a grant. It cannot replace the
application and database checks for a distinct operator and approver. The intended
Week 2 chat surface is bound to:

- target/surface: `copilot-week2` / `copilot-week2-chat`
- maximum attempts: `100`
- logical cases: `100`
- physical target requests: `121`
- target retries: `0`
- expected spend: `$10–25`
- aggregate hard budget cap: `$50`

The elevated caps apply only to the Week 2 target and its alias. Week 1 retains its
legacy `$1` / `40` attempts / `40` logical / `60` physical / one-retry envelope.

There is intentionally no hard-coded batch size. For each candidate batch size the
producer reserves worst-case Documentation calls, provider retries, input/output/
reasoning tokens, and price-based spend against every staged role limit and the staged
global limit. It chooses the largest positive size that fits; if one case cannot fit, it
fails closed. The aggregate of the resulting per-batch run budgets must remain at or
below `$50`, and each allocation must cover that batch's worst-case staged hosted-spend
reservation. The global hosted call ceiling remains `56`; it is never raised to fit the
corpus.
