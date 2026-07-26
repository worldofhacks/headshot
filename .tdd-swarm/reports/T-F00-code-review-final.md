# T-F00 Final Independent Code Review

Status: DONE

Verdict: **CHANGES_REQUIRED** (Critical: 0, Important: 4, Minor: 2)

## Immutable review basis

- Candidate:
  `e15f0a3056d78318c111edf3ce76e3f42d424ec3`
- Frozen-test baseline:
  `514f59b64d9068a380a18f903f618ffb31b7313c`
- Exact implementation diff:
  `514f59b64d9068a380a18f903f618ffb31b7313c..e15f0a3056d78318c111edf3ce76e3f42d424ec3`
- The diff contains exactly the six ticket implementation scopes:
  `.tdd-swarm/spec-lint.sh`, `.tdd-swarm/run-local-gates.sh`,
  `.tdd-swarm/check-import-cycles.py`, `.tdd-swarm/publish-report.py`,
  `.tdd-swarm/coverage-policy.md`, and `.tdd-swarm/gates.md`.
- The exact diff of all three frozen test files is empty.

## Independent gates

```text
git rev-parse HEAD
e15f0a3056d78318c111edf3ce76e3f42d424ec3

PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -q --tb=short \
  tests/swarm/test_spec_lint.py tests/swarm/test_import_cycles.py \
  tests/swarm/test_gate_wrapper.py
PASS — 67/67

PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -q --tb=short \
  tests/swarm
PASS — 67/67

bash -n .tdd-swarm/spec-lint.sh .tdd-swarm/run-local-gates.sh
PASS

.venv/bin/ruff check \
  .tdd-swarm/check-import-cycles.py .tdd-swarm/publish-report.py
PASS

.venv/bin/ruff format --check \
  .tdd-swarm/check-import-cycles.py .tdd-swarm/publish-report.py
PASS

git diff --check 514f59b..e15f0a3
PASS

git diff --exit-code 514f59b..e15f0a3 -- \
  tests/swarm/test_spec_lint.py tests/swarm/test_import_cycles.py \
  tests/swarm/test_gate_wrapper.py
PASS — empty diff

python3 .tdd-swarm/check-import-cycles.py
PASS — acyclic; sha256=1c9c9b50b02756aee940f10cf3ba1528a8f616c8eaaa16263a1f606aba6efa23

.tdd-swarm/run-local-gates.sh tickets/T-F00.md \
  514f59b64d9068a380a18f903f618ffb31b7313c
FAIL — coverage policy requires an external approval record file
```

## Important findings

### I-1 — The required repository verifier cannot pass, so the ticket DoD is unmet

Evidence:

- `.tdd-swarm/coverage-policy.md:3-7` records a proposed waiver with
  `PENDING_EXTERNAL_OWNER_APPROVAL`.
- `.tdd-swarm/gates.md:12-20` marks typecheck, new-tests, coverage, no-todos,
  no-debug-logging, docs, reachability, and spec-lint `BLOCKED`.
- `.tdd-swarm/run-local-gates.sh:864-870` deliberately makes every `BLOCKED`
  row fail the overall verdict.
- The exact ticket verifier fails before any mapped gate because no detached
  approval artifacts are supplied. Even with that approval, the retained
  `BLOCKED` rows make a zero exit impossible.

Impact: `tickets/T-F00.md` requires the named wrapper to exit zero with retained
hashes. The immutable candidate has no green repository evidence and cannot
satisfy its Definition of Done.

Exact repair: supply a genuine externally signed owner waiver or an executable
base-bound coverage policy; make each Tier-1 row runnable, including a truthful
intrinsic status for checks already executed by the wrapper; install/approve
the missing fixed adapters; then run the exact verifier against the repaired
frozen-test baseline and retain its PASS report. Do not relabel a blocked row
green without executing its check.

### I-2 — A successful gate leader can leave a live descendant outside supervision

Evidence:

- `.tdd-swarm/run-local-gates.sh:558-582` treats `BlockingIOError` as an empty
  read/EOF after the leader exits.
- `.tdd-swarm/run-local-gates.sh:592-593` then returns the leader's zero status
  without checking or terminating the remaining process group.
- A temporary read-only diagnostic invoked the candidate's `run_bounded` with
  `bash -c 'sleep 30 & echo $!'`: it returned code 0 in 0.055 seconds while the
  printed descendant PID was still alive. The diagnostic killed the descendant
  afterward.

Impact: a mapped command can report success while a child continues consuming
resources or mutating the worktree after HEAD/input revalidation and report
publication. The timeout/output-limit tests cover a live leader, not this
leader-exits-first lifecycle.

Exact repair: distinguish `EAGAIN` from real EOF; after the leader exits, require
pipe EOF and process-group quiescence within a bounded grace period. Terminate
the whole group with TERM/KILL and fail the row if descendants remain. Add a
frozen regression where a zero-exit leader leaves a silent pipe-holding child
and assert the child is gone before publication.

### I-3 — Valid parametrized pytest nodes can be misclassified as uncollected

Evidence:

- `.tdd-swarm/spec-lint.sh:322-324` reconstructs the qualified test name by
  splitting the serialized node ID on every `::`.
- Pytest permits parameter IDs containing `::`. A temporary fixture with a
  collected, non-skipped test whose ID was `left::right` was rejected as
  “not collected by pytest,” leaving AC-1 unmapped.

Impact: AC-1 can fail for a valid criterion-tagged test. This makes the
mechanical mapping gate dependent on parameter-ID spelling rather than pytest's
actual collected item identity.

Exact repair: derive scope and qualified function identity from pytest item
metadata (`item.path`, `item.originalname`/location, and collector parents), not
by parsing `nodeid`. Add a frozen parametrization case containing `::` and
require the complete mapping to pass.

### I-4 — A report can claim PASS with no valid import-graph hash

Evidence:

- `.tdd-swarm/run-local-gates.sh:920-939` fails the run only on the import
  process exit; a missing or ambiguous digest becomes the literal
  `unavailable` without changing `overall_pass`.
- `.tdd-swarm/run-local-gates.sh:946-1004` publishes that value and can still
  emit `overall-verdict: PASS`.
- A temporary committed fixture checker that exited zero but omitted the digest
  produced exactly `import-graph-sha256: unavailable` and
  `overall-verdict: PASS`.

Impact: AC-5's required import-graph evidence can be absent while the wrapper
declares the run green.

Exact repair: require exactly one strictly formatted 64-hex digest from the
same successful checker observation. Missing, malformed, or duplicate digests
must set an explicit import-validation failure, retain a diagnostic, and force
the overall verdict to FAIL. Add the zero-exit/no-digest and duplicate-digest
frozen cases.

## Minor findings

### M-1 — The publisher accepts a symlink in an earlier parent component

Evidence:

- `.tdd-swarm/publish-report.py:20-26` compares lexical absolute parents and
  applies `O_NOFOLLOW` only when opening the final parent pathname.
- A temporary path shaped as `linked-parent -> actual-parent`, followed by a
  real `reports` directory, was accepted and published successfully through
  the symlink.

Impact: the standalone fixed publisher does not itself enforce its required
fully non-symlinked directory path. The wrapper's normal path validation
currently mitigates its sole production call, so this is Minor rather than
Important.

Exact repair: walk/open every parent component from a trusted anchor with
directory FDs and `O_NOFOLLOW`, or reject any `lstat`-observed symlink component
before opening the held report directory. Add an earlier-ancestor symlink
regression to the publisher tests.

### M-2 — Non-finite coverage baselines escape the documented error boundary

Evidence:

- `.tdd-swarm/run-local-gates.sh:321-326` accepts `Decimal("NaN")` conversion
  and then raises an uncaught `decimal.InvalidOperation` during the range
  comparison.
- `.tdd-swarm/run-local-gates.sh:1034-1038` catches only `FatalGateError`, so a
  malformed policy produces a traceback rather than the stable
  `coverage-policy:`/`local-gates:` failure semantics.

Impact: malformed coverage input is fail-closed but non-deterministic for
operators and automation consuming diagnostics.

Exact repair: require `baseline.is_finite()` and wrap conversion plus range
validation in the same handled error path. Add `NaN`, `Infinity`, and
`-Infinity` policy cases that assert exit 1 without a traceback.

## Conclusion

The repaired implementation closes the prior frozen-suite findings and does
not weaken tests, but the actual required verifier is red and four Important
correctness gaps remain. `REVIEW_PASS` is not warranted.
