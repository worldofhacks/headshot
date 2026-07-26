# T-F00 Test Freeze Review

Status: DONE

Verdict: **CHANGES_REQUIRED** (Critical: 0, Important: 1, Minor: 0)

## Review basis

- Candidate HEAD: `4469a2d`
- Incremental commits: `75a9ff6` and `4469a2d`
- Prior findings reviewed: I-1 through I-5 and M-1 in
  `.tdd-swarm/reports/T-F00-repair-test-review-final.md`
- Prior closed areas were rechecked in the complete three-file frozen candidate.

## Verification

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -p no:cacheprovider -vv \
  tests/swarm/test_spec_lint.py \
  tests/swarm/test_import_cycles.py \
  tests/swarm/test_gate_wrapper.py

65 collected; 49 failed; 16 passed; 0 errors
```

Every RED is an assertion failure against missing behavior in implementation
commit `3e1c370`; there are no syntax, import, pytest-collection, fixture-setup,
or cleanup errors.

```text
.venv/bin/ruff check <three test files>          PASS
.venv/bin/ruff format --check <three test files> PASS
git diff --check 93e62dc..4469a2d -- tests/swarm PASS
```

## Incremental disposition

| Finding | Verdict | Evidence |
|---|---|---|
| I-1 — gate-ID/vector and coverage-adapter authority | CLOSED | `test_gate_wrapper.py:699-762` rejects a sanctioned vector under the wrong valid ID and a committed marker-writing unknown adapter without execution. Existing arbitrary executable and mutated-argv cases remain. |
| I-2 — runtime-skipped collected node | CLOSED | `test_spec_lint.py:214-239` uses `pytest_collection_modifyitems` to add the skip marker dynamically and requires the collected node to be rejected and named. |
| I-3 — every declared test scope hashed canonically | CLOSED | The ticket fixture declares two scopes in reverse lexical order; `test_gate_wrapper.py:1285-1322` requires the exact sorted, length-prefixed aggregate and proves it differs from declaration-order hashing. |
| I-4 — atomic report and validation/use race | CHANGES_REQUIRED | The gate-map swap case is strong, but the new pre-publication kill case still permits unlink then rewrite (Important finding below). |
| I-5 — mapped executable commit binding | CLOSED | The default script is committed before the baseline; behavioral variants are committed and approval is rebound; `test_gate_wrapper.py:961-980` separately proves a post-commit mutation cannot execute. |
| M-1 — contradictory shell wording | CLOSED | The renamed test at `test_gate_wrapper.py:715-728` now accurately says “unsanctioned shell vector.” |

The prior import-cycle, Tier-1 inventory, timeout/process-group, output-budget,
redaction, exact-limit, rendered-output, base/HEAD, exact-hash, coverage-status,
and signed-approval cases remain intact.

## Important finding

### I-1 — The new failpoint still does not distinguish atomic replace from unlink and rewrite

`tests/swarm/test_gate_wrapper.py:1080-1131` combines:

1. a successful run that requires the destination inode to change; and
2. a process killed at a wrapper-defined `before-report-publish` failpoint that
   must leave the prior report unchanged.

A lazy non-atomic implementation still passes both:

```text
build report bytes in memory
signal before-report-publish; wait
unlink(existing_report)
open(existing_report, "w") and write bytes
```

Killing it at the failpoint preserves the old file because deletion has not
happened yet. Letting it finish yields a new inode. Neither assertion observes
the missing/partial-file window between unlink and completed write. The test
therefore labels the intended phase but does not behaviorally close the exact
I-4 loophole.

Smallest repair: make the publication failpoint expose the completed
same-directory temporary file and assert, while paused, that:

- the old destination still contains the prior complete report;
- the temporary path is a regular non-symlink in the report directory;
- the temporary file already contains the complete new report; and
- after resume the destination becomes that prepared file without any
  delete/create gap.

The last property needs an observable atomic-commit boundary, not only an inode
check—for example, isolate the final filesystem commit behind a testable
publisher that performs one replace operation, or use a deterministic directory
event observer to reject `DELETE/CREATE` and accept only replacement. Retain the
kill-before-commit assertion.

## Conclusion

The incremental repairs close I-1, I-2, I-3, I-5, and M-1, and the complete
suite has clean behavior RED. Freeze remains blocked by one Important atomicity
gap: unlink-and-rewrite can still pass the purported atomic-publication tests.
