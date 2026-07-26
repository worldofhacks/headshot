# T-F00 Test-Design Final Review

Status: DONE

Verdict: REVIEW_PASS (Critical: 0, Important: 0, Minor: 1)

Reviewed commit: `87b472ffe0f83f615f8a32a32b1687f951fc3cf7`

The orchestrator's focused rerun is a clean RED: 17 feature-missing assertion failures, with no syntax, import, collection, or fixture-setup errors.

## Final verification

- The sole prior Important finding is closed. `tests/swarm/test_gate_wrapper.py:224-236` now requires a missing `baseline-base-sha` to exit 1 with a base-SHA diagnostic.
- `tests/swarm/test_gate_wrapper.py:239-256` creates a distinct commit, binds the policy to that wrong commit, invokes the wrapper with the original diff base, and requires exit 1 plus an explicit mismatch diagnostic. A wrapper that ignores the base-SHA binding can no longer pass.
- The earlier repairs remain intact: complete per-test spec mapping, real absent/incomplete/expired coverage-policy negatives, valid waiver and executable coverage paths, regression rejection, post-failure gate execution/output/exit evidence, distinct base/head identities, and exact coverage/import hashes.
- All 17 test functions have an exact `spec(T-F00:AC-n)` tag; every AC is meaningfully represented; fixtures are deterministic and remain within ticket scope.

## Minor ledger item

- `tests/swarm/test_gate_wrapper.py:139-158,288-290,310-317` still couples report behavior to a literal Markdown row layout and a locally selected canonical import-edge serialization. This does not leave an AC untested or permit a lazy implementation, but the format should be documented as contract or loosened in a future maintenance pass.

The test suite is approved to freeze.
