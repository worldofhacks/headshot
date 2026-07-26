# T-F00 Test Agent Report

Status: DONE

## Scope

- `tests/swarm/test_spec_lint.py`
- `tests/swarm/test_gate_wrapper.py`
- `tests/swarm/test_import_cycles.py`

## AC-to-test map

| Acceptance criterion | Frozen RED tests |
|---|---|
| AC-1 | `test_spec_lint_rejects_a_ticket_criterion_without_a_test_mapping`; `test_spec_lint_rejects_an_untagged_test_beside_a_tagged_test`; `test_spec_lint_rejects_a_test_tagged_to_the_wrong_ticket`; `test_spec_lint_rejects_a_tag_for_a_nonexistent_acceptance_criterion`; `test_spec_lint_accepts_a_complete_criterion_to_test_mapping` |
| AC-2 | `test_import_cycle_check_rejects_a_declared_package_layer_cycle`; `test_import_cycle_check_accepts_the_current_approved_graph` |
| AC-3 | `test_wrapper_rejects_a_truly_absent_coverage_policy`; `test_wrapper_rejects_each_incomplete_non_applicable_waiver`; `test_wrapper_rejects_an_expired_non_applicable_waiver`; `test_wrapper_accepts_a_complete_unexpired_non_applicable_waiver`; `test_wrapper_accepts_executable_coverage_at_its_base_sha_baseline`; `test_wrapper_rejects_executable_coverage_without_a_baseline_base_sha`; `test_wrapper_rejects_a_coverage_baseline_bound_to_a_different_commit`; `test_wrapper_rejects_executable_coverage_regression` |
| AC-4 | `test_wrapper_preserves_failure_output_and_runs_all_mapped_gate_rows` |
| AC-5 | `test_wrapper_writes_a_hash_bound_report_when_all_gates_are_green` |

## Verification

```text
.venv/bin/ruff check tests/swarm
All checks passed!

.venv/bin/ruff format --check tests/swarm
3 files already formatted

.venv/bin/pytest tests/swarm -q
FFFFFFFFFFFFFFFFF                                                        [100%]
17 failed
```

Every failure is a pytest assertion, not an import, fixture, or syntax error:

- AC-1 tests: `.tdd-swarm/spec-lint.sh` is absent.
- AC-2 tests: `.tdd-swarm/check-import-cycles.py` is absent.
- AC-3 through AC-5 tests: `.tdd-swarm/run-local-gates.sh` is absent.

The repaired tests close the test-design review's Critical and Important findings:

- AC-1 uses actual test functions and rejects an untagged test beside a tagged one,
  wrong-ticket tags, and nonexistent-AC tags.
- AC-3 isolates a truly absent policy; removes each mandatory waiver field; proves a
  valid unexpired waiver; executes coverage at a base-SHA baseline; rejects missing
  and mismatched baseline base-SHA bindings; and rejects a measured regression.
- AC-4 uses an execution marker to prove format → failing lint → typecheck ordering,
  preserves all three unique outputs, and requires exact per-row exits `0`, `7`, `0`.
- AC-5 creates distinct base/head commits, requires labeled identities and exact
  command/exit/output rows, hashes the policy bytes, and independently derives the
  canonical import-edge digest for the report.

`git diff --check` passed. This report is intentionally uncommitted; only the three
declared test-scope files are committed.
